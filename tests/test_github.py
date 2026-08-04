"""Offline tests for the GitHub REST API client."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from crawler.clients.github import GitHubClient, GitHubClientError
from crawler.config import HttpClientConfig
from crawler.utils.cache import RawResponseStore
from crawler.utils.http import RetrievalClient

FIXTURES = Path(__file__).parent / "fixtures"


def _make_client(
    handler: httpx.MockTransport | None = None,
) -> tuple[RetrievalClient, GitHubClient]:
    config = HttpClientConfig(
        timeout_seconds=5,
        max_retries=0,
        cache_enabled=False,
        respect_rate_limits=True,
        max_response_bytes=10_485_760,
        initial_backoff_seconds=1.0,
        max_retry_delay_seconds=60.0,
    )
    store = RawResponseStore(root=Path("/tmp/test-github-cache"))
    transport = handler or httpx.MockTransport(
        lambda request: httpx.Response(200, json=[])
    )
    retrieval = RetrievalClient(
        config=config,
        store=store,
        transport=transport,
        clock=lambda: datetime(2026, 8, 4, 12, 0, tzinfo=UTC),
    )
    return retrieval, GitHubClient(retrieval)


class TestFetchReleases:
    def test_canonical_url(self) -> None:
        seen_urls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_urls.append(str(request.url))
            return httpx.Response(
                200,
                json=[],
                headers={"content-type": "application/json"},
            )

        retrieval, client = _make_client(httpx.MockTransport(handler))
        with retrieval:
            client.fetch_releases("urllib3", "urllib3")
        assert len(seen_urls) == 1
        assert (
            seen_urls[0]
            == "https://api.github.com/repos/urllib3/urllib3/releases?per_page=100"
        )

    def test_invalid_owner_rejected(self) -> None:
        retrieval, client = _make_client()
        with retrieval, pytest.raises(GitHubClientError, match="invalid GitHub owner"):
            client.fetch_releases("", "urllib3")

    def test_invalid_repo_rejected(self) -> None:
        retrieval, client = _make_client()
        with retrieval, pytest.raises(GitHubClientError, match="invalid GitHub repo"):
            client.fetch_releases("urllib3", "../evil")

    def test_non_200_rejected(self) -> None:
        retrieval, client = _make_client(
            httpx.MockTransport(
                lambda r: httpx.Response(
                    404, json={}, headers={"content-type": "application/json"}
                )
            )
        )
        with retrieval, pytest.raises(GitHubClientError, match="HTTP 404"):
            client.fetch_releases("urllib3", "urllib3")

    def test_non_json_rejected(self) -> None:
        retrieval, client = _make_client(
            httpx.MockTransport(
                lambda r: httpx.Response(
                    200,
                    content=b"not json",
                    headers={"content-type": "text/plain"},
                )
            )
        )
        with retrieval, pytest.raises(GitHubClientError, match="not application/json"):
            client.fetch_releases("urllib3", "urllib3")

    def test_fixture_releases_parse(self) -> None:
        fixture_data = json.loads(
            (FIXTURES / "github_releases.json").read_text("utf-8")
        )

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json=fixture_data,
                headers={"content-type": "application/json"},
            )

        retrieval, client = _make_client(httpx.MockTransport(handler))
        with retrieval:
            response = client.fetch_releases("urllib3", "urllib3")
        releases = json.loads(response.content)
        assert len(releases) == 4
        assert releases[0]["tag_name"] == "2.7.0"


class TestFetchTags:
    def test_canonical_url(self) -> None:
        seen_urls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_urls.append(str(request.url))
            return httpx.Response(
                200,
                json=[],
                headers={"content-type": "application/json"},
            )

        retrieval, client = _make_client(httpx.MockTransport(handler))
        with retrieval:
            client.fetch_tags("urllib3", "urllib3")
        assert len(seen_urls) == 1
        assert (
            seen_urls[0]
            == "https://api.github.com/repos/urllib3/urllib3/tags?per_page=100"
        )

    def test_fixture_tags_parse(self) -> None:
        fixture_data = json.loads((FIXTURES / "github_tags.json").read_text("utf-8"))

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json=fixture_data,
                headers={"content-type": "application/json"},
            )

        retrieval, client = _make_client(httpx.MockTransport(handler))
        with retrieval:
            response = client.fetch_tags("urllib3", "urllib3")
        tags = json.loads(response.content)
        assert len(tags) == 5
        assert tags[0]["name"] == "2.7.0"


class TestFetchFile:
    def test_canonical_url(self) -> None:
        seen_urls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_urls.append(str(request.url))
            return httpx.Response(200, content=b"file content")

        retrieval, client = _make_client(httpx.MockTransport(handler))
        with retrieval:
            client.fetch_file("urllib3", "urllib3", "CHANGES.rst")
        assert len(seen_urls) == 1
        assert (
            seen_urls[0]
            == "https://raw.githubusercontent.com/urllib3/urllib3/main/CHANGES.rst"
        )

    def test_custom_ref(self) -> None:
        seen_urls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_urls.append(str(request.url))
            return httpx.Response(200, content=b"content")

        retrieval, client = _make_client(httpx.MockTransport(handler))
        with retrieval:
            client.fetch_file("urllib3", "urllib3", "CHANGES.rst", ref="2.7.0")
        assert "2.7.0/CHANGES.rst" in seen_urls[0]

    def test_path_traversal_rejected(self) -> None:
        retrieval, client = _make_client()
        with retrieval, pytest.raises(GitHubClientError, match="unsafe file path"):
            client.fetch_file("urllib3", "urllib3", "../etc/passwd")

    def test_null_byte_rejected(self) -> None:
        retrieval, client = _make_client()
        with retrieval, pytest.raises(GitHubClientError, match="unsafe file path"):
            client.fetch_file("urllib3", "urllib3", "file\x00.txt")

    def test_empty_path_rejected(self) -> None:
        retrieval, client = _make_client()
        with retrieval, pytest.raises(GitHubClientError, match="non-empty string"):
            client.fetch_file("urllib3", "urllib3", "")

    def test_invalid_ref_rejected(self) -> None:
        retrieval, client = _make_client()
        with retrieval, pytest.raises(GitHubClientError, match="invalid ref"):
            client.fetch_file("urllib3", "urllib3", "CHANGES.rst", ref="")

    def test_non_200_rejected(self) -> None:
        retrieval, client = _make_client(
            httpx.MockTransport(lambda r: httpx.Response(404, content=b"not found"))
        )
        with retrieval, pytest.raises(GitHubClientError, match="HTTP 404"):
            client.fetch_file("urllib3", "urllib3", "CHANGES.rst")


class TestFetchCommit:
    def test_canonical_url(self) -> None:
        seen_urls: list[str] = []
        commit_sha = "a" * 40

        def handler(request: httpx.Request) -> httpx.Response:
            seen_urls.append(str(request.url))
            return httpx.Response(
                200,
                json={"sha": commit_sha, "files": []},
                headers={"content-type": "application/json"},
            )

        retrieval, client = _make_client(httpx.MockTransport(handler))
        with retrieval:
            client.fetch_commit("urllib3", "urllib3", commit_sha)
        assert len(seen_urls) == 1
        assert (
            seen_urls[0]
            == f"https://api.github.com/repos/urllib3/urllib3/commits/{commit_sha}"
        )

    def test_invalid_sha_rejected(self) -> None:
        retrieval, client = _make_client()
        with retrieval, pytest.raises(GitHubClientError, match="invalid commit SHA"):
            client.fetch_commit("urllib3", "urllib3", "not-a-sha")

    def test_short_sha_rejected(self) -> None:
        retrieval, client = _make_client()
        with retrieval, pytest.raises(GitHubClientError, match="invalid commit SHA"):
            client.fetch_commit("urllib3", "urllib3", "abc123")

    def test_non_200_rejected(self) -> None:
        retrieval, client = _make_client(
            httpx.MockTransport(
                lambda r: httpx.Response(
                    404, json={}, headers={"content-type": "application/json"}
                )
            )
        )
        with retrieval, pytest.raises(GitHubClientError, match="HTTP 404"):
            client.fetch_commit("urllib3", "urllib3", "a" * 40)

    def test_non_json_rejected(self) -> None:
        retrieval, client = _make_client(
            httpx.MockTransport(
                lambda r: httpx.Response(
                    200,
                    content=b"not json",
                    headers={"content-type": "text/plain"},
                )
            )
        )
        with retrieval, pytest.raises(GitHubClientError, match="not application/json"):
            client.fetch_commit("urllib3", "urllib3", "a" * 40)

    def test_fixture_commit_parse(self) -> None:
        fixture_data = json.loads(
            (FIXTURES / "github_commit_version_api.json").read_text("utf-8")
        )
        commit_sha = fixture_data["sha"]

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json=fixture_data,
                headers={"content-type": "application/json"},
            )

        retrieval, client = _make_client(httpx.MockTransport(handler))
        with retrieval:
            response = client.fetch_commit("urllib3", "urllib3", commit_sha)
        payload = json.loads(response.content)
        assert payload["sha"] == commit_sha
        assert len(payload["files"]) == 2
