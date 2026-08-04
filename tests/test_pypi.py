"""Offline tests for the bounded PyPI project adapter."""

from pathlib import Path

import httpx
import pytest

from crawler.clients.pypi import PyPIClient, PyPIClientError
from crawler.config import HttpClientConfig
from crawler.utils.cache import RawResponseStore
from crawler.utils.http import RetrievalClient

FIXTURE = Path(__file__).parent / "fixtures" / "pypi_project.json"


def _config() -> HttpClientConfig:
    return HttpClientConfig(
        timeout_seconds=5.0,
        max_retries=0,
        cache_enabled=True,
        respect_rate_limits=True,
        max_response_bytes=1_000_000,
        initial_backoff_seconds=0.0,
        max_retry_delay_seconds=5.0,
    )


def test_pypi_client_fetches_canonical_url_and_replays_raw_cache(
    tmp_path: Path,
) -> None:
    calls = 0
    fixture_bytes = FIXTURE.read_bytes()

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        assert str(request.url) == "https://pypi.org/pypi/urllib3/json"
        assert request.headers["accept"] == "application/json"
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json; charset=UTF-8"},
            content=fixture_bytes,
            request=request,
        )

    store = RawResponseStore(tmp_path / "raw" / "pypi")
    with RetrievalClient(
        config=_config(),
        store=store,
        transport=httpx.MockTransport(handler),
    ) as retrieval:
        first = PyPIClient(retrieval).fetch_project("Urllib3")

    def fail_handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"unexpected network request: {request.url}")

    with RetrievalClient(
        config=_config(),
        store=store,
        transport=httpx.MockTransport(fail_handler),
    ) as retrieval:
        second = PyPIClient(retrieval).fetch_project("urllib3")

    assert calls == 1
    assert first.from_cache is False
    assert second.from_cache is True
    assert first.content == second.content == fixture_bytes
    assert first.body_sha256 == second.body_sha256


@pytest.mark.parametrize(
    "project_name",
    ["", " urllib3", "../urllib3", "urllib3/other", "urllib3?token=secret"],
)
def test_pypi_client_rejects_unsafe_project_names(
    tmp_path: Path, project_name: str
) -> None:
    with (
        RetrievalClient(
            config=_config(),
            store=RawResponseStore(tmp_path / "raw"),
            transport=httpx.MockTransport(
                lambda request: pytest.fail(f"unexpected request: {request.url}")
            ),
        ) as retrieval,
        pytest.raises(PyPIClientError, match="invalid PyPI project name"),
    ):
        PyPIClient(retrieval).fetch_project(project_name)


@pytest.mark.parametrize(
    ("status", "content_type", "message"),
    [
        (404, "application/json", "HTTP 404"),
        (200, "text/html", "not application/json"),
    ],
)
def test_pypi_client_rejects_unsuccessful_or_non_json_response(
    tmp_path: Path, status: int, content_type: str, message: str
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status,
            headers={"Content-Type": content_type},
            content=b"{}",
            request=request,
        )

    with (
        RetrievalClient(
            config=_config(),
            store=RawResponseStore(tmp_path / "raw"),
            transport=httpx.MockTransport(handler),
        ) as retrieval,
        pytest.raises(PyPIClientError, match=message),
    ):
        PyPIClient(retrieval).fetch_project("urllib3")
