"""Bounded adapter for the GitHub REST API and raw content endpoints."""

from __future__ import annotations

import re

from crawler.utils.http import RetrievalClient, RetrievedResponse

_OWNER_REPO_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$")
_REF_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")
_GITHUB_API_BASE = "https://api.github.com"
_GITHUB_RAW_BASE = "https://raw.githubusercontent.com"


class GitHubClientError(RuntimeError):
    """Raised when a GitHub resource cannot be safely retrieved."""


def _validate_owner_repo(owner: str, repo: str) -> None:
    if not isinstance(owner, str) or not _OWNER_REPO_PATTERN.fullmatch(owner):
        raise GitHubClientError(f"invalid GitHub owner: {owner!r}")
    if not isinstance(repo, str) or not _OWNER_REPO_PATTERN.fullmatch(repo):
        raise GitHubClientError(f"invalid GitHub repo: {repo!r}")


def _validate_json_response(
    response: RetrievedResponse, context: str
) -> RetrievedResponse:
    if response.status_code != 200:
        raise GitHubClientError(
            f"GitHub returned HTTP {response.status_code} for {context}"
        )
    content_type = response.headers.get("content-type", "")
    if content_type.partition(";")[0].strip().lower() != "application/json":
        raise GitHubClientError(f"GitHub response is not application/json: {context}")
    return response


class GitHubClient:
    """Fetch releases, tags, and file content through the shared retrieval boundary."""

    def __init__(self, retrieval_client: RetrievalClient) -> None:
        self._retrieval_client = retrieval_client

    def fetch_releases(self, owner: str, repo: str) -> RetrievedResponse:
        """Fetch the first page of releases for a repository."""
        _validate_owner_repo(owner, repo)
        url = f"{_GITHUB_API_BASE}/repos/{owner}/{repo}/releases?per_page=100"
        response = self._retrieval_client.fetch(
            "GET",
            url,
            headers={"Accept": "application/vnd.github+json"},
        )
        return _validate_json_response(response, f"{owner}/{repo} releases")

    def fetch_tags(self, owner: str, repo: str) -> RetrievedResponse:
        """Fetch the first page of tags for a repository."""
        _validate_owner_repo(owner, repo)
        url = f"{_GITHUB_API_BASE}/repos/{owner}/{repo}/tags?per_page=100"
        response = self._retrieval_client.fetch(
            "GET",
            url,
            headers={"Accept": "application/vnd.github+json"},
        )
        return _validate_json_response(response, f"{owner}/{repo} tags")

    def fetch_file(
        self, owner: str, repo: str, path: str, ref: str = "main"
    ) -> RetrievedResponse:
        """Fetch raw file content from the repository."""
        _validate_owner_repo(owner, repo)
        if not isinstance(path, str) or not path:
            raise GitHubClientError("file path must be a non-empty string")
        if ".." in path or "\x00" in path:
            raise GitHubClientError(f"unsafe file path: {path!r}")
        if not isinstance(ref, str) or not _REF_PATTERN.fullmatch(ref):
            raise GitHubClientError(f"invalid ref: {ref!r}")

        url = f"{_GITHUB_RAW_BASE}/{owner}/{repo}/{ref}/{path}"
        response = self._retrieval_client.fetch("GET", url)
        if response.status_code != 200:
            raise GitHubClientError(
                f"GitHub returned HTTP {response.status_code} for "
                f"{owner}/{repo}/{ref}/{path}"
            )
        return response


__all__ = ["GitHubClient", "GitHubClientError"]
