"""Bounded adapter for the public PyPI project metadata endpoint."""

from __future__ import annotations

import re

from packaging.utils import canonicalize_name

from crawler.utils.http import RetrievalClient, RetrievedResponse

_PROJECT_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,198}[A-Za-z0-9])?$")
_PYPI_BASE_URL = "https://pypi.org/pypi"


class PyPIClientError(RuntimeError):
    """Raised when PyPI project metadata cannot be safely retrieved."""


class PyPIClient:
    """Fetch exact project JSON through the shared retrieval boundary."""

    def __init__(self, retrieval_client: RetrievalClient) -> None:
        self._retrieval_client = retrieval_client

    def fetch_project(self, project_name: str) -> RetrievedResponse:
        """Fetch one canonical PyPI project JSON response."""
        if not isinstance(project_name, str) or not _PROJECT_NAME.fullmatch(
            project_name
        ):
            raise PyPIClientError("invalid PyPI project name")

        canonical_name = canonicalize_name(project_name)
        response = self._retrieval_client.fetch(
            "GET",
            f"{_PYPI_BASE_URL}/{canonical_name}/json",
            headers={"Accept": "application/json"},
        )
        if response.status_code != 200:
            raise PyPIClientError(
                f"PyPI returned HTTP {response.status_code} for {canonical_name}"
            )
        content_type = response.headers.get("content-type", "")
        if content_type.partition(";")[0].strip().lower() != "application/json":
            raise PyPIClientError("PyPI response is not application/json")
        return response


__all__ = ["PyPIClient", "PyPIClientError"]
