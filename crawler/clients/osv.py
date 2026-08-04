"""Bounded adapter for the Open Source Vulnerabilities (OSV) REST API."""

from __future__ import annotations

import json
import re

from crawler.utils.http import RetrievalClient, RetrievedResponse

_PACKAGE_NAME_PATTERN = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,198}[A-Za-z0-9])?$"
)
_VULN_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{3,64}$")
_OSV_BASE_URL = "https://api.osv.dev/v1"


class OSVClientError(RuntimeError):
    """Raised when an OSV resource cannot be safely retrieved."""


class OSVClient:
    """Fetch package vulnerabilities and vulnerability details from OSV."""

    def __init__(self, retrieval_client: RetrievalClient) -> None:
        self._retrieval_client = retrieval_client

    def query_package(
        self, package_name: str, ecosystem: str = "PyPI"
    ) -> RetrievedResponse:
        """Fetch all vulnerabilities for a package in an ecosystem."""
        if not isinstance(package_name, str) or not _PACKAGE_NAME_PATTERN.fullmatch(
            package_name
        ):
            raise OSVClientError(
                f"invalid package name for OSV query: {package_name!r}"
            )
        if not isinstance(ecosystem, str) or not ecosystem:
            raise OSVClientError(f"invalid ecosystem for OSV query: {ecosystem!r}")

        payload = {
            "package": {
                "name": package_name,
                "ecosystem": ecosystem,
            }
        }
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        url = f"{_OSV_BASE_URL}/query"

        response = self._retrieval_client.fetch(
            "POST",
            url,
            content=body,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        if response.status_code != 200:
            raise OSVClientError(
                f"OSV query returned HTTP {response.status_code} for {package_name}"
            )
        content_type = response.headers.get("content-type", "")
        if content_type.partition(";")[0].strip().lower() != "application/json":
            raise OSVClientError("OSV query response is not application/json")
        return response

    def fetch_vuln(self, vuln_id: str) -> RetrievedResponse:
        """Fetch full vulnerability details by OSV/GHSA/CVE/PYSEC ID."""
        if not isinstance(vuln_id, str) or not _VULN_ID_PATTERN.fullmatch(vuln_id):
            raise OSVClientError(
                f"invalid vulnerability ID for OSV lookup: {vuln_id!r}"
            )

        url = f"{_OSV_BASE_URL}/vulns/{vuln_id}"
        response = self._retrieval_client.fetch(
            "GET",
            url,
            headers={"Accept": "application/json"},
        )
        if response.status_code != 200:
            raise OSVClientError(
                f"OSV vuln lookup returned HTTP {response.status_code} for {vuln_id}"
            )
        content_type = response.headers.get("content-type", "")
        if content_type.partition(";")[0].strip().lower() != "application/json":
            raise OSVClientError("OSV vuln response is not application/json")
        return response


__all__ = ["OSVClient", "OSVClientError"]
