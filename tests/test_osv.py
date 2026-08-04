"""Unit tests for the OSV client adapter."""

import json

import pytest
import respx
from httpx import Response

from crawler.clients.osv import OSVClient, OSVClientError
from crawler.config import HttpClientConfig
from crawler.utils.cache import RawResponseStore
from crawler.utils.http import RetrievalClient


@pytest.fixture
def retrieval_client(tmp_path) -> RetrievalClient:
    config = HttpClientConfig(
        timeout_seconds=5.0,
        max_retries=0,
        cache_enabled=True,
        respect_rate_limits=True,
        max_response_bytes=10_485_760,
        initial_backoff_seconds=1.0,
        max_retry_delay_seconds=60.0,
    )
    store = RawResponseStore(tmp_path / "raw_cache")
    return RetrievalClient(config=config, store=store)


def test_osv_client_invalid_package_name(retrieval_client):
    client = OSVClient(retrieval_client)
    with pytest.raises(OSVClientError, match="invalid package name"):
        client.query_package("../invalid")


def test_osv_client_invalid_vuln_id(retrieval_client):
    client = OSVClient(retrieval_client)
    with pytest.raises(OSVClientError, match="invalid package name"):
        client.query_package("")
    with pytest.raises(OSVClientError, match="invalid vulnerability ID"):
        client.fetch_vuln("invalid id with spaces")


@respx.mock
def test_osv_client_query_package_success(retrieval_client):
    client = OSVClient(retrieval_client)
    payload = {"vulns": [{"id": "GHSA-565x-2c8m-578w"}]}

    respx.post("https://api.osv.dev/v1/query").mock(
        return_value=Response(
            200,
            json=payload,
            headers={"Content-Type": "application/json"},
        )
    )

    response = client.query_package("urllib3", ecosystem="PyPI")
    assert response.status_code == 200
    data = json.loads(response.content.decode("utf-8"))
    assert data["vulns"][0]["id"] == "GHSA-565x-2c8m-578w"


@respx.mock
def test_osv_client_fetch_vuln_success(retrieval_client):
    client = OSVClient(retrieval_client)
    payload = {"id": "CVE-2023-45803", "summary": "Body leak"}

    respx.get("https://api.osv.dev/v1/vulns/CVE-2023-45803").mock(
        return_value=Response(
            200,
            json=payload,
            headers={"Content-Type": "application/json"},
        )
    )

    response = client.fetch_vuln("CVE-2023-45803")
    assert response.status_code == 200
    data = json.loads(response.content.decode("utf-8"))
    assert data["id"] == "CVE-2023-45803"


@respx.mock
def test_osv_client_non_200_error(retrieval_client):
    client = OSVClient(retrieval_client)

    respx.get("https://api.osv.dev/v1/vulns/NONEXISTENT").mock(
        return_value=Response(404, text="Not Found")
    )

    with pytest.raises(OSVClientError, match="OSV vuln lookup returned HTTP 404"):
        client.fetch_vuln("NONEXISTENT")


@respx.mock
def test_osv_client_invalid_content_type(retrieval_client):
    client = OSVClient(retrieval_client)

    respx.post("https://api.osv.dev/v1/query").mock(
        return_value=Response(
            200,
            text="<html>Error</html>",
            headers={"Content-Type": "text/html"},
        )
    )

    with pytest.raises(OSVClientError, match="not application/json"):
        client.query_package("urllib3")
