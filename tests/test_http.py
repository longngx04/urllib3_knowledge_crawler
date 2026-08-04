"""Offline integration tests for the Phase 2 retrieval boundary."""

import logging
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from crawler.config import HttpClientConfig
from crawler.utils.cache import RawResponseStore, UnsafeRequestError
from crawler.utils.http import (
    RateLimitError,
    ResponseTooLargeError,
    RetrievalClient,
    RetryExhaustedError,
)


def _config(**updates: object) -> HttpClientConfig:
    values: dict[str, object] = {
        "timeout_seconds": 5.0,
        "max_retries": 2,
        "cache_enabled": True,
        "respect_rate_limits": True,
        "max_response_bytes": 1024,
        "initial_backoff_seconds": 1.0,
        "max_retry_delay_seconds": 60.0,
    }
    values.update(updates)
    return HttpClientConfig.model_validate(values)


def test_second_request_replays_verified_cache_without_transport(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    calls = 0

    def first_handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json", "ETag": '"v1"'},
            content=b'{"source":"fixture"}',
            request=request,
        )

    store = RawResponseStore(tmp_path / "raw")
    caplog.set_level(logging.INFO)
    with RetrievalClient(
        config=_config(),
        store=store,
        transport=httpx.MockTransport(first_handler),
    ) as client:
        first = client.fetch("GET", "https://example.com/data?b=2&a=1")

    def fail_handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"unexpected transport call: {request.url.host}")

    with RetrievalClient(
        config=_config(),
        store=store,
        transport=httpx.MockTransport(fail_handler),
    ) as client:
        second = client.fetch("get", "https://example.com/data?a=1&b=2#ignored")

    assert calls == 1
    assert first.from_cache is False
    assert first.attempts == 1
    assert second.from_cache is True
    assert second.attempts == 0
    assert first.content == second.content
    assert first.body_sha256 == second.body_sha256
    assert first.cache_key == second.cache_key
    assert "retrieval cache miss" in caplog.text
    assert "retrieval cache hit" in caplog.text


def test_429_retries_after_provider_delay(tmp_path: Path) -> None:
    attempts = 0
    sleeps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(429, headers={"Retry-After": "2"}, request=request)
        return httpx.Response(200, content=b"ok", request=request)

    with RetrievalClient(
        config=_config(),
        store=RawResponseStore(tmp_path / "raw"),
        transport=httpx.MockTransport(handler),
        sleeper=sleeps.append,
        clock=lambda: datetime(2026, 8, 4, tzinfo=UTC),
    ) as client:
        response = client.fetch("GET", "https://example.com/data")

    assert attempts == 2
    assert sleeps == [2.0]
    assert response.attempts == 2
    assert response.content == b"ok"


@pytest.mark.parametrize("status_code", [500, 502, 503, 504])
def test_transient_server_statuses_retry_once(tmp_path: Path, status_code: int) -> None:
    attempts = 0
    sleeps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        current_status = status_code if attempts == 1 else 200
        return httpx.Response(current_status, content=b"response", request=request)

    with RetrievalClient(
        config=_config(),
        store=RawResponseStore(tmp_path / "raw"),
        transport=httpx.MockTransport(handler),
        sleeper=sleeps.append,
    ) as client:
        response = client.fetch("GET", "https://example.com/data")

    assert response.status_code == 200
    assert attempts == 2
    assert sleeps == [1.0]


def test_connection_error_retries_once_then_succeeds(tmp_path: Path) -> None:
    attempts = 0
    sleeps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise httpx.ReadError("synthetic connection reset", request=request)
        return httpx.Response(200, content=b"ok", request=request)

    with RetrievalClient(
        config=_config(),
        store=RawResponseStore(tmp_path / "raw"),
        transport=httpx.MockTransport(handler),
        sleeper=sleeps.append,
    ) as client:
        response = client.fetch("GET", "https://example.com/data")

    assert response.content == b"ok"
    assert response.attempts == 2
    assert sleeps == [1.0]


def test_permanent_status_is_returned_without_retry(tmp_path: Path) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(404, content=b"missing", request=request)

    with RetrievalClient(
        config=_config(),
        store=RawResponseStore(tmp_path / "raw"),
        transport=httpx.MockTransport(handler),
        sleeper=lambda delay: pytest.fail(f"unexpected sleep: {delay}"),
    ) as client:
        response = client.fetch("GET", "https://example.com/missing")

    assert calls == 1
    assert response.status_code == 404
    assert response.content == b"missing"


def test_timeout_retries_are_bounded_and_actionable(tmp_path: Path) -> None:
    attempts = 0
    sleeps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        raise httpx.ReadTimeout("synthetic timeout", request=request)

    with (
        RetrievalClient(
            config=_config(),
            store=RawResponseStore(tmp_path / "raw"),
            transport=httpx.MockTransport(handler),
            sleeper=sleeps.append,
        ) as client,
        pytest.raises(RetryExhaustedError, match="3 attempts.*example.com"),
    ):
        client.fetch("GET", "https://example.com/data")

    assert attempts == 3
    assert sleeps == [1.0, 2.0]


def test_github_rate_limit_reset_is_detected(tmp_path: Path) -> None:
    now = datetime(2026, 8, 4, 12, 0, tzinfo=UTC)
    attempts = 0
    sleeps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(
                403,
                headers={
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(now.timestamp()) + 3),
                },
                request=request,
            )
        return httpx.Response(200, content=b"ok", request=request)

    with RetrievalClient(
        config=_config(),
        store=RawResponseStore(tmp_path / "raw"),
        transport=httpx.MockTransport(handler),
        sleeper=sleeps.append,
        clock=lambda: now,
    ) as client:
        response = client.fetch("GET", "https://api.github.com/repos/example/project")

    assert response.status_code == 200
    assert sleeps == [3.0]


def test_unbounded_retry_after_raises_without_sleep(tmp_path: Path) -> None:
    sleeps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "120"}, request=request)

    with (
        RetrievalClient(
            config=_config(),
            store=RawResponseStore(tmp_path / "raw"),
            transport=httpx.MockTransport(handler),
            sleeper=sleeps.append,
        ) as client,
        pytest.raises(RateLimitError, match="example.com"),
    ):
        client.fetch("GET", "https://example.com/data")

    assert sleeps == []


def test_github_token_is_scoped_and_never_persisted_or_logged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    token = "github_test_token_value"
    monkeypatch.setenv("GITHUB_TOKEN", token)
    observed: list[tuple[str, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append((request.url.host, request.headers.get("authorization")))
        return httpx.Response(200, content=b"ok", request=request)

    store = RawResponseStore(tmp_path / "raw")
    caplog.set_level(logging.INFO)
    with RetrievalClient(
        config=_config(),
        store=store,
        transport=httpx.MockTransport(handler),
    ) as client:
        client.fetch("GET", "https://api.github.com/repos/example/project")
        client.fetch("GET", "https://example.com/public")

    assert observed == [
        ("api.github.com", f"Bearer {token}"),
        ("example.com", None),
    ]
    persisted = "".join(
        path.read_text(encoding="utf-8", errors="ignore")
        for path in store.root.rglob("*")
        if path.is_file()
    )
    assert token not in persisted
    assert token not in caplog.text
    assert "authorization" not in persisted.lower()


@pytest.mark.parametrize("header", ["Authorization", "Cookie", "Proxy-Authorization"])
def test_sensitive_caller_headers_are_rejected(tmp_path: Path, header: str) -> None:
    with (
        RetrievalClient(
            config=_config(),
            store=RawResponseStore(tmp_path / "raw"),
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, request=request)
            ),
        ) as client,
        pytest.raises(UnsafeRequestError, match="managed internally"),
    ):
        client.fetch("GET", "https://example.com/data", headers={header: "secret"})


def test_oversized_caller_header_is_rejected(tmp_path: Path) -> None:
    with (
        RetrievalClient(
            config=_config(),
            store=RawResponseStore(tmp_path / "raw"),
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, request=request)
            ),
        ) as client,
        pytest.raises(UnsafeRequestError, match="safety bounds"),
    ):
        client.fetch(
            "GET", "https://example.com/data", headers={"X-Large": "x" * 4_097}
        )


def test_declared_oversized_response_is_not_stored(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Length": "5"},
            content=b"x",
            request=request,
        )

    store = RawResponseStore(tmp_path / "raw")
    with (
        RetrievalClient(
            config=_config(max_response_bytes=4),
            store=store,
            transport=httpx.MockTransport(handler),
        ) as client,
        pytest.raises(ResponseTooLargeError, match="Content-Length"),
    ):
        client.fetch("GET", "https://example.com/data")

    assert not any(path.is_file() for path in store.root.rglob("*"))


def test_streamed_oversized_response_is_not_stored(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            stream=httpx.ByteStream(b"12345"),
            request=request,
        )

    store = RawResponseStore(tmp_path / "raw")
    with (
        RetrievalClient(
            config=_config(max_response_bytes=4),
            store=store,
            transport=httpx.MockTransport(handler),
        ) as client,
        pytest.raises(ResponseTooLargeError, match="streamed"),
    ):
        client.fetch("GET", "https://example.com/data")

    assert not any(path.is_file() for path in store.root.rglob("*"))


def test_cache_disabled_contacts_transport_every_time(tmp_path: Path) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, content=b"ok", request=request)

    store = RawResponseStore(tmp_path / "raw")
    with RetrievalClient(
        config=_config(cache_enabled=False),
        store=store,
        transport=httpx.MockTransport(handler),
    ) as client:
        first = client.fetch("GET", "https://example.com/data")
        second = client.fetch("GET", "https://example.com/data")

    assert calls == 2
    assert first.from_cache is second.from_cache is False
    assert not any(path.is_file() for path in store.root.rglob("*"))


def test_oversized_cached_response_is_rejected_before_transport(tmp_path: Path) -> None:
    store = RawResponseStore(tmp_path / "raw")

    def first_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"12345", request=request)

    with RetrievalClient(
        config=_config(max_response_bytes=10),
        store=store,
        transport=httpx.MockTransport(first_handler),
    ) as client:
        client.fetch("GET", "https://example.com/data")

    def fail_handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"unexpected transport call: {request.url.host}")

    with (
        RetrievalClient(
            config=_config(max_response_bytes=4),
            store=store,
            transport=httpx.MockTransport(fail_handler),
        ) as client,
        pytest.raises(ResponseTooLargeError, match="cached response"),
    ):
        client.fetch("GET", "https://example.com/data")
