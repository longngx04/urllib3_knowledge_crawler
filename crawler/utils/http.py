"""Security-bounded shared HTTP retrieval client."""

from __future__ import annotations

import hashlib
import logging
import os
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType

import httpx

from crawler.config import HttpClientConfig
from crawler.utils.cache import (
    SENSITIVE_REQUEST_HEADERS,
    CacheEntryTooLargeError,
    RawResponseStore,
    RequestIdentity,
    UnsafeRequestError,
    build_request_identity,
    sanitized_response_headers,
)
from crawler.utils.retry import (
    RetryPolicyError,
    exception_retry_delay,
    is_transient_exception,
    retry_decision,
)

_GITHUB_API_HOST = "api.github.com"


class RetrievalError(RuntimeError):
    """Base error for an unsuccessful retrieval."""


class ResponseTooLargeError(RetrievalError):
    """Raised when a declared or streamed response exceeds its configured bound."""


class RetryExhaustedError(RetrievalError):
    """Raised when approved transient retries are exhausted."""


class RateLimitError(RetrievalError):
    """Raised when a provider requests a delay outside configured bounds."""


@dataclass(frozen=True, slots=True)
class RetrievedResponse:
    """Exact retrieved bytes and provenance-ready response metadata."""

    status_code: int
    url: str
    headers: Mapping[str, str]
    content: bytes
    retrieved_at: datetime
    body_sha256: str
    cache_key: str
    from_cache: bool
    attempts: int


class RetrievalClient:
    """Synchronous HTTPS client with verified caching and bounded retries."""

    def __init__(
        self,
        *,
        config: HttpClientConfig,
        store: RawResponseStore,
        github_token: str | None = None,
        transport: httpx.BaseTransport | None = None,
        sleeper: Callable[[float], None] = time.sleep,
        clock: Callable[[], datetime] | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        token = github_token if github_token is not None else os.getenv("GITHUB_TOKEN")
        if token is not None and (not token or any(char.isspace() for char in token)):
            raise UnsafeRequestError("GitHub token has an invalid format")
        self.config = config
        self.store = store
        self._github_token = token
        self._sleeper = sleeper
        self._clock = clock or (lambda: datetime.now(UTC))
        self._logger = logger or logging.getLogger(__name__)
        self._client = httpx.Client(
            timeout=httpx.Timeout(config.timeout_seconds),
            follow_redirects=False,
            transport=transport,
            headers={"User-Agent": "urllib3-knowledge-crawler/0.1.0"},
        )

    def __enter__(self) -> RetrievalClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying HTTPX connection pool."""
        self._client.close()

    def fetch(
        self,
        method: str,
        url: str,
        *,
        content: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> RetrievedResponse:
        """Fetch one HTTPS resource or replay its integrity-checked raw response."""
        identity = build_request_identity(method, url, content)
        request_headers = self._request_headers(identity, headers or {})
        host = httpx.URL(identity.url).host

        if self.config.cache_enabled:
            try:
                cached = self.store.load(
                    identity.cache_key,
                    max_body_bytes=self.config.max_response_bytes,
                )
            except CacheEntryTooLargeError as error:
                raise ResponseTooLargeError(
                    "cached response exceeds configured maximum"
                ) from error
            if cached is not None:
                self._logger.info(
                    "retrieval cache hit request_id=%s host=%s",
                    identity.cache_key[:12],
                    host,
                )
                response = cached.metadata.response
                return RetrievedResponse(
                    status_code=response.status_code,
                    url=identity.url,
                    headers=MappingProxyType(dict(response.headers)),
                    content=cached.content,
                    retrieved_at=response.retrieved_at,
                    body_sha256=response.body_sha256,
                    cache_key=identity.cache_key,
                    from_cache=True,
                    attempts=0,
                )
            self._logger.info(
                "retrieval cache miss request_id=%s host=%s",
                identity.cache_key[:12],
                host,
            )

        attempts = 0
        while True:
            attempts += 1
            try:
                status_code, response_headers, body = self._send_once(
                    identity, content, request_headers
                )
            except ResponseTooLargeError:
                raise
            except httpx.HTTPError as error:
                if not is_transient_exception(error):
                    raise RetrievalError(
                        "permanent HTTP failure for host "
                        f"{host}: {type(error).__name__}"
                    ) from error
                if attempts > self.config.max_retries:
                    raise RetryExhaustedError(
                        "transport retries exhausted after "
                        f"{attempts} attempts for host {host}"
                    ) from error
                delay = exception_retry_delay(attempts, self.config)
                self._log_retry(identity, host, attempts, delay, type(error).__name__)
                self._sleeper(delay)
                continue

            now = self._aware_now()
            try:
                decision = retry_decision(
                    status_code=status_code,
                    headers=response_headers,
                    host=host,
                    attempt=attempts,
                    now=now,
                    config=self.config,
                )
            except RetryPolicyError as error:
                raise RateLimitError(
                    f"unsafe provider retry policy for host {host}"
                ) from error
            if decision.should_retry:
                if attempts > self.config.max_retries:
                    raise RetryExhaustedError(
                        f"HTTP {status_code} retries exhausted after "
                        f"{attempts} attempts for host {host}"
                    )
                self._log_retry(
                    identity,
                    host,
                    attempts,
                    decision.delay_seconds,
                    decision.reason,
                )
                self._sleeper(decision.delay_seconds)
                continue

            safe_headers = sanitized_response_headers(response_headers)
            if self.config.cache_enabled:
                stored = self.store.store(
                    identity=identity,
                    status_code=status_code,
                    headers=response_headers,
                    retrieved_at=now,
                    body=body,
                )
                body_sha256 = stored.metadata.response.body_sha256
            else:
                body_sha256 = hashlib.sha256(body).hexdigest()
            return RetrievedResponse(
                status_code=status_code,
                url=identity.url,
                headers=MappingProxyType(safe_headers),
                content=body,
                retrieved_at=now,
                body_sha256=body_sha256,
                cache_key=identity.cache_key,
                from_cache=False,
                attempts=attempts,
            )

    def _request_headers(
        self, identity: RequestIdentity, headers: Mapping[str, str]
    ) -> dict[str, str]:
        request_headers: dict[str, str] = {}
        total_length = 0
        for key, value in headers.items():
            normalized_key = key.strip().lower()
            if normalized_key in SENSITIVE_REQUEST_HEADERS:
                raise UnsafeRequestError(
                    "authorization and cookie headers are managed internally"
                )
            if "\r" in key or "\n" in key or "\r" in value or "\n" in value:
                raise UnsafeRequestError("request headers must not contain newlines")
            total_length += len(key) + len(value)
            if len(key) > 256 or len(value) > 4_096 or total_length > 16_384:
                raise UnsafeRequestError(
                    "request headers exceed configured safety bounds"
                )
            request_headers[key] = value
        if self._github_token and httpx.URL(identity.url).host == _GITHUB_API_HOST:
            request_headers["Authorization"] = f"Bearer {self._github_token}"
        return request_headers

    def _send_once(
        self,
        identity: RequestIdentity,
        content: bytes | None,
        headers: Mapping[str, str],
    ) -> tuple[int, dict[str, str], bytes]:
        with self._client.stream(
            identity.method,
            identity.url,
            content=content,
            headers=headers,
        ) as response:
            content_length = response.headers.get("content-length")
            if content_length is not None:
                try:
                    declared_length = int(content_length)
                except ValueError:
                    declared_length = -1
                if declared_length > self.config.max_response_bytes:
                    raise ResponseTooLargeError(
                        "response Content-Length exceeds configured maximum"
                    )

            chunks: list[bytes] = []
            total_bytes = 0
            for chunk in response.iter_bytes():
                total_bytes += len(chunk)
                if total_bytes > self.config.max_response_bytes:
                    raise ResponseTooLargeError(
                        "streamed response exceeds configured maximum"
                    )
                chunks.append(chunk)
            return response.status_code, dict(response.headers), b"".join(chunks)

    def _aware_now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise RetrievalError(
                "retrieval clock must return a timezone-aware datetime"
            )
        return now

    def _log_retry(
        self,
        identity: RequestIdentity,
        host: str,
        attempt: int,
        delay: float,
        reason: str,
    ) -> None:
        self._logger.warning(
            "retrieval retry request_id=%s host=%s attempt=%d "
            "delay_seconds=%.3f reason=%s",
            identity.cache_key[:12],
            host,
            attempt,
            delay,
            reason,
        )


__all__ = [
    "RateLimitError",
    "ResponseTooLargeError",
    "RetrievedResponse",
    "RetrievalClient",
    "RetrievalError",
    "RetryExhaustedError",
]
