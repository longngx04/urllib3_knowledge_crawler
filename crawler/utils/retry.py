"""Pure retry classification and bounded delay calculation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

import httpx

from crawler.config import HttpClientConfig

TRANSIENT_STATUS_CODES = frozenset({429, 500, 502, 503, 504})


class RetryPolicyError(ValueError):
    """Raised when a provider requests an unsafe retry delay."""


@dataclass(frozen=True, slots=True)
class RetryDecision:
    """Retry classification for one failed attempt."""

    should_retry: bool
    delay_seconds: float
    reason: str


def is_transient_exception(error: BaseException) -> bool:
    """Return whether an HTTPX exception is safe to retry."""
    return isinstance(error, (httpx.TimeoutException, httpx.NetworkError))


def _retry_after_seconds(value: str, now: datetime) -> float | None:
    value = value.strip()
    if not value:
        return None
    try:
        seconds = int(value)
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(value)
        except (TypeError, ValueError, OverflowError):
            return None
        if retry_at.tzinfo is None or retry_at.utcoffset() is None:
            return None
        delta = retry_at.astimezone(UTC) - now.astimezone(UTC)
        return max(0.0, delta.total_seconds())
    return float(seconds) if seconds >= 0 else None


def _github_reset_seconds(value: str, now: datetime) -> float | None:
    try:
        reset_at = int(value)
    except ValueError:
        return None
    return max(0.0, float(reset_at) - now.timestamp())


def retry_decision(
    *,
    status_code: int,
    headers: Mapping[str, str],
    host: str,
    attempt: int,
    now: datetime,
    config: HttpClientConfig,
) -> RetryDecision:
    """Classify one HTTP response and calculate its bounded next delay."""
    normalized_headers = {key.lower(): value for key, value in headers.items()}
    github_limited = (
        status_code == 403
        and host == "api.github.com"
        and normalized_headers.get("x-ratelimit-remaining") == "0"
    )
    if status_code not in TRANSIENT_STATUS_CODES and not github_limited:
        return RetryDecision(False, 0.0, "permanent_status")

    exponential = config.initial_backoff_seconds * float(2 ** max(0, attempt - 1))
    fallback_delay = min(exponential, config.max_retry_delay_seconds)
    provider_delay: float | None = None
    reason = "transient_status"

    if config.respect_rate_limits:
        retry_after = normalized_headers.get("retry-after")
        if retry_after is not None:
            provider_delay = _retry_after_seconds(retry_after, now)
            reason = "retry_after"
        if provider_delay is None and github_limited:
            reset = normalized_headers.get("x-ratelimit-reset")
            if reset is not None:
                provider_delay = _github_reset_seconds(reset, now)
                reason = "github_rate_limit"

    if provider_delay is not None:
        if provider_delay > config.max_retry_delay_seconds:
            raise RetryPolicyError("provider retry delay exceeds configured maximum")
        fallback_delay = max(fallback_delay, provider_delay)
    return RetryDecision(True, fallback_delay, reason)


def exception_retry_delay(attempt: int, config: HttpClientConfig) -> float:
    """Return bounded exponential delay for a transient transport exception."""
    exponential = config.initial_backoff_seconds * float(2 ** max(0, attempt - 1))
    return float(min(exponential, config.max_retry_delay_seconds))


__all__ = [
    "RetryDecision",
    "RetryPolicyError",
    "TRANSIENT_STATUS_CODES",
    "exception_retry_delay",
    "is_transient_exception",
    "retry_decision",
]
