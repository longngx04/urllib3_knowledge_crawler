"""Unit tests for bounded provider retry policy."""

from datetime import UTC, datetime

import pytest

from crawler.config import HttpClientConfig
from crawler.utils.retry import RetryPolicyError, retry_decision


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


def test_retry_after_http_date_is_respected() -> None:
    now = datetime(2026, 8, 4, 12, 0, tzinfo=UTC)
    decision = retry_decision(
        status_code=429,
        headers={"Retry-After": "Tue, 04 Aug 2026 12:00:10 GMT"},
        host="example.com",
        attempt=1,
        now=now,
        config=_config(),
    )

    assert decision.should_retry is True
    assert decision.delay_seconds == 10
    assert decision.reason == "retry_after"


def test_retry_after_above_bound_is_rejected() -> None:
    with pytest.raises(RetryPolicyError, match="exceeds"):
        retry_decision(
            status_code=429,
            headers={"Retry-After": "61"},
            host="example.com",
            attempt=1,
            now=datetime(2026, 8, 4, tzinfo=UTC),
            config=_config(),
        )


def test_permanent_status_is_not_retried() -> None:
    decision = retry_decision(
        status_code=404,
        headers={},
        host="example.com",
        attempt=1,
        now=datetime(2026, 8, 4, tzinfo=UTC),
        config=_config(),
    )

    assert decision.should_retry is False
    assert decision.delay_seconds == 0
