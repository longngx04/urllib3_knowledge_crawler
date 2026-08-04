"""Tests for deterministic request identity and verified raw storage."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from crawler.utils.cache import (
    CacheCorruptionError,
    RawResponseStore,
    UnsafeRequestError,
    UnsafeStoragePathError,
    build_request_identity,
)


def test_request_identity_normalizes_query_order_and_fragment() -> None:
    first = build_request_identity(
        "get", "https://EXAMPLE.com/resource?z=2&a=1&a=0#ignored"
    )
    second = build_request_identity("GET", "https://example.com/resource?a=0&a=1&z=2")

    assert first == second
    assert first.method == "GET"
    assert first.url == "https://example.com/resource?a=0&a=1&z=2"


def test_request_identity_distinguishes_none_and_empty_body() -> None:
    without_body = build_request_identity("POST", "https://example.com/api")
    empty_body = build_request_identity("POST", "https://example.com/api", b"")

    assert without_body.body_sha256 is None
    assert empty_body.body_sha256 is not None
    assert without_body.cache_key != empty_body.cache_key


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/data",
        "https://user:password@example.com/data",
        "https://example.com/data?api_key=secret",
        "https://example.com/data?access-token=secret",
        "not-a-url",
    ],
)
def test_request_identity_rejects_unsafe_urls(url: str) -> None:
    with pytest.raises(UnsafeRequestError):
        build_request_identity("GET", url)


def test_request_identity_rejects_oversized_url() -> None:
    with pytest.raises(UnsafeRequestError, match="8192"):
        build_request_identity("GET", f"https://example.com/{'x' * 8_200}")


def test_raw_store_round_trip_preserves_safe_metadata(tmp_path: Path) -> None:
    identity = build_request_identity("GET", "https://example.com/data")
    store = RawResponseStore(tmp_path / "raw")
    stored = store.store(
        identity=identity,
        status_code=200,
        headers={
            "Content-Type": "application/json",
            "ETag": '"abc"',
            "Set-Cookie": "session=secret",
            "X-Private": "do-not-store",
        },
        retrieved_at=datetime(2026, 8, 4, tzinfo=UTC),
        body=b'{"ok":true}',
    )
    loaded = store.load(identity.cache_key)

    assert loaded == stored
    assert loaded is not None
    assert loaded.metadata.response.content_type == "application/json"
    assert loaded.metadata.response.headers == {
        "content-type": "application/json",
        "etag": '"abc"',
    }
    assert loaded.content == b'{"ok":true}'

    body_path = next((tmp_path / "raw").rglob("*.body"))
    metadata_path = next((tmp_path / "raw").rglob("*.json"))
    assert body_path.stat().st_mode & 0o777 == 0o600
    assert metadata_path.stat().st_mode & 0o777 == 0o600
    persisted = metadata_path.read_text(encoding="utf-8")
    assert "session=secret" not in persisted
    assert "do-not-store" not in persisted
    assert json.loads(persisted)["response"]["body_sha256"]


def test_raw_store_detects_body_corruption(tmp_path: Path) -> None:
    identity = build_request_identity("GET", "https://example.com/data")
    store = RawResponseStore(tmp_path / "raw")
    store.store(
        identity=identity,
        status_code=200,
        headers={},
        retrieved_at=datetime(2026, 8, 4, tzinfo=UTC),
        body=b"original",
    )
    next((tmp_path / "raw").rglob("*.body")).write_bytes(b"tampered")

    with pytest.raises(CacheCorruptionError, match="SHA-256"):
        store.load(identity.cache_key)


def test_raw_store_detects_incomplete_entry(tmp_path: Path) -> None:
    identity = build_request_identity("GET", "https://example.com/data")
    store = RawResponseStore(tmp_path / "raw")
    shard = store.root / identity.cache_key[:2]
    shard.mkdir()
    (shard / f"{identity.cache_key}.body").write_bytes(b"orphan")

    with pytest.raises(CacheCorruptionError, match="incomplete"):
        store.load(identity.cache_key)


def test_raw_store_rejects_injected_sensitive_metadata_header(tmp_path: Path) -> None:
    identity = build_request_identity("GET", "https://example.com/data")
    store = RawResponseStore(tmp_path / "raw")
    store.store(
        identity=identity,
        status_code=200,
        headers={},
        retrieved_at=datetime(2026, 8, 4, tzinfo=UTC),
        body=b"original",
    )
    metadata_path = next((tmp_path / "raw").rglob("*.json"))
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["response"]["headers"]["authorization"] = "Bearer injected"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    with pytest.raises(CacheCorruptionError, match="decoded"):
        store.load(identity.cache_key)


def test_raw_store_rejects_symlink_root(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)

    with pytest.raises(UnsafeStoragePathError, match="symlink"):
        RawResponseStore(link)


def test_raw_store_rejects_symlink_entry(tmp_path: Path) -> None:
    identity = build_request_identity("GET", "https://example.com/data")
    store = RawResponseStore(tmp_path / "raw")
    shard = store.root / identity.cache_key[:2]
    shard.mkdir()
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    (shard / f"{identity.cache_key}.body").symlink_to(outside)

    with pytest.raises(CacheCorruptionError, match="symlink"):
        store.load(identity.cache_key)
