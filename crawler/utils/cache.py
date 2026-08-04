"""Deterministic request identity and verified raw-response storage."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Annotated
from urllib.parse import urlencode

import httpx
from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
)

_CACHE_KEY_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_METHOD_PATTERN = re.compile(r"^[A-Z]+$")
_SENSITIVE_QUERY_KEYS = frozenset(
    {
        "accesskey",
        "accesstoken",
        "apikey",
        "authorization",
        "clientsecret",
        "password",
        "secret",
        "signature",
        "token",
    }
)
SENSITIVE_REQUEST_HEADERS = frozenset(
    {"authorization", "cookie", "proxy-authorization", "set-cookie"}
)
PERSISTED_RESPONSE_HEADERS = frozenset(
    {
        "cache-control",
        "content-type",
        "date",
        "etag",
        "expires",
        "last-modified",
        "retry-after",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "x-ratelimit-resource",
    }
)
_MAX_METADATA_BYTES = 65_536
_MAX_HEADER_VALUE_LENGTH = 2_048
_MAX_URL_LENGTH = 8_192


class UnsafeRequestError(ValueError):
    """Raised when request identity could expose credentials or ambiguity."""


class UnsafeStoragePathError(ValueError):
    """Raised when a raw-store path or cache key is unsafe."""


class CacheCorruptionError(RuntimeError):
    """Raised when cached metadata or body integrity cannot be verified."""


class CacheEntryTooLargeError(CacheCorruptionError):
    """Raised before reading a cached body that exceeds its configured bound."""


@dataclass(frozen=True, slots=True)
class RequestIdentity:
    """Canonical identity used to locate one raw response."""

    method: str
    url: str
    body_sha256: str | None
    cache_key: str


class RequestMetadata(BaseModel):
    """Persisted credential-free request identity."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    method: Annotated[str, Field(pattern=r"^[A-Z]+$", max_length=16)]
    url: Annotated[str, Field(max_length=_MAX_URL_LENGTH)]
    body_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")] | None


class ResponseMetadata(BaseModel):
    """Persisted response facts required for cache replay and provenance."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    status_code: int = Field(ge=100, le=599)
    content_type: Annotated[str, Field(max_length=_MAX_HEADER_VALUE_LENGTH)] | None
    retrieved_at: AwareDatetime
    body_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    body_size: int = Field(ge=0)
    headers: dict[str, str]

    @field_validator("headers")
    @classmethod
    def validate_safe_headers(cls, headers: dict[str, str]) -> dict[str, str]:
        for key, value in headers.items():
            if key not in PERSISTED_RESPONSE_HEADERS or key != key.lower():
                raise ValueError("cache metadata contains a non-allowlisted header")
            if len(value) > _MAX_HEADER_VALUE_LENGTH:
                raise ValueError("cache metadata header exceeds size limit")
        return dict(sorted(headers.items()))


class RawResponseMetadata(BaseModel):
    """Sidecar metadata stored beside exact raw response bytes."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    request: RequestMetadata
    response: ResponseMetadata


@dataclass(frozen=True, slots=True)
class StoredResponse:
    """One integrity-checked cached response."""

    cache_key: str
    metadata: RawResponseMetadata
    content: bytes


def _normalized_sensitive_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


def _cache_key(method: str, url: str, body_sha256: str | None) -> str:
    payload = json.dumps(
        {"body_sha256": body_sha256, "method": method, "url": url},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def build_request_identity(
    method: str, url: str, body: bytes | None = None
) -> RequestIdentity:
    """Return a deterministic, credential-free identity for one HTTPS request."""
    normalized_method = method.strip().upper()
    if len(normalized_method) > 16 or not _METHOD_PATTERN.fullmatch(normalized_method):
        raise UnsafeRequestError("HTTP method must contain ASCII letters only")
    if len(url) > _MAX_URL_LENGTH:
        raise UnsafeRequestError("request URL exceeds the 8192-character limit")

    try:
        parsed = httpx.URL(url)
    except (TypeError, ValueError) as error:
        raise UnsafeRequestError("request URL is invalid") from error
    if parsed.scheme != "https" or not parsed.host:
        raise UnsafeRequestError("request URL must use HTTPS and include a host")
    if parsed.userinfo:
        raise UnsafeRequestError("request URL must not contain userinfo")

    query_pairs = sorted(parsed.params.multi_items())
    for key, _ in query_pairs:
        if _normalized_sensitive_key(key) in _SENSITIVE_QUERY_KEYS:
            raise UnsafeRequestError(
                "credentials are not allowed in request query parameters"
            )
    normalized_query = urlencode(query_pairs).encode("ascii") if query_pairs else None
    normalized_url = str(parsed.copy_with(query=normalized_query, fragment=None))
    body_sha256 = hashlib.sha256(body).hexdigest() if body is not None else None
    return RequestIdentity(
        method=normalized_method,
        url=normalized_url,
        body_sha256=body_sha256,
        cache_key=_cache_key(normalized_method, normalized_url, body_sha256),
    )


def sanitized_response_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Return only bounded cache/rate-limit headers safe to persist and log."""
    sanitized: dict[str, str] = {}
    for key, value in headers.items():
        normalized_key = key.lower()
        if normalized_key in PERSISTED_RESPONSE_HEADERS:
            sanitized[normalized_key] = value[:_MAX_HEADER_VALUE_LENGTH]
    return dict(sorted(sanitized.items()))


class RawResponseStore:
    """Filesystem store for exact raw bytes and deterministic safe metadata."""

    def __init__(self, root: Path) -> None:
        if root.exists() and root.is_symlink():
            raise UnsafeStoragePathError("raw response root must not be a symlink")
        try:
            root.mkdir(parents=True, exist_ok=True)
            self.root = root.resolve(strict=True)
        except OSError as error:
            raise UnsafeStoragePathError("cannot create raw response root") from error
        if not self.root.is_dir():
            raise UnsafeStoragePathError("raw response root must be a directory")

    def _paths(self, cache_key: str) -> tuple[Path, Path]:
        if not _CACHE_KEY_PATTERN.fullmatch(cache_key):
            raise UnsafeStoragePathError("cache key must be a full lowercase SHA-256")
        directory = self.root / cache_key[:2]
        return directory / f"{cache_key}.body", directory / f"{cache_key}.json"

    def load(
        self, cache_key: str, *, max_body_bytes: int | None = None
    ) -> StoredResponse | None:
        """Load and verify a cached response, or return ``None`` for a true miss."""
        body_path, metadata_path = self._paths(cache_key)
        if body_path.is_symlink() or metadata_path.is_symlink():
            raise CacheCorruptionError("cache entry must not contain symlinks")
        body_exists = body_path.is_file()
        metadata_exists = metadata_path.is_file()
        if not body_exists and not metadata_exists:
            return None
        if body_exists != metadata_exists:
            raise CacheCorruptionError("cache entry is incomplete")

        try:
            if metadata_path.stat().st_size > _MAX_METADATA_BYTES:
                raise CacheCorruptionError("cache metadata exceeds size limit")
            metadata = RawResponseMetadata.model_validate_json(
                metadata_path.read_text(encoding="utf-8")
            )
            body_size = body_path.stat().st_size
            if body_size != metadata.response.body_size:
                raise CacheCorruptionError("cached response body size mismatch")
            if max_body_bytes is not None and body_size > max_body_bytes:
                raise CacheEntryTooLargeError(
                    "cached response exceeds configured maximum"
                )
            content = body_path.read_bytes()
        except CacheCorruptionError:
            raise
        except (OSError, UnicodeError, ValidationError) as error:
            raise CacheCorruptionError("cache entry cannot be decoded") from error

        expected_key = _cache_key(
            metadata.request.method,
            metadata.request.url,
            metadata.request.body_sha256,
        )
        if expected_key != cache_key:
            raise CacheCorruptionError("cache metadata does not match its key")
        actual_sha256 = hashlib.sha256(content).hexdigest()
        if actual_sha256 != metadata.response.body_sha256:
            raise CacheCorruptionError("cached response body SHA-256 mismatch")
        return StoredResponse(cache_key, metadata, content)

    def store(
        self,
        *,
        identity: RequestIdentity,
        status_code: int,
        headers: Mapping[str, str],
        retrieved_at: datetime,
        body: bytes,
    ) -> StoredResponse:
        """Atomically persist exact bytes and their credential-free metadata."""
        body_sha256 = hashlib.sha256(body).hexdigest()
        normalized_headers = {key.lower(): value for key, value in headers.items()}
        safe_headers = sanitized_response_headers(normalized_headers)
        metadata = RawResponseMetadata(
            request=RequestMetadata(
                method=identity.method,
                url=identity.url,
                body_sha256=identity.body_sha256,
            ),
            response=ResponseMetadata(
                status_code=status_code,
                content_type=safe_headers.get("content-type"),
                retrieved_at=retrieved_at,
                body_sha256=body_sha256,
                body_size=len(body),
                headers=safe_headers,
            ),
        )
        body_path, metadata_path = self._paths(identity.cache_key)
        try:
            body_path.parent.mkdir(parents=True, exist_ok=True)
            if body_path.parent.resolve(strict=True).parent != self.root:
                raise UnsafeStoragePathError("cache shard escaped raw response root")
        except OSError as error:
            raise UnsafeStoragePathError("cannot create cache shard") from error

        self._atomic_write(body_path, body)
        encoded_metadata = (
            json.dumps(
                metadata.model_dump(mode="json"),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        self._atomic_write(metadata_path, encoded_metadata)
        return StoredResponse(identity.cache_key, metadata, body)

    @staticmethod
    def _atomic_write(path: Path, content: bytes) -> None:
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=path.parent, prefix=f".{path.name}.", delete=False
            ) as temporary:
                temporary_path = Path(temporary.name)
                os.chmod(temporary_path, 0o600)
                temporary.write(content)
                temporary.flush()
                os.fsync(temporary.fileno())
            os.replace(temporary_path, path)
        except OSError as error:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
            raise UnsafeStoragePathError("cannot persist raw response") from error


__all__ = [
    "CacheCorruptionError",
    "CacheEntryTooLargeError",
    "PERSISTED_RESPONSE_HEADERS",
    "RawResponseMetadata",
    "RawResponseStore",
    "RequestIdentity",
    "SENSITIVE_REQUEST_HEADERS",
    "StoredResponse",
    "UnsafeRequestError",
    "UnsafeStoragePathError",
    "build_request_identity",
    "sanitized_response_headers",
]
