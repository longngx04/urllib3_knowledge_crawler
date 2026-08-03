"""Deterministic identifiers for normalized records."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Set
from datetime import date, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel

_RECORD_TYPE_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")


def _canonicalize(value: object) -> object:
    """Convert supported identity values to a deterministic JSON-compatible shape."""
    if isinstance(value, BaseModel):
        return _canonicalize(value.model_dump(mode="json"))
    if isinstance(value, Enum):
        return _canonicalize(value.value)
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("identity timestamps must include a timezone")
        utc_suffix = value.isoformat().replace("+00:00", "Z")
        return utc_suffix
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Mapping):
        canonical: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("identity mapping keys must be strings")
            canonical[key] = _canonicalize(item)
        return canonical
    if isinstance(value, Set):
        items = [_canonicalize(item) for item in value]
        return sorted(items, key=_canonical_json)
    if isinstance(value, (list, tuple)):
        return [_canonicalize(item) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("identity values cannot contain non-finite numbers")
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"unsupported identity value: {type(value).__name__}")


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def stable_record_id(record_type: str, identity: Mapping[str, Any]) -> str:
    """Return a stable ``<record-type>:<sha256>`` identifier.

    Only explicit identity fields should be passed. Volatile metadata such as retrieval
    times and confidence scores must not be included unless they truly define identity.
    """
    if not _RECORD_TYPE_PATTERN.fullmatch(record_type):
        raise ValueError("record_type must use lowercase snake_case")

    canonical_identity = _canonicalize(identity)
    payload = _canonical_json(canonical_identity).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    return f"{record_type}:{digest}"


__all__ = ["stable_record_id"]
