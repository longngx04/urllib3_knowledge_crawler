"""Load ignored local ``.env`` files into process environment variables.

The crawler reads credentials such as ``GITHUB_TOKEN`` via ``os.getenv``. Operators
commonly copy ``.env.example`` to ``.env``; without this helper those values would be
invisible unless the shell exported them first.
"""

from __future__ import annotations

import os
from pathlib import Path

_MAX_ENV_FILE_BYTES = 64_000
_ALLOWED_KEYS = frozenset({"GITHUB_TOKEN", "NVD_API_KEY", "CRAWLER_OFFLINE"})


def _parse_assignment(line: str) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if stripped.startswith("export "):
        stripped = stripped[len("export ") :].strip()
    if "=" not in stripped:
        return None
    key, raw_value = stripped.split("=", maxsplit=1)
    key = key.strip()
    if not key or not key.replace("_", "").isalnum() or key[0].isdigit():
        return None
    value = raw_value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1]
    return key, value


def load_env_file(path: Path, *, overwrite: bool = False) -> tuple[str, ...]:
    """Load ``KEY=VALUE`` assignments from ``path`` into ``os.environ``.

    Returns the names of variables that were newly applied. Existing environment
    variables are preserved unless ``overwrite`` is true. Unknown keys outside the
    allowlist are ignored so unexpected local secrets are not injected into the process.
    Values are never logged or returned.
    """

    if not path.is_file() or path.is_symlink():
        return ()
    size = path.stat().st_size
    if size > _MAX_ENV_FILE_BYTES:
        raise ValueError(f"env file exceeds {_MAX_ENV_FILE_BYTES} bytes: {path}")

    applied: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        parsed = _parse_assignment(line)
        if parsed is None:
            continue
        key, value = parsed
        if key not in _ALLOWED_KEYS:
            continue
        if not overwrite and key in os.environ:
            continue
        os.environ[key] = value
        applied.append(key)
    return tuple(applied)


def load_default_env_files(*, start: Path | None = None) -> tuple[str, ...]:
    """Load the nearest ``.env`` from ``start`` (default: cwd) or its parents."""

    current = (start or Path.cwd()).resolve()
    candidates = [current / ".env", *([parent / ".env" for parent in current.parents])]
    # Cap walk depth to repository-scale trees.
    for candidate in candidates[:8]:
        if candidate.is_file() and not candidate.is_symlink():
            return load_env_file(candidate)
    return ()


__all__ = ["load_default_env_files", "load_env_file"]
