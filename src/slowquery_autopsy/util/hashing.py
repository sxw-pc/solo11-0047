"""Deterministic hashing helpers used across the pipeline."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def short_hash(text: str, length: int = 16) -> str:
    if not 8 <= length <= 64:
        raise ValueError("hash length must be between 8 and 64")
    return sha256_text(text)[:length]


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def stable_id(prefix: str, *parts: Any, length: int = 16) -> str:
    digest = short_hash("|".join(canonical_json(part) for part in parts), length)
    return f"{prefix}-{digest}" if prefix else digest


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def combined_file_hash(items: list[tuple[str, str, Path]]) -> str:
    """Hash stable display paths, formats and bytes without mtimes or absolutes."""
    digest = hashlib.sha256()
    for relative_path, log_format, path in items:
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(log_format.encode("utf-8"))
        digest.update(b"\0")
        if path.is_file():
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(65536), b""):
                    digest.update(chunk)
        digest.update(b"\0")
    return digest.hexdigest()
