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
    return sha256_bytes(path.read_bytes())


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


def file_parse_cache_key(
    display_path: str,
    file_sha256: str,
    log_format: str,
    format_config: dict[str, Any],
    encoding: str,
    parser_version: int,
    fingerprint_rules_sha256: str,
) -> str:
    """Bind every input that can change a file's derived parse result.

    A hit is only valid when *all* of the following match: the file's identity
    (display path), its exact byte content (sha256), the declared log format and
    its full format configuration, the configured encoding, the parser code
    version and the fingerprint-rule set. Any configuration change therefore
    produces a fresh key instead of replaying stale derived data.
    """
    payload = {
        "display_path": display_path,
        "sha256": file_sha256,
        "log_format": log_format,
        "format_config": format_config,
        "encoding": encoding,
        "parser_version": parser_version,
        "fingerprint_rules_sha256": fingerprint_rules_sha256,
    }
    return stable_id("fpc", payload, length=32)
