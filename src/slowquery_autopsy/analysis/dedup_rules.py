"""Tolerance rules and cross-format event equivalence primitives."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..models import SlowQuery
from ..util.hashing import stable_id
from ..util.timefmt import normalize_timestamp, timestamp_distance_seconds

DEFAULTS: dict[str, Any] = {
    "enabled": True,
    "time_tolerance_seconds": 1.0,
    "duration_tolerance_ms": 2.0,
    "duration_tolerance_ratio": 0.002,
    "lock_tolerance_ms": 1.0,
    "lock_tolerance_ratio": 0.05,
    "rows_tolerance": 0,
    "rows_tolerance_ratio": 0.001,
    "cross_file_only": True,
}

_NUMERIC_KEYS = (
    "time_tolerance_seconds",
    "duration_tolerance_ms",
    "duration_tolerance_ratio",
    "lock_tolerance_ms",
    "lock_tolerance_ratio",
    "rows_tolerance_ratio",
)


@dataclass(frozen=True)
class DedupRules:
    enabled: bool = True
    time_tolerance_seconds: float = 1.0
    duration_tolerance_ms: float = 2.0
    duration_tolerance_ratio: float = 0.002
    lock_tolerance_ms: float = 1.0
    lock_tolerance_ratio: float = 0.05
    rows_tolerance: int = 0
    rows_tolerance_ratio: float = 0.001
    cross_file_only: bool = True

    @classmethod
    def from_mapping(cls, raw: dict[str, Any] | None) -> "DedupRules":
        values = dict(DEFAULTS)
        for key, value in (raw or {}).items():
            if key not in values:
                raise ValueError(f"dedup.{key}: unknown key")
            values[key] = value
        for key in _NUMERIC_KEYS:
            raw_value = values[key]
            if isinstance(raw_value, bool) or not isinstance(raw_value, (int, float)):
                raise ValueError(f"dedup.{key}: expected a non-negative number")
            if float(raw_value) < 0:
                raise ValueError(f"dedup.{key}: expected a non-negative number")
            values[key] = float(raw_value)
        rows_tolerance = values["rows_tolerance"]
        if isinstance(rows_tolerance, bool) or not isinstance(rows_tolerance, int):
            raise ValueError("dedup.rows_tolerance: expected a non-negative integer")
        if rows_tolerance < 0:
            raise ValueError("dedup.rows_tolerance: expected a non-negative integer")
        if not isinstance(values["enabled"], bool):
            raise ValueError("dedup.enabled: expected a boolean")
        if not isinstance(values["cross_file_only"], bool):
            raise ValueError("dedup.cross_file_only: expected a boolean")
        return cls(**values)

    def as_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "time_tolerance_seconds": self.time_tolerance_seconds,
            "duration_tolerance_ms": self.duration_tolerance_ms,
            "duration_tolerance_ratio": self.duration_tolerance_ratio,
            "lock_tolerance_ms": self.lock_tolerance_ms,
            "lock_tolerance_ratio": self.lock_tolerance_ratio,
            "rows_tolerance": self.rows_tolerance,
            "rows_tolerance_ratio": self.rows_tolerance_ratio,
            "cross_file_only": self.cross_file_only,
        }


def normalize_event_time(value: str) -> str:
    """Normalize ``...Z`` and naive timestamps to the same UTC ISO representation."""
    return normalize_timestamp(value)


def event_signature(query: SlowQuery) -> tuple[str, tuple[str, ...]] | None:
    """Return the SQL part of the event key, or ``None`` when it is unavailable."""
    if not query.normalized_sql or not query.tokens:
        return None
    return query.normalized_sql, tuple(query.tokens)


def event_key(query: SlowQuery) -> str:
    """Deterministic *zero-tolerance* identity key (normalized time + SQL + tokens).

    Tolerance-window matching is performed by :func:`events_equivalent`; this
    key is the coarse bucket used in the audit trail and by callers that only
    need an exact match.
    """
    return stable_id(
        "evk",
        normalize_event_time(query.timestamp),
        query.normalized_sql,
        list(query.tokens),
        length=32,
    )


def _within(value: float, reference: float, absolute: float, ratio: float) -> bool:
    scale = max(abs(value), abs(reference))
    return abs(value - reference) <= absolute + ratio * scale


def _signature_matches(left: SlowQuery, right: SlowQuery) -> bool:
    if left.normalized_sql != right.normalized_sql:
        return False
    if tuple(left.tokens) != tuple(right.tokens):
        return False
    # ``fingerprint`` is derived from the two fields above; when both sides
    # carry one they must still agree (defensive against stale fixtures).
    if left.fingerprint and right.fingerprint and left.fingerprint != right.fingerprint:
        return False
    return True


def events_equivalent(left: SlowQuery, right: SlowQuery, rules: DedupRules | None = None) -> bool:
    """True when two rows may describe the same physical execution."""
    rules = rules or DedupRules()
    if left is right:
        return False
    if not _signature_matches(left, right):
        return False
    if rules.cross_file_only and left.source_file == right.source_file:
        return False
    distance = timestamp_distance_seconds(left.timestamp, right.timestamp)
    if distance is None or distance > rules.time_tolerance_seconds:
        return False
    if not _within(
        left.duration_ms, right.duration_ms,
        rules.duration_tolerance_ms, rules.duration_tolerance_ratio,
    ):
        return False
    if not _within(
        left.lock_time_ms, right.lock_time_ms,
        rules.lock_tolerance_ms, rules.lock_tolerance_ratio,
    ):
        return False
    if not _within(
        float(left.rows_sent), float(right.rows_sent),
        float(rules.rows_tolerance), rules.rows_tolerance_ratio,
    ):
        return False
    if not _within(
        float(left.rows_examined), float(right.rows_examined),
        float(rules.rows_tolerance), rules.rows_tolerance_ratio,
    ):
        return False
    return True
