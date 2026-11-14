"""Cross-file / cross-format slow-query event grouping.

A single physical execution can be exported by several collectors: for example
with ``Rows_examined`` and ``Query_time`` in 2 decimals from a PostgreSQL CSV export
next to a normalized MySQL slow log entry for the *same* execution where
``Query_time`` has 6 decimals.  :mod:`dedup_rules` defines the tolerance windows
and the pairwise equivalence test; this module groups equivalent rows, keeps one
representative per event and attaches the other source files/lines to it.

Two safeguards keep the tolerance window from collapsing genuinely distinct
executions:

1. ``cross_file_only`` (default) requires a different ``source_file``; two
   identical rows in one log are two executions and must stay two events.
2. An event group absorbs at most one row per source file.

Duplicates are never used as anchors for further matching (the grouping is a
star around the representative, not a transitive closure), which prevents a
chain of barely-similar rows from snowballing into one oversized event.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from ..models import SlowQuery
from ..util.hashing import canonical_json, stable_id
from ..util.timefmt import timestamp_distance_seconds
from .dedup_rules import (
    DEFAULTS,
    DedupRules,
    event_key,
    event_signature,
    events_equivalent,
    normalize_event_time,
)

__all__ = [
    "DEFAULTS",
    "DedupGroup",
    "DedupResult",
    "DedupRules",
    "dedup_fingerprint",
    "deduplicate_queries",
    "event_key",
    "event_signature",
    "events_equivalent",
    "normalize_event_time",
]


def _distance(left: SlowQuery, right: SlowQuery) -> tuple[float, float, float, float]:
    distance = timestamp_distance_seconds(left.timestamp, right.timestamp)
    time_delta = float("inf") if distance is None else distance
    return (
        time_delta,
        abs(left.duration_ms - right.duration_ms),
        abs(left.lock_time_ms - right.lock_time_ms),
        float(abs(left.rows_examined - right.rows_examined) + abs(left.rows_sent - right.rows_sent)),
    )


def _source_payload(query: SlowQuery) -> dict[str, Any]:
    return {
        "source_file": query.source_file,
        "line_no": query.line_no,
        "query_id": query.query_id,
        "log_format": query.log_format,
        "timestamp": normalize_event_time(query.timestamp),
        "duration_ms": round(query.duration_ms, 3),
        "lock_time_ms": round(query.lock_time_ms, 3),
        "rows_sent": query.rows_sent,
        "rows_examined": query.rows_examined,
    }


@dataclass
class DedupGroup:
    representative: SlowQuery
    duplicates: list[SlowQuery] = field(default_factory=list)
    event_id: str = ""

    @property
    def members(self) -> list[SlowQuery]:
        return [self.representative, *self.duplicates]

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "representative": _source_payload(self.representative),
            "redundant_sources": [_source_payload(query) for query in self.duplicates],
        }


@dataclass
class DedupResult:
    groups: list[DedupGroup] = field(default_factory=list)
    rules: DedupRules = field(default_factory=DedupRules)

    @property
    def event_count(self) -> int:
        return len(self.groups)

    @property
    def duplicate_row_count(self) -> int:
        return sum(len(group.duplicates) for group in self.groups)

    @property
    def folded_groups(self) -> list[DedupGroup]:
        return [group for group in self.groups if group.duplicates]

    def as_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.rules.enabled,
            "rules": self.rules.as_dict(),
            "events": self.event_count,
            "duplicate_rows": self.duplicate_row_count,
            "groups": [group.as_dict() for group in self.folded_groups],
        }


def _sort_key(query: SlowQuery) -> tuple[Any, ...]:
    time_key = normalize_event_time(query.timestamp)
    return (
        query.normalized_sql,
        tuple(query.tokens),
        time_key or "￿",
        query.duration_ms,
        query.source_file,
        query.line_no,
        query.query_id,
    )


def _reset(query: SlowQuery) -> None:
    query.event_id = ""
    query.duplicate_of = ""
    query.redundant_sources = []


def deduplicate_queries(
    queries: Iterable[SlowQuery], rules: DedupRules | None = None
) -> DedupResult:
    """Group equivalent rows and annotate them in place.

    The representative keeps its ``cluster_id`` and receives a
    ``redundant_sources`` list.  Folded rows receive ``duplicate_of`` and lose
    their ``cluster_id`` so downstream aggregation counts the event once.
    """
    rules = rules or DedupRules()
    items = list(queries)
    for query in items:
        _reset(query)
    if not rules.enabled:
        for query in items:
            query.event_id = query.query_id
        return DedupResult(groups=[], rules=rules)

    candidates = [query for query in items if not query.excluded and event_signature(query)]
    candidates.sort(key=_sort_key)

    groups: list[DedupGroup] = []
    by_signature: dict[tuple[str, tuple[str, ...]], list[DedupGroup]] = {}
    for query in candidates:
        signature = event_signature(query)
        assert signature is not None
        best: DedupGroup | None = None
        best_score: tuple[Any, ...] | None = None
        for group in by_signature.get(signature, []):
            representative = group.representative
            if not events_equivalent(representative, query, rules):
                continue
            if any(member.source_file == query.source_file for member in group.members):
                # One file contributes at most one observation of an event.
                continue
            score = (*_distance(representative, query), _sort_key(representative))
            if best_score is None or score < best_score:
                best, best_score = group, score
        if best is None:
            group = DedupGroup(representative=query)
            groups.append(group)
            by_signature.setdefault(signature, []).append(group)
            continue
        best.duplicates.append(query)
        query.duplicate_of = best.representative.query_id
        query.cluster_id = ""

    for group in groups:
        ordered = sorted(group.duplicates, key=lambda item: (item.source_file, item.line_no))
        group.duplicates = ordered
        group.event_id = stable_id(
            "ev",
            group.representative.query_id,
            group.representative.normalized_sql,
            list(group.representative.tokens),
            normalize_event_time(group.representative.timestamp),
        )
        group.representative.event_id = group.event_id
        group.representative.redundant_sources = [_source_payload(query) for query in ordered]
        for query in ordered:
            query.event_id = group.event_id

    groups.sort(key=lambda group: _sort_key(group.representative))
    return DedupResult(groups=groups, rules=rules)


def dedup_fingerprint(result: DedupResult) -> str:
    """Stable digest of an event view, useful in tests and audit metadata."""
    payload: Sequence[dict[str, Any]] = [group.as_dict() for group in result.folded_groups]
    return stable_id("dd", canonical_json(payload), length=16)
