"""Stable fingerprint ids, quantiles, cluster aggregation and window attribution."""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Iterable

from ..models import Cluster, ClusterWindowEvent, SlowQuery
from ..util.hashing import short_hash

# Default burst window: occurrences of one fingerprint within this many
# seconds of the previous occurrence stay in the same event.
DEFAULT_WINDOW_SECONDS = 300


def fingerprint_id(normalized_sql: str, tokens: Iterable[str]) -> str:
    """Hash normalized text plus the ordered structural token sequence."""
    payload = normalized_sql + "\x1e" + " ".join(tokens)
    return short_hash(payload, 16)


def nearest_rank(values: list[float], quantile: float) -> float:
    """Deterministic nearest-rank quantile (1-based rank, no interpolation)."""
    if not values:
        return 0.0
    if not 0 <= quantile <= 1:
        raise ValueError("quantile must be between 0 and 1")
    ordered = sorted(values)
    rank = max(1, math.ceil(quantile * len(ordered)))
    return ordered[min(rank, len(ordered)) - 1]


def parse_event_time(timestamp: str) -> datetime | None:
    """Parse an ingestion-normalized UTC timestamp for cross-source comparison.

    Both the MySQL slow-log and PostgreSQL CSV parsers store ISO-8601 UTC
    strings (``...Z``) via ``util.timefmt``; naive strings are assumed UTC to
    match that convention. Returns ``None`` when the value is missing or not
    parseable, so callers can keep the occurrence instead of dropping it.
    """
    raw = (timestamp or "").strip()
    if not raw:
        return None
    candidate = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _window_sort_key(query: SlowQuery) -> tuple[int, datetime | None, str, int, str]:
    # Timed occurrences first (flag 0), unparseable timestamps last (flag 1),
    # so an unparseable record can never be silently merged across a gap.
    parsed = parse_event_time(query.timestamp)
    return (
        1 if parsed is None else 0,
        parsed,
        query.source_file,
        query.line_no,
        query.query_id,
    )


def build_window_events(queries: list[SlowQuery], window_seconds: int) -> list[ClusterWindowEvent]:
    """Group one cluster's occurrences into deterministic burst events.

    Occurrences are ordered by timestamp (with stable file/line tie-breakers),
    and a new event starts only when the gap to the previous occurrence is
    strictly greater than ``window_seconds``: an occurrence whose timestamp
    lands exactly on the window endpoint stays in the current event. Records
    with unparseable timestamps each become their own singleton event, which
    never undercounts a burst by merging unknown data into it.
    """
    if window_seconds < 0:
        raise ValueError("window_seconds must be non-negative")
    ordered = sorted(queries, key=_window_sort_key)
    events: list[ClusterWindowEvent] = []
    current: list[SlowQuery] = []
    previous_time: datetime | None = None

    def flush() -> None:
        if not current:
            return
        events.append(
            ClusterWindowEvent(
                event_index=len(events) + 1,
                started_at=current[0].timestamp,
                ended_at=current[-1].timestamp,
                occurrence_count=len(current),
                total_duration_ms=sum(item.duration_ms for item in current),
                max_query_duration_ms=max(item.duration_ms for item in current),
                rows_examined=sum(item.rows_examined for item in current),
                rows_sent=sum(item.rows_sent for item in current),
                query_ids=[item.query_id for item in current],
            )
        )

    for query in ordered:
        parsed = parse_event_time(query.timestamp)
        if current and (parsed is None or previous_time is None
                        or (parsed - previous_time).total_seconds() > window_seconds):
            flush()
            current = []
        current.append(query)
        previous_time = parsed
    flush()
    return events


def _attach_window_metrics(cluster: Cluster, events: list[ClusterWindowEvent],
                           window_seconds: int) -> None:
    cluster.window_seconds = window_seconds
    cluster.window_events = events
    cluster.window_event_count = len(events)
    cluster.window_max_duration_ms = max(
        (event.total_duration_ms for event in events), default=0.0
    )
    cluster.window_max_rows_examined = max(
        (event.rows_examined for event in events), default=0
    )
    cluster.cost.update({
        "window_event_count": cluster.window_event_count,
        "window_max_duration_ms": round(cluster.window_max_duration_ms, 3),
        "window_max_rows_examined": cluster.window_max_rows_examined,
    })


def _cluster_from_queries(queries: list[SlowQuery], overall_total: float) -> Cluster:
    durations = sorted(query.duration_ms for query in queries)
    total_duration = sum(durations)
    count = len(queries)
    rows_examined = sum(query.rows_examined for query in queries)
    rows_sent = sum(query.rows_sent for query in queries)
    lock_ratio = (
        sum(query.lock_time_ms for query in queries) / total_duration
        if total_duration > 0
        else 0.0
    )
    avg_duration = total_duration / count if count else 0.0
    first = queries[0]
    return Cluster(
        fingerprint=first.fingerprint,
        sample_sql=first.sql,
        normalized_sql=first.normalized_sql,
        query_count=count,
        total_duration_ms=total_duration,
        avg_duration_ms=avg_duration,
        min_duration_ms=durations[0] if durations else 0.0,
        max_duration_ms=durations[-1] if durations else 0.0,
        p50_duration_ms=nearest_rank(durations, 0.50),
        p95_duration_ms=nearest_rank(durations, 0.95),
        total_rows_examined=rows_examined,
        total_rows_sent=rows_sent,
        amplification=rows_examined / max(rows_sent, 1),
        lock_ratio=lock_ratio,
        duration_share=total_duration / overall_total if overall_total > 0 else 0.0,
        projected_ms_per_1k_calls=avg_duration * 1000.0,
        query_ids=[query.query_id for query in queries],
    )


def build_clusters(
    queries: Iterable[SlowQuery], window_seconds: int = DEFAULT_WINDOW_SECONDS
) -> list[Cluster]:
    included = [query for query in queries if not query.excluded and query.fingerprint]
    overall_total = sum(query.duration_ms for query in included)
    grouped: dict[str, list[SlowQuery]] = {}
    for query in included:
        grouped.setdefault(query.fingerprint, []).append(query)
    clusters = [
        _cluster_from_queries(group, overall_total) for group in grouped.values()
    ]
    for cluster in clusters:
        cluster.cost = {
            "amplification": round(cluster.amplification, 3),
            "lock_ratio": round(cluster.lock_ratio, 6),
            "avg_duration_ms": round(cluster.avg_duration_ms, 3),
            "p95_duration_ms": round(cluster.p95_duration_ms, 3),
            "projected_ms_per_1k_calls": round(cluster.projected_ms_per_1k_calls, 3),
        }
        _attach_window_metrics(
            cluster, build_window_events(grouped[cluster.fingerprint], window_seconds),
            window_seconds,
        )
    clusters.sort(key=lambda cluster: (-cluster.total_duration_ms, cluster.fingerprint))
    return clusters


def cluster_rows(clusters: Iterable[Cluster]) -> dict[str, dict[str, object]]:
    return {cluster.fingerprint: cluster.as_dict() for cluster in clusters}
