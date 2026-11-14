"""Stable fingerprint ids, quantiles and cluster aggregation."""

from __future__ import annotations

import math
from typing import Iterable

from ..models import Cluster, SlowQuery
from ..util.hashing import short_hash


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


def build_clusters(queries: Iterable[SlowQuery]) -> list[Cluster]:
    """Aggregate by fingerprint over *events*, never over raw log rows.

    Rows folded by :mod:`slowquery_autopsy.analysis.dedup` carry
    ``duplicate_of`` and are skipped here so ``query_count`` matches
    ``summary.counts.analyzed_queries``.  Excluded metadata statements are
    skipped as before.
    """
    included = [
        query for query in queries
        if not query.excluded and not query.duplicate_of and query.fingerprint
    ]
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
    clusters.sort(key=lambda cluster: (-cluster.total_duration_ms, cluster.fingerprint))
    return clusters


def cluster_rows(clusters: Iterable[Cluster]) -> dict[str, dict[str, object]]:
    return {cluster.fingerprint: cluster.as_dict() for cluster in clusters}
