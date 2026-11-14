"""Stable fingerprint ids, quantiles and cluster aggregation."""

from __future__ import annotations

import math
from typing import Iterable

from ..models import Cluster, ParentCluster, SlowQuery
from ..util.hashing import short_hash

STRUCTURAL_NAMESPACE = "structural-equivalence-v1"


def fingerprint_id(normalized_sql: str, tokens: Iterable[str]) -> str:
    """Hash normalized text plus the ordered structural token sequence."""
    payload = normalized_sql + "\x1e" + " ".join(tokens)
    return short_hash(payload, 16)


def structural_fingerprint_id(structural_tokens: Iterable[str]) -> str:
    """Hash the canonical structural token sequence for a parent cluster."""
    payload = STRUCTURAL_NAMESPACE + "\x1e" + " ".join(structural_tokens)
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


def _aggregate(queries: list[SlowQuery], overall_total: float) -> dict[str, float]:
    """Compute cluster statistics directly from member queries.

    Quantiles, amplification, lock ratio and projected cost are all derived
    from the raw members so parent and child levels stay self-consistent
    without summing pre-aggregated child values.
    """
    durations = sorted(query.duration_ms for query in queries)
    total_duration = sum(durations)
    count = len(queries)
    rows_examined = sum(query.rows_examined for query in queries)
    rows_sent = sum(query.rows_sent for query in queries)
    lock_time = sum(query.lock_time_ms for query in queries)
    avg_duration = total_duration / count if count else 0.0
    return {
        "query_count": count,
        "total_duration_ms": total_duration,
        "avg_duration_ms": avg_duration,
        "min_duration_ms": durations[0] if durations else 0.0,
        "max_duration_ms": durations[-1] if durations else 0.0,
        "p50_duration_ms": nearest_rank(durations, 0.50),
        "p95_duration_ms": nearest_rank(durations, 0.95),
        "total_rows_examined": rows_examined,
        "total_rows_sent": rows_sent,
        "amplification": rows_examined / max(rows_sent, 1),
        "lock_ratio": lock_time / total_duration if total_duration > 0 else 0.0,
        "duration_share": total_duration / overall_total if overall_total > 0 else 0.0,
        "projected_ms_per_1k_calls": avg_duration * 1000.0,
    }


def _cost_vector(stats: dict[str, float]) -> dict[str, object]:
    return {
        "amplification": round(stats["amplification"], 3),
        "lock_ratio": round(stats["lock_ratio"], 6),
        "avg_duration_ms": round(stats["avg_duration_ms"], 3),
        "p95_duration_ms": round(stats["p95_duration_ms"], 3),
        "projected_ms_per_1k_calls": round(stats["projected_ms_per_1k_calls"], 3),
    }


def _cluster_from_queries(queries: list[SlowQuery], overall_total: float) -> Cluster:
    first = queries[0]
    stats = _aggregate(queries, overall_total)
    return Cluster(
        fingerprint=first.fingerprint,
        sample_sql=first.sql,
        normalized_sql=first.normalized_sql,
        query_ids=[query.query_id for query in queries],
        structural_fingerprint=first.structural_fingerprint,
        **stats,
    )


def build_clusters(queries: Iterable[SlowQuery]) -> list[Cluster]:
    included = [query for query in queries if not query.excluded and query.fingerprint]
    overall_total = sum(query.duration_ms for query in included)
    grouped: dict[str, list[SlowQuery]] = {}
    for query in included:
        grouped.setdefault(query.fingerprint, []).append(query)
    clusters = [
        _cluster_from_queries(group, overall_total) for group in grouped.values()
    ]
    for cluster in clusters:
        cluster.cost = _cost_vector({
            "amplification": cluster.amplification,
            "lock_ratio": cluster.lock_ratio,
            "avg_duration_ms": cluster.avg_duration_ms,
            "p95_duration_ms": cluster.p95_duration_ms,
            "projected_ms_per_1k_calls": cluster.projected_ms_per_1k_calls,
        })
    clusters.sort(key=lambda cluster: (-cluster.total_duration_ms, cluster.fingerprint))
    return clusters


def _parent_from_queries(queries: list[SlowQuery], overall_total: float) -> ParentCluster:
    first = queries[0]
    stats = _aggregate(queries, overall_total)
    # Deterministic child bookkeeping: fingerprints ordered, counts from members.
    child_counts: dict[str, int] = {}
    for query in queries:
        child_counts[query.fingerprint] = child_counts.get(query.fingerprint, 0) + 1
    child_fingerprints = sorted(child_counts)
    parent = ParentCluster(
        structural_fingerprint=first.structural_fingerprint,
        sample_sql=first.sql,
        structural_sql=first.structural_sql,
        query_ids=sorted(query.query_id for query in queries),
        child_fingerprints=child_fingerprints,
        child_query_counts={fp: child_counts[fp] for fp in child_fingerprints},
        **stats,
    )
    parent.cost = _cost_vector({
        "amplification": parent.amplification,
        "lock_ratio": parent.lock_ratio,
        "avg_duration_ms": parent.avg_duration_ms,
        "p95_duration_ms": parent.p95_duration_ms,
        "projected_ms_per_1k_calls": parent.projected_ms_per_1k_calls,
    })
    return parent


def build_parent_clusters(queries: Iterable[SlowQuery]) -> list[ParentCluster]:
    """Group included queries by structural fingerprint into parent clusters."""
    included = [
        query
        for query in queries
        if not query.excluded and query.fingerprint and query.structural_fingerprint
    ]
    overall_total = sum(query.duration_ms for query in included)
    grouped: dict[str, list[SlowQuery]] = {}
    for query in included:
        grouped.setdefault(query.structural_fingerprint, []).append(query)
    parents = [
        _parent_from_queries(group, overall_total) for group in grouped.values()
    ]
    parents.sort(
        key=lambda parent: (
            -parent.total_duration_ms,
            parent.structural_fingerprint,
        )
    )
    return parents


def cluster_rows(clusters: Iterable[Cluster]) -> dict[str, dict[str, object]]:
    return {cluster.fingerprint: cluster.as_dict() for cluster in clusters}
