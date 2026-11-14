"""Explainable cost vectors and threshold-based cost attribution."""

from __future__ import annotations

from typing import Any, Iterable

from ..models import Cluster, SlowQuery

COMPARATORS = {
    "gt": lambda actual, threshold: actual > threshold,
    "gte": lambda actual, threshold: actual >= threshold,
    "lt": lambda actual, threshold: actual < threshold,
    "lte": lambda actual, threshold: actual <= threshold,
    "eq": lambda actual, threshold: actual == threshold,
}


def query_cost_vector(query: SlowQuery) -> dict[str, float]:
    amplification = query.rows_examined / max(query.rows_sent, 1)
    lock_ratio = query.lock_time_ms / query.duration_ms if query.duration_ms > 0 else 0.0
    return {
        "duration_ms": round(query.duration_ms, 3),
        "rows_examined": query.rows_examined,
        "rows_sent": query.rows_sent,
        "amplification": round(amplification, 3),
        "lock_ratio": round(lock_ratio, 6),
        "projected_ms_per_1k_calls": round(query.duration_ms * 1000.0, 3),
    }


def attach_query_costs(queries: Iterable[SlowQuery]) -> None:
    for query in queries:
        query.cost = query_cost_vector(query)


def cluster_metric(cluster: Cluster, metric: str) -> float:
    metrics = {
        "amplification": cluster.amplification,
        "lock_ratio": cluster.lock_ratio,
        "avg_duration_ms": cluster.avg_duration_ms,
        "p95_duration_ms": cluster.p95_duration_ms,
        "total_duration_ms": cluster.total_duration_ms,
        "projected_ms_per_1k_calls": cluster.projected_ms_per_1k_calls,
        "query_count": float(cluster.query_count),
        # Window-level burst attribution (see analysis.fingerprint).
        "window_event_count": float(cluster.window_event_count),
        "window_max_duration_ms": cluster.window_max_duration_ms,
        "window_max_rows_examined": float(cluster.window_max_rows_examined),
    }
    if metric not in metrics:
        raise ValueError(f"unsupported cost metric: {metric!r}")
    return metrics[metric]


def _format(template: str, values: dict[str, Any]) -> str:
    try:
        return str(template).format(**values)
    except (KeyError, ValueError, TypeError):
        return str(template)


def evaluate_cost(clusters: Iterable[Cluster], rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        comparator = COMPARATORS[rule["operator"]]
        threshold = float(rule["threshold"])
        min_count = int(rule.get("min_count", 0))
        for cluster in clusters:
            if cluster.query_count < min_count:
                continue
            actual = cluster_metric(cluster, rule["metric"])
            if not comparator(actual, threshold):
                continue
            values = {
                "actual": round(actual, 6),
                "threshold": rule["threshold"],
                "metric": rule["metric"],
                "query_count": cluster.query_count,
                "cluster_id": cluster.fingerprint,
                "fingerprint": cluster.fingerprint,
            }
            candidates.append({
                "category": "cost",
                "rule_id": rule["id"],
                "severity": rule["severity"],
                "title": rule["title"],
                "description": _format(
                    rule.get("description", "{metric} = {actual} (threshold {threshold})"),
                    values,
                ),
                "recommendation": _format(rule.get("recommendation", "Review this query pattern."), values),
                "cluster_id": cluster.fingerprint,
                "query_id": "",
                "plan_file": "",
                "node_path": "",
                "evidence": values,
            })
    candidates.sort(key=lambda item: (item["rule_id"], item["cluster_id"]))
    return candidates
