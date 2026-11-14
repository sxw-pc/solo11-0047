"""Explainable cost vectors and threshold/relative-basis cost attribution.

Absolute cost rules compare one cluster metric against a fixed threshold.
Relative cost rules additionally place the cluster inside the distribution of
*the other clusters in the same batch*:

* ``basis: batch_share``  — the cluster's metric sum divided by the batch sum
  (for ``total_duration_ms`` this is the cluster's share of analysed duration);
* ``basis: batch_median`` — the cluster's metric divided by the batch median.

The batch distribution is computed once per rule from every cluster in the
batch, so evaluation is independent of the order in which clusters are
iterated.  A relative rule needs at least two clusters: a lone cluster is the
whole batch, and calling it "the largest" would be meaningless, so relative
rules simply produce no candidate for a single-cluster batch.
"""

from __future__ import annotations

import math
import statistics
from typing import Any, Iterable

from ..models import Cluster, SlowQuery

COMPARATORS = {
    "gt": lambda actual, threshold: actual > threshold,
    "gte": lambda actual, threshold: actual >= threshold,
    "lt": lambda actual, threshold: actual < threshold,
    "lte": lambda actual, threshold: actual <= threshold,
    "eq": lambda actual, threshold: actual == threshold,
}

#: Absolute per-cluster metrics usable as ``metric`` in a cost rule.
METRIC_GETTERS = {
    "amplification": lambda cluster: cluster.amplification,
    "lock_ratio": lambda cluster: cluster.lock_ratio,
    "avg_duration_ms": lambda cluster: cluster.avg_duration_ms,
    "p95_duration_ms": lambda cluster: cluster.p95_duration_ms,
    "total_duration_ms": lambda cluster: cluster.total_duration_ms,
    "projected_ms_per_1k_calls": lambda cluster: cluster.projected_ms_per_1k_calls,
    "query_count": lambda cluster: float(cluster.query_count),
    "total_rows_examined": lambda cluster: float(cluster.total_rows_examined),
    "total_rows_sent": lambda cluster: float(cluster.total_rows_sent),
    "duration_share": lambda cluster: cluster.duration_share,
}
ABSOLUTE_METRICS = frozenset(METRIC_GETTERS)

#: Metrics that are additive across clusters and therefore meaningful for a
#: ``batch_share`` comparison.  Ratios and averages are deliberately excluded.
SHARE_METRICS = frozenset({
    "total_duration_ms",
    "query_count",
    "total_rows_examined",
    "total_rows_sent",
})

RELATIVE_BASES = frozenset({"batch_share", "batch_median"})
COST_BASES = frozenset({"absolute"}) | RELATIVE_BASES

#: Relative rules describe "unusually large" clusters only; ``lt``/``lte``/``eq``
#: on a distributional measure is not a slow-query risk assertion.
RELATIVE_OPERATORS = frozenset({"gt", "gte"})


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
    getter = METRIC_GETTERS.get(metric)
    if getter is None:
        raise ValueError(f"unsupported cost metric: {metric!r}")
    return float(getter(cluster))


def _format(template: str, values: dict[str, Any]) -> str:
    try:
        return str(template).format(**values)
    except (KeyError, ValueError, TypeError):
        return str(template)


def validate_cost_rule(rule: dict[str, Any], where: str) -> None:
    """Reject nonsensical metric/basis/operator/threshold combinations.

    Called while loading configuration so an ill-defined relative rule fails
    at startup rather than in the middle of a batch.
    """
    metric = rule.get("metric")
    if metric not in ABSOLUTE_METRICS:
        raise ValueError(f"{where}.metric: unsupported cost metric {metric!r}")
    operator = rule.get("operator")
    if operator not in COMPARATORS:
        raise ValueError(f"{where}.operator: unsupported {operator!r}")
    if "basis" in rule:
        basis = rule["basis"]
        if basis not in COST_BASES:
            raise ValueError(f"{where}.basis: unsupported {basis!r}")
    else:
        basis = "absolute"
    threshold = rule.get("threshold")
    try:
        numeric_threshold = float(threshold)
    except (TypeError, ValueError):
        raise ValueError(f"{where}.threshold: expected a number, got {threshold!r}") from None
    if basis == "absolute":
        return

    # Relative rules only make sense for upwards comparisons of an "unusually
    # large" cluster.  ``lt``/``lte``/``eq`` would flag typical or small
    # clusters, which is not a risk signal.
    if operator not in RELATIVE_OPERATORS:
        raise ValueError(
            f"{where}.operator: relative basis {basis!r} requires gt or gte, got {operator!r}"
        )
    if basis == "batch_share":
        if metric not in SHARE_METRICS:
            raise ValueError(
                f"{where}.metric: basis 'batch_share' requires an additive metric "
                f"({', '.join(sorted(SHARE_METRICS))}), got {metric!r}"
            )
        if not 0 < numeric_threshold <= 1:
            raise ValueError(
                f"{where}.threshold: basis 'batch_share' expects a fraction in (0, 1], "
                f"got {threshold!r}"
            )
    else:  # batch_median
        if numeric_threshold <= 1:
            raise ValueError(
                f"{where}.threshold: basis 'batch_median' expects a multiple greater than 1, "
                f"got {threshold!r}"
            )


def _batch_context(
    clusters: list[Cluster], metric: str, basis: str
) -> tuple[float, int] | None:
    """Return ``(baseline, cluster_count)`` for a relative rule.

    ``None`` means the relative comparison is not meaningful (single-cluster
    batch or a non-positive baseline); the rule then yields no candidates.
    """
    if len(clusters) < 2:
        return None
    values = [cluster_metric(cluster, metric) for cluster in clusters]
    if basis == "batch_share":
        # fsum keeps the batch total independent of the iteration order.
        baseline = math.fsum(values)
    else:
        baseline = float(statistics.median(values))
    if baseline <= 0:
        return None
    return baseline, len(clusters)


def evaluate_cost(clusters: Iterable[Cluster], rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # Materialise once: callers may pass a generator, and every rule needs to
    # see the full batch to compute its distribution.
    cluster_list = list(clusters)
    candidates: list[dict[str, Any]] = []
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        # Reuse the loader's validation as the single source of truth so a
        # direct call cannot drift from configuration-time behaviour.
        validate_cost_rule(rule, f"rule {rule.get('id')}")
        basis = str(rule.get("basis", "absolute"))
        comparator = COMPARATORS[rule["operator"]]
        threshold = float(rule["threshold"])
        min_count = int(rule.get("min_count", 0))
        metric = rule["metric"]
        context = (
            _batch_context(cluster_list, metric, basis) if basis != "absolute" else None
        )
        if basis != "absolute" and context is None:
            # A single-cluster batch has no peer distribution: skip rather than
            # flag the only cluster as "100% of the batch" or "1.0x the median".
            continue
        baseline = context[0] if context else 0.0
        batch_clusters = context[1] if context else len(cluster_list)
        for cluster in cluster_list:
            if cluster.query_count < min_count:
                continue
            absolute = cluster_metric(cluster, metric)
            if basis == "absolute":
                if not comparator(absolute, threshold):
                    continue
                values = {
                    "actual": round(absolute, 6),
                    "threshold": rule["threshold"],
                    "metric": metric,
                    "query_count": cluster.query_count,
                    "cluster_id": cluster.fingerprint,
                    "fingerprint": cluster.fingerprint,
                }
                default_description = "{metric} = {actual} (threshold {threshold})"
            else:
                relative = absolute / baseline
                if not comparator(relative, threshold):
                    continue
                values = {
                    "actual": round(absolute, 6),
                    "threshold": rule["threshold"],
                    "metric": metric,
                    "basis": basis,
                    "relative_value": round(relative, 6),
                    "baseline_value": round(baseline, 6),
                    "batch_clusters": batch_clusters,
                    "query_count": cluster.query_count,
                    "cluster_id": cluster.fingerprint,
                    "fingerprint": cluster.fingerprint,
                }
                if basis == "batch_share":
                    values["relative_percent"] = round(relative * 100.0, 4)
                default_description = (
                    "{metric} = {actual}；批内相对值 {relative_value}x（阈值 {threshold}x）"
                )
            candidates.append({
                "category": "cost",
                "rule_id": rule["id"],
                "severity": rule["severity"],
                "title": rule["title"],
                "description": _format(
                    rule.get("description", default_description),
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
