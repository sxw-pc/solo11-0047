from __future__ import annotations

import pytest

from slowquery_autopsy.analysis.cost import (
    attach_query_costs,
    evaluate_cost,
    query_cost_vector,
    validate_cost_rule,
)
from slowquery_autopsy.analysis.fingerprint import build_clusters
from slowquery_autopsy.models import SlowQuery


def _query(duration: float, lock: float, examined: int, sent: int, fp: str = "aaaaaaaaaaaaaaaa"):
    return SlowQuery(
        source_file="synthetic.log", line_no=1, timestamp="2026-01-01T00:00:00Z",
        duration_ms=duration, lock_time_ms=lock, rows_sent=sent, rows_examined=examined,
        user="u", client="c", database="d", sql="SELECT 1;", log_format="mysql_slow",
        query_id=f"q-{duration}-{examined}", fingerprint=fp, cluster_id=fp,
        normalized_sql="SELECT ?;", tokens=["SELECT", "?"],
    )


def test_query_cost_vector_and_cluster_metrics():
    query = _query(2000.0, 500.0, 10000, 20)
    vector = query_cost_vector(query)
    assert vector == {
        "duration_ms": 2000.0, "rows_examined": 10000, "rows_sent": 20,
        "amplification": 500.0, "lock_ratio": 0.25,
        "projected_ms_per_1k_calls": 2000000.0,
    }
    attach_query_costs([query])
    assert query.cost["amplification"] == 500.0
    cluster = build_clusters([
        _query(1000, 100, 10000, 20), _query(3000, 300, 10000, 20)
    ])[0]
    assert cluster.query_count == 2
    assert cluster.avg_duration_ms == 2000.0
    assert cluster.p50_duration_ms == 1000.0
    assert cluster.p95_duration_ms == 3000.0
    assert cluster.amplification == 500.0
    assert cluster.lock_ratio == 0.1
    assert cluster.duration_share == 1.0


def test_threshold_rules_and_min_count_boundary():
    cluster = build_clusters([
        _query(1000, 0, 10000, 20) for _ in range(4)
    ])[0]
    rules = [{
        "id": "T-AMP", "title": "amp", "metric": "amplification",
        "operator": "gt", "threshold": 100, "min_count": 4, "severity": "high",
        "description": "{actual} > {threshold}", "recommendation": "inspect",
    }]
    candidates = evaluate_cost([cluster], rules)
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate["cluster_id"] == cluster.fingerprint
    assert candidate["evidence"]["actual"] == 500.0
    assert candidate["evidence"]["threshold"] == 100
    assert candidate["evidence"]["query_count"] == 4
    rules[0]["min_count"] = 5
    assert evaluate_cost([cluster], rules) == []


def test_operator_boundary_and_disabled_rule():
    cluster = build_clusters([_query(1000, 0, 100, 1)])[0]
    rule = {
        "id": "T-EQ", "title": "eq", "metric": "amplification",
        "operator": "gte", "threshold": 100, "min_count": 1, "severity": "medium",
    }
    assert len(evaluate_cost([cluster], [rule])) == 1
    rule["enabled"] = False
    assert evaluate_cost([cluster], [rule]) == []


def test_candidates_are_sorted_deterministically():
    first = build_clusters([_query(1000, 0, 1000, 1, "bbbbbbbbbbbbbbbb")])[0]
    second = build_clusters([_query(1000, 0, 1000, 1, "aaaaaaaaaaaaaaaa")])[0]
    rule = {
        "id": "T-ALL", "title": "all", "metric": "query_count",
        "operator": "gte", "threshold": 1, "min_count": 1, "severity": "low",
    }
    candidates = evaluate_cost([first, second], [rule])
    assert [item["cluster_id"] for item in candidates] == [
        "aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"
    ]


# --- relative / batch-distribution rules -----------------------------------

def _clusters(*specs: tuple[str, float]):
    """Build one cluster per (fingerprint, duration) pair, one query each."""
    return build_clusters([_query(duration, 0, 100, 10, fp) for fp, duration in specs])


SHARE_RULE = {
    "id": "T-SHARE", "title": "share", "metric": "total_duration_ms",
    "operator": "gte", "threshold": 0.30, "min_count": 1, "severity": "medium",
    "basis": "batch_share",
    "description": "{actual}ms / batch = {relative_percent}% (threshold {threshold})",
    "recommendation": "inspect",
}
MEDIAN_RULE = {
    "id": "T-MEDIAN", "title": "median", "metric": "total_duration_ms",
    "operator": "gte", "threshold": 2.0, "min_count": 1, "severity": "medium",
    "basis": "batch_median",
    "description": "{actual}ms vs median {baseline_value}ms = {relative_value}x",
    "recommendation": "inspect",
}


def test_batch_share_evidence_holds_absolute_and_relative_values():
    # 500 + 300 + 200 = 1000 -> shares 50% / 30% / 20%.
    clusters = _clusters(("a" * 16, 500), ("b" * 16, 300), ("c" * 16, 200))
    candidates = evaluate_cost(clusters, [SHARE_RULE])
    assert [item["cluster_id"] for item in candidates] == ["a" * 16, "b" * 16]
    top = candidates[0]["evidence"]
    assert top["actual"] == 500.0                 # absolute value
    assert top["baseline_value"] == 1000.0        # batch total
    assert top["relative_value"] == 0.5           # relative value
    assert top["relative_percent"] == 50.0
    assert top["batch_clusters"] == 3
    assert top["basis"] == "batch_share"
    assert candidates[1]["evidence"]["relative_value"] == 0.3
    # Description exposes both the absolute and the relative figure.
    assert "500.0ms" in candidates[0]["description"]
    assert "50.0%" in candidates[0]["description"]


def test_batch_median_uses_median_of_all_clusters_and_reports_baseline():
    clusters = _clusters(("a" * 16, 1000), ("b" * 16, 200), ("c" * 16, 300))
    candidates = evaluate_cost(clusters, [MEDIAN_RULE])
    assert len(candidates) == 1
    evidence = candidates[0]["evidence"]
    assert evidence["cluster_id"] == "a" * 16
    assert evidence["actual"] == 1000.0
    assert evidence["baseline_value"] == 300.0    # median of [200, 300, 1000]
    assert evidence["relative_value"] == pytest.approx(1000 / 300, rel=0, abs=1e-6)
    assert "median 300.0ms" in candidates[0]["description"]


def test_relative_results_are_independent_of_cluster_iteration_order():
    specs = (("a" * 16, 500), ("b" * 16, 300), ("c" * 16, 200), ("d" * 16, 100))
    forward = _clusters(*specs)          # build_clusters returns -total_duration order
    backward = list(reversed(forward))   # deliberately pass clusters in another order
    shuffled = [forward[2], forward[0], forward[3], forward[1]]
    rules = [SHARE_RULE, MEDIAN_RULE]
    baseline = evaluate_cost(forward, rules)
    assert evaluate_cost(backward, rules) == baseline
    assert evaluate_cost(shuffled, rules) == baseline
    # A generator is also accepted: the batch distribution is materialised once.
    assert evaluate_cost((c for c in shuffled), rules) == baseline


def test_single_cluster_batch_does_not_trigger_relative_rules():
    cluster = _clusters(("a" * 16, 1000))[0]
    assert evaluate_cost([cluster], [SHARE_RULE, MEDIAN_RULE]) == []
    # Absolute rules still apply to a one-cluster batch.
    absolute = dict(SHARE_RULE, id="T-ABS", basis="absolute", metric="total_duration_ms",
                    operator="gt", threshold=500)
    assert len(evaluate_cost([cluster], [absolute])) == 1


def test_zero_baseline_batch_is_skipped_instead_of_dividing_by_zero():
    zero = _clusters(("a" * 16, 0), ("b" * 16, 0))
    assert evaluate_cost(zero, [SHARE_RULE, MEDIAN_RULE]) == []


@pytest.mark.parametrize(
    "rule",
    [
        dict(SHARE_RULE, metric="avg_duration_ms"),      # non-additive for a share
        dict(SHARE_RULE, threshold=1.5),                 # share cannot exceed 1
        dict(SHARE_RULE, threshold=0),
        dict(SHARE_RULE, operator="lt"),                 # relative rules go upwards
        dict(MEDIAN_RULE, operator="eq"),
        dict(MEDIAN_RULE, threshold=1.0),                # ratio of the median itself
        dict(MEDIAN_RULE, threshold=0.5),
        dict(SHARE_RULE, basis="batch_tukey"),           # unknown basis
        dict(SHARE_RULE, metric="not_a_metric"),
        dict(SHARE_RULE, threshold="not-a-number"),
    ],
)
def test_validate_cost_rule_rejects_meaningless_relative_rules(rule):
    with pytest.raises(ValueError):
        validate_cost_rule(rule, "cost.rules[0]")


def test_validate_cost_rule_accepts_absolute_and_relative_forms():
    validate_cost_rule(
        {"id": "A", "metric": "amplification", "operator": "gt",
         "threshold": 100, "severity": "high", "title": "t"},
        "cost.rules[0]",
    )
    validate_cost_rule(SHARE_RULE, "cost.rules[0]")
    validate_cost_rule(MEDIAN_RULE, "cost.rules[0]")
    # An explicit absolute basis must also be accepted.
    validate_cost_rule({**SHARE_RULE, "basis": "absolute", "threshold": 1000},
                       "cost.rules[0]")


def test_evaluate_cost_rejects_unknown_basis_without_config_validation():
    cluster = _clusters(("a" * 16, 1000), ("b" * 16, 500))[0]
    with pytest.raises(ValueError):
        evaluate_cost([cluster], [dict(SHARE_RULE, basis="batch_nonsense")])
