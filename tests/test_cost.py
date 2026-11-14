from __future__ import annotations

from slowquery_autopsy.analysis.cost import (
    attach_query_costs,
    evaluate_cost,
    query_cost_vector,
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
