from __future__ import annotations

from slowquery_autopsy.analysis.cost import (
    attach_query_costs,
    cluster_metric,
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


def _timed_query(timestamp: str, duration: float, examined: int,
                 fp: str = "aaaaaaaaaaaaaaaa", line_no: int = 1) -> SlowQuery:
    return SlowQuery(
        source_file="synthetic.log", line_no=line_no, timestamp=timestamp,
        duration_ms=duration, lock_time_ms=0.0, rows_sent=1, rows_examined=examined,
        user="u", client="c", database="d", sql="SELECT 1;", log_format="mysql_slow",
        query_id=f"q-{line_no}", fingerprint=fp, cluster_id=fp,
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


def test_window_metrics_are_exposed_to_cluster_metric():
    cluster = build_clusters([
        _timed_query("2026-01-10T00:00:00Z", 100.0, 1000, line_no=1),
        _timed_query("2026-01-10T00:01:00Z", 300.0, 3000, line_no=2),
        _timed_query("2026-01-10T00:30:00Z", 200.0, 2000, line_no=3),
    ], window_seconds=300)[0]
    assert cluster_metric(cluster, "window_event_count") == 2.0
    assert cluster_metric(cluster, "window_max_duration_ms") == 400.0
    assert cluster_metric(cluster, "window_max_rows_examined") == 4000.0
    try:
        cluster_metric(cluster, "not_a_metric")
    except ValueError as exc:
        assert "unsupported cost metric" in str(exc)
    else:  # pragma: no cover - defensive
        raise AssertionError("expected ValueError for unknown metric")


def test_window_metric_rules_evaluate_like_existing_cost_rules():
    # One tight 2-occurrence burst, then an isolated occurrence 30 minutes later.
    cluster = build_clusters([
        _timed_query("2026-01-10T00:00:00Z", 100.0, 5000, line_no=1),
        _timed_query("2026-01-10T00:02:00Z", 400.0, 7000, line_no=2),
        _timed_query("2026-01-10T00:32:00Z", 50.0, 100, line_no=3),
    ], window_seconds=300)[0]
    burst_rule = {
        "id": "COST-WIN-EVENTS", "title": "burst count",
        "metric": "window_event_count", "operator": "gte", "threshold": 2,
        "min_count": 1, "severity": "medium",
    }
    scan_rule = {
        "id": "COST-WIN-SCAN", "title": "window scan",
        "metric": "window_max_rows_examined", "operator": "gt", "threshold": 20000,
        "min_count": 1, "severity": "high",
    }
    duration_rule = {
        "id": "COST-WIN-TIME", "title": "window duration",
        "metric": "window_max_duration_ms", "operator": "gt", "threshold": 400,
        "min_count": 1, "severity": "low",
    }
    candidates = evaluate_cost([cluster], [burst_rule, scan_rule, duration_rule])
    by_rule = {item["rule_id"]: item for item in candidates}
    assert set(by_rule) == {"COST-WIN-EVENTS", "COST-WIN-TIME"}
    assert by_rule["COST-WIN-EVENTS"]["evidence"]["actual"] == 2
    assert by_rule["COST-WIN-EVENTS"]["evidence"]["metric"] == "window_event_count"
    assert by_rule["COST-WIN-TIME"]["evidence"]["actual"] == 500.0
    # The largest single-window scan volume is 12000, below the 10000 rule's
    # threshold only when the burst stays one event; splitting would miss it.
    assert cluster.window_max_rows_examined == 12000
    assert "COST-WIN-SCAN" not in by_rule
    scan_rule["threshold"] = 12000  # gt on the endpoint value must stay False
    assert evaluate_cost([cluster], [scan_rule]) == []


def test_window_rules_respect_min_count_and_remain_backward_compatible():
    cluster = build_clusters([
        _timed_query("2026-01-10T00:00:00Z", 100.0, 100),
        _timed_query("2026-01-10T00:30:00Z", 100.0, 100, line_no=2),
    ], window_seconds=300)[0]
    rule = {
        "id": "COST-WIN-MIN", "title": "events", "metric": "window_event_count",
        "operator": "gte", "threshold": 1, "min_count": 3, "severity": "low",
    }
    assert evaluate_cost([cluster], [rule]) == []
    # Pre-window metrics and evidence keys keep their original semantics.
    legacy = {
        "id": "T-AMP", "title": "amp", "metric": "amplification",
        "operator": "gt", "threshold": 50, "min_count": 1, "severity": "high",
    }
    candidate = evaluate_cost([cluster], [legacy])[0]
    assert candidate["evidence"]["query_count"] == 2
    assert candidate["cluster_id"] == cluster.fingerprint
