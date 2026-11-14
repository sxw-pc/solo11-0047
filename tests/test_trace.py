"""Cross-batch fingerprint persistence tracing."""

from __future__ import annotations

import copy

from slowquery_autopsy.analysis.risk_rules import finding_id_for
from slowquery_autopsy.analysis.trace import (
    ABSENT,
    NOT_COLLECTED,
    OBSERVED,
    STATUS_CONTINUOUS,
    STATUS_DISAPPEARED,
    STATUS_NEW,
    STATUS_REAPPEARED,
    STATUS_SINGLE,
    trace_fingerprints,
)


def _cluster(batch_id: str, fingerprint: str, count: int, p95: float,
             sample: str = "SELECT 1") -> dict:
    return {
        "batch_id": batch_id,
        "cluster_id": fingerprint,
        "fingerprint": fingerprint,
        "sample_sql": sample,
        "normalized_sql": sample,
        "query_count": count,
        "p95_duration_ms": p95,
        "total_duration_ms": p95 * count,
    }


def _finding(batch_id: str, fingerprint: str, rule_id: str, severity: str,
             evidence: dict, plan_file: str = "", node_path: str = "") -> dict:
    # Real ids hash evidence, which is exactly what changes between batches.
    finding_id = finding_id_for({
        "rule_id": rule_id,
        "cluster_id": fingerprint,
        "plan_file": plan_file,
        "node_path": node_path,
        "evidence": evidence,
    })
    return {
        "batch_id": batch_id,
        "finding_id": finding_id,
        "cluster_id": fingerprint,
        "rule_id": rule_id,
        "severity": severity,
        "category": "cost" if not plan_file else "plan",
        "title": rule_id,
        "plan_file": plan_file,
        "node_path": node_path,
        "evidence": evidence,
    }


def _log_file(batch_id: str, path: str, parsed: int = 1) -> dict:
    return {"batch_id": batch_id, "path": path, "parsed_count": parsed}


def _source(batch_id: str, fingerprint: str, path: str, count: int = 1) -> dict:
    return {
        "batch_id": batch_id,
        "fingerprint": fingerprint,
        "source_file": path,
        "query_count": count,
    }


def _trace(batch_ids, clusters, findings, log_files, sources, **kwargs):
    return trace_fingerprints(batch_ids, clusters, findings, log_files, sources,
                              **kwargs)


def test_continuous_presence_and_per_batch_metrics():
    batches = ["b1", "b2", "b3"]
    clusters = [
        _cluster("b1", "fp-a", 2, 3000.0),
        _cluster("b2", "fp-a", 5, 4200.0),
        _cluster("b3", "fp-a", 1, 2500.0),
    ]
    findings = [
        _finding("b1", "fp-a", "COST-P95-001", "high", {"actual": 3000, "query_count": 2}),
        _finding("b2", "fp-a", "COST-P95-001", "high", {"actual": 4200, "query_count": 5}),
        _finding("b3", "fp-a", "COST-P95-001", "high", {"actual": 2500, "query_count": 1}),
    ]
    log_files = [_log_file(batch_id, "logs/a.log") for batch_id in batches]
    sources = [_source(batch_id, "fp-a", "logs/a.log") for batch_id in batches]
    trace = _trace(batches, clusters, findings, log_files, sources)

    entry = trace["fingerprints"][0]
    assert [item["query_count"] for item in entry["batches"]] == [2, 5, 1]
    assert [item["p95_duration_ms"] for item in entry["batches"]] == [3000.0, 4200.0, 2500.0]
    assert [item["state"] for item in entry["batches"]] == ["observed"] * 3
    assert entry["status"] == STATUS_CONTINUOUS
    assert entry["first_seen_batch"] == "b1"
    assert entry["last_seen_batch"] == "b3"

    # Identity is rule + target, not the evidence-derived finding id.
    high = entry["high_findings"]
    assert high["count"] == 1
    assert high["keys"][0]["rule_id"] == "COST-P95-001"
    assert high["keys"][0]["finding_ids_changed"] is True
    assert len(set(high["keys"][0]["finding_ids"])) == 3
    # Only high/critical is tracked; only one such key exists here.
    assert high["keys"][0]["severities"] == ["high"]


def test_gap_without_collection_is_not_a_disappearance():
    batches = ["b1", "b2", "b3"]
    clusters = [_cluster("b1", "fp-a", 1, 1000.0), _cluster("b3", "fp-a", 1, 1000.0)]
    log_files = [
        _log_file("b1", "logs/a.log"),
        _log_file("b2", "logs/other.log"),  # b2 simply did not collect a.log
        _log_file("b3", "logs/a.log"),
    ]
    sources = [
        _source("b1", "fp-a", "logs/a.log"),
        _source("b3", "fp-a", "logs/a.log"),
    ]
    trace = _trace(batches, clusters, [], log_files, sources)
    entry = trace["fingerprints"][0]
    states = [item["state"] for item in entry["batches"]]
    assert states == [OBSERVED, NOT_COLLECTED, OBSERVED]
    assert entry["not_collected_batches"] == ["b2"]
    assert entry["absent_batches"] == []
    # A not-collected gap must not turn continuous presence into "reappeared".
    assert entry["status"] == STATUS_CONTINUOUS
    missing = entry["batches"][1]["missing_sources"]
    assert missing == ["logs/a.log"]
    assert entry["batches"][1]["coverage_known"] is True


def test_absent_after_real_collection_is_disappearance():
    batches = ["b1", "b2"]
    clusters = [_cluster("b1", "fp-a", 1, 1000.0)]
    log_files = [_log_file("b1", "logs/a.log"), _log_file("b2", "logs/a.log", parsed=0)]
    sources = [_source("b1", "fp-a", "logs/a.log")]
    trace = _trace(batches, clusters, [], log_files, sources)
    entry = trace["fingerprints"][0]
    assert [item["state"] for item in entry["batches"]] == [OBSERVED, ABSENT]
    assert entry["status"] == STATUS_DISAPPEARED
    assert entry["last_seen_batch"] == "b1"


def test_reappearance_after_absent():
    batches = ["b1", "b2", "b3"]
    clusters = [_cluster("b1", "fp-a", 1, 1000.0), _cluster("b3", "fp-a", 1, 1000.0)]
    log_files = [_log_file(batch_id, "logs/a.log") for batch_id in batches]
    sources = [_source(batch_id, "fp-a", "logs/a.log") for batch_id in ("b1", "b3")]
    trace = _trace(batches, clusters, [], log_files, sources)
    entry = trace["fingerprints"][0]
    assert [item["state"] for item in entry["batches"]] == [OBSERVED, ABSENT, OBSERVED]
    assert entry["status"] == STATUS_REAPPEARED


def test_new_fingerprint_and_single_batch_status():
    batches = ["b1", "b2"]
    clusters = [_cluster("b1", "fp-old", 1, 1000.0), _cluster("b2", "fp-new", 1, 1000.0)]
    log_files = [_log_file(batch_id, "logs/a.log") for batch_id in batches]
    sources = [
        _source("b1", "fp-old", "logs/a.log"),
        _source("b2", "fp-new", "logs/a.log"),
    ]
    trace = _trace(batches, clusters, [], log_files, sources)
    entries = {item["fingerprint"]: item for item in trace["fingerprints"]}
    assert entries["fp-old"]["status"] == STATUS_DISAPPEARED
    assert entries["fp-new"]["status"] == STATUS_NEW
    assert entries["fp-new"]["first_seen_batch"] == "b2"
    assert entries["fp-new"]["batches"][0]["state"] == ABSENT
    assert entries["fp-new"]["batches"][1]["state"] == OBSERVED

    single = _trace(["b1"], [_cluster("b1", "fp-a", 1, 1000.0)], [], [], [])
    assert single["fingerprints"][0]["status"] == STATUS_SINGLE


def test_partial_source_coverage_is_not_collected():
    batches = ["b1", "b2"]
    clusters = [_cluster("b1", "fp-a", 1, 1000.0)]
    log_files = [_log_file("b1", "logs/a.log"), _log_file("b2", "logs/a.log")]
    # fp-a was also seen in b1's b.log, which b2 never collected.
    sources = [_source("b1", "fp-a", "logs/a.log"), _source("b1", "fp-a", "logs/b.log")]
    trace = _trace(batches, clusters, [], log_files, sources)
    entry = trace["fingerprints"][0]
    assert entry["batches"][1]["state"] == NOT_COLLECTED
    assert entry["batches"][1]["missing_sources"] == ["logs/b.log"]
    assert entry["status"] == STATUS_SINGLE


def test_unknown_coverage_falls_back_to_not_collected():
    batches = ["b1", "b2"]
    clusters = [_cluster("b1", "fp-a", 1, 1000.0)]
    log_files = [_log_file("b1", "logs/a.log"), _log_file("b2", "logs/a.log")]
    trace = _trace(batches, clusters, [], log_files, [],
                   sources_known={"b1"})
    entry = trace["fingerprints"][0]
    assert entry["batches"][1]["state"] == NOT_COLLECTED
    assert entry["batches"][1]["coverage_known"] is False
    assert entry["batches"][1]["missing_sources"] == []


def test_ordering_is_the_supplied_batch_sequence():
    clusters = [_cluster("b2", "fp-a", 1, 1000.0), _cluster("b1", "fp-a", 2, 1000.0),
                _cluster("b3", "fp-a", 1, 1000.0)]
    trace = _trace(["b2", "b1", "b3"], clusters, [], [], [])
    entry = trace["fingerprints"][0]
    assert [item["batch_id"] for item in entry["batches"]] == ["b2", "b1", "b3"]
    assert entry["first_seen_batch"] == "b2"
    assert entry["last_seen_batch"] == "b3"


def test_counts_and_unknown_batches_are_ignored():
    clusters = [_cluster("b1", "fp-a", 1, 1000.0),
                _cluster("zzz", "fp-leak", 1, 1000.0)]
    findings = [_finding("b1", "fp-a", "COST-AVG-001", "critical", {"x": 1}),
                _finding("zzz", "fp-leak", "COST-AVG-001", "critical", {"x": 2})]
    trace = _trace(["b1"], clusters, findings, [], [])
    assert [item["fingerprint"] for item in trace["fingerprints"]] == ["fp-a"]
    assert trace["counts"]["high_findings"] == 1


def test_unattributed_high_findings_are_counted_not_dropped():
    trace = _trace(["b1"], [_cluster("b1", "fp-a", 1, 1000.0)], [
        _finding("b1", "fp-plan-only", "PLAN-FULLSCAN-001", "high", {"x": 1},
                 plan_file="plans/x.json", node_path="0"),
    ], [], [])
    assert trace["counts"]["high_findings"] == 1
    assert trace["counts"]["unattributed_high_findings"] == 1
    assert trace["fingerprints"][0]["high_findings"]["count"] == 0


def test_trace_is_deterministic_and_does_not_mutate_inputs():
    batches = ["b1", "b2"]
    clusters = [_cluster("b2", "fp-b", 1, 10.0), _cluster("b1", "fp-a", 1, 10.0)]
    findings = [_finding("b1", "fp-a", "COST-AVG-001", "high", {"x": 1})]
    log_files = [_log_file("b1", "logs/a.log"), _log_file("b2", "logs/a.log")]
    sources = [_source("b1", "fp-a", "logs/a.log"), _source("b2", "fp-b", "logs/a.log")]
    snapshot = copy.deepcopy((clusters, findings, log_files, sources))
    first = _trace(batches, clusters, findings, log_files, sources)
    second = _trace(batches, clusters, findings, log_files, sources)
    assert first == second
    assert snapshot == (clusters, findings, log_files, sources)
    assert [item["fingerprint"] for item in first["fingerprints"]] == ["fp-a", "fp-b"]
    assert first["counts"]["by_status"] == {STATUS_NEW: 1, STATUS_DISAPPEARED: 1}


def test_medium_and_low_findings_are_not_tracked():
    findings = [
        _finding("b1", "fp-a", "COST-P95-001", "medium", {"x": 1}),
        _finding("b1", "fp-a", "PLAN-SORT-001", "low", {"x": 2}),
        _finding("b1", "fp-a", "COST-AVG-001", "critical", {"x": 3}),
    ]
    trace = _trace(["b1"], [_cluster("b1", "fp-a", 1, 1000.0)], findings, [], [])
    entry = trace["fingerprints"][0]
    assert entry["batches"][0]["high_finding_count"] == 1
    assert entry["high_findings"]["count"] == 1
    assert entry["high_findings"]["keys"][0]["rule_id"] == "COST-AVG-001"
    assert trace["counts"]["high_findings"] == 1


def test_status_legend_covers_every_status():
    trace = _trace(["b1"], [_cluster("b1", "fp-a", 1, 1000.0)], [], [], [])
    legend = trace["status_legend"]
    assert set(legend) == {
        STATUS_SINGLE, STATUS_CONTINUOUS, STATUS_NEW, STATUS_REAPPEARED, STATUS_DISAPPEARED,
    }
    assert trace["status_basis"] == "observed_and_absent_batches"


def test_duplicate_batch_ids_are_collapsed():
    trace = _trace(["b1", "b2", "b1"], [_cluster("b1", "fp-a", 1, 1000.0)], [], [], [])
    assert [item["batch_id"] for item in trace["batches"]] == ["b1", "b2"]
    assert len(trace["fingerprints"][0]["batches"]) == 2
