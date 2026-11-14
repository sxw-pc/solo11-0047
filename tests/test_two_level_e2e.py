"""End-to-end determinism of the two-level (parent/child) fingerprint output."""

from __future__ import annotations

from slowquery_autopsy.analysis.fingerprint import (
    build_clusters,
    build_parent_clusters,
)
from slowquery_autopsy.pipeline import attach_fingerprints
from slowquery_autopsy.report.json_report import build_json_report


def test_repeated_runs_yield_identical_two_level_fingerprints(config):
    from slowquery_autopsy.ingest.log_parser import parse_inputs

    def fingerprints():
        parsed = parse_inputs(config)
        attach_fingerprints(parsed.queries, config)
        queries = [q for q in parsed.queries if not q.excluded]
        parents = build_parent_clusters(queries)
        children = build_clusters(queries)
        return (
            sorted((q.query_id, q.fingerprint, q.structural_fingerprint) for q in queries),
            sorted((p.structural_fingerprint, tuple(p.child_fingerprints),
                    tuple(p.query_ids)) for p in parents),
            sorted((c.fingerprint, c.structural_fingerprint) for c in children),
        )

    first = fingerprints()
    for _ in range(2):
        assert fingerprints() == first


def test_full_report_is_byte_stable_across_builds(config):
    from slowquery_autopsy.pipeline import build_result

    first = build_json_report(build_result(config, created_at="2026-01-11T00:00:00Z"))
    second = build_json_report(build_result(config, created_at="2026-01-11T00:00:00Z"))
    assert first == second
    # Parent/child linkage is complete and every child maps to an existing parent.
    parent_ids = {p["structural_fingerprint"] for p in first["parent_clusters"]}
    for child in first["clusters"]:
        assert child["structural_fingerprint"] in parent_ids
    # Every analyzed query is reachable through exactly one parent's query_ids.
    analyzed = {q["query_id"] for q in first["queries"] if not q["excluded"]}
    parent_owned = {qid for p in first["parent_clusters"] for qid in p["query_ids"]}
    assert parent_owned == analyzed
    # Child fingerprints referenced by parents are a subset of real clusters.
    child_ids = {c["fingerprint"] for c in first["clusters"]}
    referenced = {fp for p in first["parent_clusters"] for fp in p["child_fingerprints"]}
    assert referenced <= child_ids


def test_parent_child_statistics_reconcile_on_fixtures(config):
    from slowquery_autopsy.pipeline import build_result

    result = build_result(config, created_at="2026-01-11T00:00:00Z")
    # Counts and durations reconcile at both levels (no double counting).
    assert sum(p.query_count for p in result.parent_clusters) == sum(
        c.query_count for c in result.clusters
    )
    assert round(sum(p.total_duration_ms for p in result.parent_clusters), 6) == round(
        sum(c.total_duration_ms for c in result.clusters), 6
    )
    assert round(sum(p.duration_share for p in result.parent_clusters), 6) == 1.0
    # Per-parent reconciliation against its own children.
    child_by_id = {c.fingerprint: c for c in result.clusters}
    for parent in result.parent_clusters:
        members = [child_by_id[fp] for fp in parent.child_fingerprints]
        assert sum(c.query_count for c in members) == parent.query_count
        assert round(sum(c.total_duration_ms for c in members), 6) == round(
            parent.total_duration_ms, 6
        )
        assert sum(c.total_rows_examined for c in members) == parent.total_rows_examined
        assert sum(c.total_rows_sent for c in members) == parent.total_rows_sent
        # Amplification must be recomputed at parent granularity (ratio of
        # totals), never taken as an average of child amplifications.
        recomputed = parent.total_rows_examined / max(parent.total_rows_sent, 1)
        assert parent.amplification == recomputed
        # projected cost follows the parent-level average, not child sums.
        assert parent.projected_ms_per_1k_calls == parent.avg_duration_ms * 1000.0
