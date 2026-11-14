from __future__ import annotations

import pytest

from slowquery_autopsy.store.ledger import Ledger, LedgerError, open_readonly


def test_schema_and_idempotent_batch(ledger_result):
    config, result = ledger_result
    with Ledger(config.ledger_path) as ledger:
        names = set(ledger.table_names())
        assert {"batches", "log_files", "slow_queries", "clusters", "plans",
                "plan_nodes", "findings", "baselines", "comparisons",
                "unparsed_lines"} <= names
        assert ledger.save_batch(result) is False
        assert len(ledger.list_batches()) == 1
        batch = ledger.get_batch(result.batch_id)
        assert batch["summary"]["counts"]["queries"] == 20
        assert batch["status"] == "complete"


def test_read_only_queries_and_write_rejection(ledger_result):
    config, result = ledger_result
    with open_readonly(config.ledger_path) as ledger:
        assert ledger.readonly is True
        assert len(ledger.list_queries(result.batch_id)) == 20
        assert len(ledger.list_unparsed(result.batch_id)) == 3
        assert len(ledger.list_findings(result.batch_id)) == len(result.findings)
        clusters = ledger.list_clusters(result.batch_id)
        assert clusters[0]["total_duration_ms"] >= clusters[-1]["total_duration_ms"]
        cluster = ledger.get_cluster(result.batch_id, clusters[0]["cluster_id"])
        assert cluster and len(ledger.list_queries(result.batch_id, cluster["cluster_id"])) == 10
        with pytest.raises(LedgerError):
            ledger.init_schema()
        with pytest.raises(LedgerError):
            ledger.save_batch(result)


def test_parent_clusters_are_persisted_with_child_links(ledger_result):
    config, result = ledger_result
    with open_readonly(config.ledger_path) as ledger:
        parents = ledger.list_parent_clusters(result.batch_id)
        assert len(parents) == len(result.parent_clusters)
        persisted = {p["structural_fingerprint"]: p for p in parents}
        for parent in result.parent_clusters:
            row = persisted[parent.structural_fingerprint]
            assert row["query_count"] == parent.query_count
            assert row["child_fingerprints"] == parent.child_fingerprints
            assert row["child_query_counts"] == parent.child_query_counts
            assert row["child_cluster_count"] == len(parent.child_fingerprints)
            assert row["structural_sql"] == parent.structural_sql
        # Child rows carry the parent structural id for upward navigation.
        for cluster in ledger.list_clusters(result.batch_id):
            assert cluster["structural_fingerprint"] in persisted
        # Persisted parent totals match the in-memory aggregate exactly.
        assert round(sum(p["total_duration_ms"] for p in parents), 6) == round(
            sum(c.total_duration_ms for c in result.clusters), 6
        )


def test_plan_nodes_findings_and_relationships(ledger_result):
    config, result = ledger_result
    with open_readonly(config.ledger_path) as ledger:
        nested = next(plan for plan in ledger.list_plans(result.batch_id)
                      if plan["source_file"].endswith("nested_loop.json"))
        plan = ledger.get_plan(result.batch_id, nested["plan_id"])
        assert plan and len(plan["nodes"]) == 3
        assert plan["nodes"][-1]["path"] == "0.1"
        finding = ledger.list_findings(result.batch_id)[0]
        assert ledger.get_finding(result.batch_id, finding["finding_id"])["rule_id"] == finding["rule_id"]
        query = ledger.list_queries(result.batch_id)[0]
        assert ledger.get_query(result.batch_id, query["query_id"])["sql_text"]
        assert ledger.latest_batch_id() == result.batch_id


def test_baselines_and_comparisons(ledger_result):
    config, result = ledger_result
    with Ledger(config.ledger_path) as ledger:
        ledger.set_baseline("ci", result.batch_id, "2026-01-11T00:00:00Z")
        assert ledger.get_baseline("ci")["batch_id"] == result.batch_id
        assert [item["name"] for item in ledger.list_baselines()] == ["ci"]
        summary = {"counts": {"new_clusters": 0}}
        ledger.record_comparison("cmp-test", result.batch_id, result.batch_id,
                                 "2026-01-11T00:00:00Z", summary)
        comparisons = ledger.list_comparisons()
        assert comparisons[0]["summary"] == summary


def test_missing_ledger_readonly_fails(tmp_path):
    with pytest.raises(FileNotFoundError):
        open_readonly(tmp_path / "missing.sqlite3")
