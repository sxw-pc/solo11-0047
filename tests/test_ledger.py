from __future__ import annotations

import sqlite3

import pytest

from slowquery_autopsy.store.ledger import Ledger, LedgerError, open_readonly
from slowquery_autopsy.store.schema import SCHEMA_SQL


def _legacy_sql() -> str:
    return SCHEMA_SQL.replace(
        "  event_id TEXT NOT NULL DEFAULT '', duplicate_of TEXT NOT NULL DEFAULT '',\n"
        "  redundant_sources_json TEXT NOT NULL DEFAULT '[]',\n",
        "",
    )


def test_init_schema_migrates_v1_ledger(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    assert "event_id" not in _legacy_sql()
    with sqlite3.connect(path) as conn:
        conn.executescript(_legacy_sql())
        conn.execute("INSERT INTO schema_meta(key, value) VALUES ('version', '1')")
    with Ledger(path) as ledger:
        ledger.init_schema()
        columns = {row["name"] for row in ledger.conn.execute("PRAGMA table_info(slow_queries)")}
        assert {"event_id", "duplicate_of", "redundant_sources_json"} <= columns
        version = ledger.conn.execute(
            "SELECT value FROM schema_meta WHERE key = 'version'"
        ).fetchone()["value"]
        assert version == "2"


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
        assert batch["summary"]["counts"]["queries"] == 22
        assert batch["summary"]["counts"]["analyzed_queries"] == 18
        assert batch["summary"]["counts"]["duplicate_queries"] == 2
        assert batch["status"] == "complete"


def test_read_only_queries_and_write_rejection(ledger_result):
    config, result = ledger_result
    with open_readonly(config.ledger_path) as ledger:
        assert ledger.readonly is True
        assert len(ledger.list_queries(result.batch_id)) == 22
        folded = ledger.list_duplicate_sources(result.batch_id)
        assert len(folded) == 2
        assert {item["source_file"] for item in folded} == {
            "fixtures/logs/pg_crossformat_duplicates.log"
        }
        assert all(item["line_no"] >= 1 for item in folded)
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
