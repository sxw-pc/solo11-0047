"""Ledger-backed cross-batch tracing on real pipeline output."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from slowquery_autopsy.analysis.trace import trace_batches_from_ledger
from slowquery_autopsy.pipeline import run
from slowquery_autopsy.store.ledger import Ledger, open_readonly
from trace_support import (
    TRACE_KEYS,
    UNIQUE_BLOCK,
    append_block,
    drop_fingerprint,
    project,
    trace_config,
)


def test_ledger_trace_tracks_counts_p95_and_finding_identity(tmp_path, project_root):
    config_path = project(tmp_path, project_root)
    config = trace_config(config_path, tmp_path)
    first, _ = run(config, created_at="2026-02-01T00:00:00Z")

    # B2: an extra run of the same fingerprint changes queries and P95, so the
    # evidence-derived finding ids change while the fingerprint stays put.
    append_block(
        tmp_path / "fixtures/logs/mysql_slow_01.log",
        "# Time: 2026-02-02T10:00:00Z\n"
        "# User@Host: svc_app[svc_app] @ node-a [synthetic]  Id: 777\n"
        "# Schema: shopdemo\n"
        "# Query_time: 9.500000  Lock_time: 0.010000 Rows_sent: 20  Rows_examined: 280000\n"
        "SET timestamp=1768039200;\n"
        "SELECT * FROM orders WHERE customer_id = 1 AND status = 'PAID' "
        "ORDER BY created_at DESC LIMIT 20;\n",
    )
    second, _ = run(config, created_at="2026-02-02T00:00:00Z")

    with open_readonly(config.ledger_path) as ledger:
        trace = trace_batches_from_ledger(ledger, [first.batch_id, second.batch_id])
        batches = ledger.list_batches_chronological()

    assert set(trace) == TRACE_KEYS
    assert [item["batch_id"] for item in trace["batches"]] == [
        first.batch_id, second.batch_id,
    ]
    assert batches[0]["batch_id"] == first.batch_id
    entries = {item["fingerprint"]: item for item in trace["fingerprints"]}
    fingerprint = next(
        cluster.fingerprint for cluster in second.clusters
        if cluster.query_count > 10
    )
    entry = entries[fingerprint]
    first_entry = next(c for c in first.clusters if c.fingerprint == fingerprint)
    second_entry = next(c for c in second.clusters if c.fingerprint == fingerprint)
    assert [item["query_count"] for item in entry["batches"]] == [
        first_entry.query_count, second_entry.query_count,
    ]
    assert entry["batches"][0]["p95_duration_ms"] == round(first_entry.p95_duration_ms, 3)
    assert entry["batches"][1]["p95_duration_ms"] == round(second_entry.p95_duration_ms, 3)
    assert entry["status"] == "continuous"
    assert entry["first_seen_batch"] == first.batch_id
    assert entry["last_seen_batch"] == second.batch_id
    # P95 changed for this fingerprint, so at least one finding id differs...
    keys = entry["high_findings"]["keys"]
    assert keys and any(key["finding_ids_changed"] for key in keys)
    # ...but the identifying rule+target key is stable across both batches.
    for key in keys:
        assert set(key["present_in_batches"]) == {first.batch_id, second.batch_id}


def test_ledger_trace_distinguishes_missing_source_from_missing_fingerprint(
    tmp_path, project_root,
):
    config_path = project(tmp_path, project_root)
    config = trace_config(config_path, tmp_path)
    slow_02 = tmp_path / "fixtures/logs/mysql_slow_02.log"
    # A fingerprint that exists only in mysql_slow_02.log keeps the assertions
    # independent of the other sources.
    append_block(slow_02, UNIQUE_BLOCK)
    first, _ = run(config, created_at="2026-03-01T00:00:00Z")
    unique = next(q.fingerprint for q in first.queries if "warehouse_items" in q.sql)

    # B2 drops that query from mysql_slow_02.log but still collects the file.
    drop_fingerprint(slow_02, "warehouse_items")
    absent, _ = run(config, created_at="2026-03-02T00:00:00Z")

    with open_readonly(config.ledger_path) as ledger:
        trace_absent = trace_batches_from_ledger(
            ledger, [first.batch_id, absent.batch_id]
        )

    # B3 removes the file from the inputs: that is not a disappearance.
    import yaml

    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    raw["inputs"] = [
        item for item in raw["inputs"]
        if not item["path"].endswith("mysql_slow_02.log")
    ]
    config_path.write_text(
        yaml.safe_dump(raw, sort_keys=False, allow_unicode=True), encoding="utf-8"
    )
    config3 = trace_config(config_path, tmp_path)
    uncollected, _ = run(config3, created_at="2026-03-03T00:00:00Z")

    with open_readonly(config3.ledger_path) as ledger:
        trace_all = trace_batches_from_ledger(
            ledger, [first.batch_id, absent.batch_id, uncollected.batch_id]
        )

    entry = next(item for item in trace_absent["fingerprints"]
                 if item["fingerprint"] == unique)
    assert [item["state"] for item in entry["batches"]] == ["observed", "absent"]
    assert entry["status"] == "disappeared"

    entry = next(item for item in trace_all["fingerprints"]
                 if item["fingerprint"] == unique)
    assert [item["state"] for item in entry["batches"]] == [
        "observed", "absent", "not_collected",
    ]
    assert entry["batches"][2]["missing_sources"] == [
        "fixtures/logs/mysql_slow_02.log",
    ]
    assert entry["not_collected_batches"] == [uncollected.batch_id]
    # The fingerprint is still absent in the latest batch that actually covered it.
    assert entry["last_seen_batch"] == first.batch_id
    assert entry["status"] == "disappeared"


def test_trace_is_repeatable_for_the_same_batch_set(tmp_path, project_root):
    config_path = project(tmp_path, project_root)
    config = trace_config(config_path, tmp_path)
    result, _ = run(config, created_at="2026-05-01T00:00:00Z")
    with open_readonly(config.ledger_path) as ledger:
        first = trace_batches_from_ledger(ledger, [result.batch_id])
        second = trace_batches_from_ledger(ledger, [result.batch_id])
    assert first == second
    assert first["counts"]["fingerprints"] == len(result.clusters)
    assert first["counts"]["observations"] == len(result.clusters)


def _legacy_project(tmp_path, project_root):
    """Create a 2-batch project, then strip ``fingerprint_sources`` from it."""
    config_path = project(tmp_path, project_root)
    config = trace_config(config_path, tmp_path)
    slow_02 = tmp_path / "fixtures/logs/mysql_slow_02.log"
    append_block(slow_02, UNIQUE_BLOCK)
    first, _ = run(config, created_at="2026-06-01T00:00:00Z")
    unique = next(q.fingerprint for q in first.queries if "warehouse_items" in q.sql)
    drop_fingerprint(slow_02, "warehouse_items")
    second, _ = run(config, created_at="2026-06-02T00:00:00Z")

    legacy = tmp_path / "legacy.sqlite3"
    with open_readonly(config.ledger_path) as source_ledger:
        dump = list(source_ledger.conn.iterdump())
    connection = sqlite3.connect(legacy)
    try:
        connection.executescript("\n".join(dump))
        connection.execute("DROP TABLE fingerprint_sources")
        connection.commit()
    finally:
        connection.close()
    return legacy, first.batch_id, second.batch_id, unique


def test_legacy_ledger_without_sources_table(tmp_path, project_root):
    """A pre-v2 ledger cannot prove non-collection, so it must not claim absence."""
    legacy, first_id, second_id, unique = _legacy_project(tmp_path, project_root)
    with open_readonly(legacy) as ledger:
        assert ledger.has_fingerprint_sources() is False
        assert ledger.list_fingerprint_sources(first_id) == []
        trace = trace_batches_from_ledger(ledger, [first_id, second_id])
    entry = next(item for item in trace["fingerprints"]
                 if item["fingerprint"] == unique)
    assert [item["state"] for item in entry["batches"]] == ["observed", "not_collected"]
    assert entry["batches"][1]["coverage_known"] is False
    # Not enough proof to say "disappeared", so the status stays conservative.
    assert entry["status"] == "single_batch"


def test_backfill_restores_coverage_for_legacy_batches(tmp_path, project_root):
    legacy, first_id, second_id, unique = _legacy_project(tmp_path, project_root)
    with Ledger(legacy) as ledger:
        ledger.init_schema()
        assert ledger.backfill_fingerprint_sources() > 0
        # Idempotent: a second pass inserts nothing.
        assert ledger.backfill_fingerprint_sources() == 0
        trace = trace_batches_from_ledger(ledger, [first_id, second_id])
    entry = next(item for item in trace["fingerprints"]
                 if item["fingerprint"] == unique)
    assert [item["state"] for item in entry["batches"]] == ["observed", "absent"]
    assert entry["status"] == "disappeared"


def test_writable_ledger_has_new_tables(tmp_path, project_root):
    config_path = project(tmp_path, project_root)
    config = trace_config(config_path, tmp_path)
    with Ledger(config.ledger_path) as ledger:
        ledger.init_schema()
        assert {"fingerprint_sources", "traces"} <= set(ledger.table_names())
        ledger.record_trace("trc-test", ["b1", "b2"], "2026-01-01T00:00:00Z",
                            {"counts": {"batches": 2}})
        assert ledger.list_traces()[0]["batch_ids"] == ["b1", "b2"]
