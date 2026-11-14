"""CLI surface for the cross-batch fingerprint trace."""

from __future__ import annotations

import json

from slowquery_autopsy.cli import main
from slowquery_autopsy.pipeline import run
from slowquery_autopsy.store.ledger import open_readonly
from trace_support import append_block, project, trace_config


def test_trace_cli_defaults_ordering_output_and_record(tmp_path, project_root, capsys):
    config_path = project(tmp_path, project_root)
    config = trace_config(config_path, tmp_path)
    first, _ = run(config, created_at="2026-04-01T00:00:00Z")
    append_block(
        tmp_path / "fixtures/logs/pg_log_01.log",
        "2026-04-02T09:00:00Z,svc_report,shopdemo,6.000,0.010,1,50,node-d,"
        "SELECT COUNT(*) FROM order_items WHERE product_id = 9;\n",
    )
    second, _ = run(config, created_at="2026-04-02T00:00:00Z")
    capsys.readouterr()

    output = tmp_path / "trace.json"
    assert main(["trace", "--config", str(config_path), "--output", str(output)]) == 0
    printed = capsys.readouterr()
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload == json.loads(printed.out)
    assert [item["batch_id"] for item in payload["batches"]] == [
        first.batch_id, second.batch_id,
    ]
    assert "trace: batches=2" in printed.err

    # Explicit --batch order is preserved verbatim.
    assert main([
        "trace", "--config", str(config_path),
        "--batch", second.batch_id, "--batch", first.batch_id,
    ]) == 0
    reversed_payload = json.loads(capsys.readouterr().out)
    assert [item["batch_id"] for item in reversed_payload["batches"]] == [
        second.batch_id, first.batch_id,
    ]

    # Only the newest batch.
    assert main(["trace", "--config", str(config_path), "--last", "1"]) == 0
    latest = json.loads(capsys.readouterr().out)
    assert [item["batch_id"] for item in latest["batches"]] == [second.batch_id]

    assert main([
        "trace", "--config", str(config_path), "--batch", "batch-missing",
    ]) == 2
    assert "unknown batch" in capsys.readouterr().err
    assert main(["trace", "--config", str(config_path), "--last", "0"]) == 2

    with open_readonly(config.ledger_path) as ledger:
        traces = ledger.list_traces()
    assert len(traces) == 3
    assert traces[0]["summary"]["trace_type"] == "slowquery-autopsy-fingerprint-trace"


def test_trace_cli_without_ledger_is_an_error(tmp_path, project_root, capsys):
    # Copy the project but never run it: the ledger does not exist yet.
    config_path = project(tmp_path, project_root)
    assert main(["trace", "--config", str(config_path)]) == 2
    assert "ledger not found" in capsys.readouterr().err
    assert main(["trace", "--config", str(config_path), "--last", "1"]) == 2
