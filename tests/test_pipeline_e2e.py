from __future__ import annotations

import json
import shutil
from pathlib import Path

import yaml

from slowquery_autopsy.analysis.diff import diff_batches
from slowquery_autopsy.cli import main
from slowquery_autopsy.store.ledger import Ledger, open_readonly

NEW_BLOCK = """# Time: 2026-01-13T09:00:00Z
# User@Host: svc_app[svc_app] @ node-new [synthetic]  Id: 901
# Schema: shopdemo
# Query_time: 5.200000  Lock_time: 0.010000 Rows_sent: 1  Rows_examined: 42
SELECT COUNT(*) FROM order_items WHERE product_id = 77;
"""


def _project(tmp_path: Path, project_root: Path) -> Path:
    shutil.copytree(project_root / "fixtures", tmp_path / "fixtures")
    shutil.copytree(project_root / "configs", tmp_path / "configs")
    return tmp_path / "configs/pipeline.yaml"


def test_run_ledger_report_diff_chain(tmp_path, project_root, capsys):
    config_path = _project(tmp_path, project_root)
    assert main(["run", "--config", str(config_path), "--now", "2026-01-12T00:00:00Z"]) == 0
    ledger_path = tmp_path / "data/ledger.sqlite3"
    with open_readonly(ledger_path) as ledger:
        first = ledger.list_batches()[0]["batch_id"]
        assert ledger.get_batch(first)["summary"]["counts"]["queries"] == 20
    report_dir = tmp_path / "reports" / first
    assert (report_dir / "report.md").is_file()
    assert (report_dir / "report.json").is_file()
    assert (report_dir / "html/index.html").is_file()

    with (tmp_path / "fixtures/logs/mysql_slow_01.log").open("a", encoding="utf-8") as handle:
        handle.write(NEW_BLOCK)
    assert main(["run", "--config", str(config_path), "--now", "2026-01-12T01:00:00Z"]) == 0
    with open_readonly(ledger_path) as ledger:
        batches = ledger.list_batches()
        assert len(batches) == 2
        head = batches[0]["batch_id"]
        assert head != first
        assert ledger.get_batch(head)["summary"]["counts"]["queries"] == 21
    capsys.readouterr()
    assert main(["diff", "--config", str(config_path), "--base", first, "--head", head]) == 0
    captured = capsys.readouterr()
    diff = json.loads(captured.out)
    assert diff["base_batch_id"] == first and diff["head_batch_id"] == head
    assert diff["counts"]["new_clusters"] == 1
    assert diff["counts"]["disappeared_clusters"] == 0
    assert diff["clusters"]["new"][0]["query_count"] == 1
    with open_readonly(ledger_path) as ledger:
        assert len(ledger.list_comparisons()) == 1
    assert main(["validate", "--config", str(config_path)]) == 0


def test_fail_on_high_severity_exit_code(tmp_path, project_root):
    config_path = _project(tmp_path, project_root)
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    raw["risk"]["fail_on_severity"] = ["high"]
    config_path.write_text(yaml.safe_dump(raw, sort_keys=False, allow_unicode=True), encoding="utf-8")
    assert main(["run", "--config", str(config_path), "--now", "2026-01-12T00:00:00Z"]) == 1


def test_diff_pure_new_disappeared_and_high_findings():
    base_clusters = [
        {"cluster_id": "a", "query_count": 1, "total_duration_ms": 10.0, "sample_sql": "A"},
        {"cluster_id": "b", "query_count": 1, "total_duration_ms": 10.0, "sample_sql": "B"},
    ]
    head_clusters = [
        {"cluster_id": "b", "query_count": 2, "total_duration_ms": 20.0, "sample_sql": "B"},
        {"cluster_id": "c", "query_count": 1, "total_duration_ms": 30.0, "sample_sql": "C"},
    ]
    base_findings = [
        {"finding_id": "f1", "severity": "high", "rule_id": "R1"},
        {"finding_id": "f2", "severity": "low", "rule_id": "R2"},
    ]
    head_findings = [{"finding_id": "f3", "severity": "critical", "rule_id": "R3"}]
    diff = diff_batches("base", "head", base_clusters, head_clusters, base_findings, head_findings)
    assert [item["cluster_id"] for item in diff["clusters"]["new"]] == ["c"]
    assert [item["cluster_id"] for item in diff["clusters"]["disappeared"]] == ["a"]
    assert diff["counts"]["new_high_findings"] == 1
    assert diff["counts"]["disappeared_high_findings"] == 1
