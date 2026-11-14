from __future__ import annotations

import json
from dataclasses import replace

import pytest

from slowquery_autopsy.analysis.diff import diff_batches
from slowquery_autopsy.analysis.risk_rules import (
    apply_finding_baselines,
    build_findings,
    finding_id_for,
    high_finding_ids,
)
from slowquery_autopsy.models import FindingBaseline
from slowquery_autopsy.pipeline import build_result, persist_result
from slowquery_autopsy.report.json_report import build_json_report
from slowquery_autopsy.report.markdown_report import render_markdown
from slowquery_autopsy.store.ledger import Ledger, open_readonly


def _candidate(**overrides):
    candidate = {
        "category": "cost", "rule_id": "COST-AMP-001", "severity": "high",
        "title": "amplification", "description": "amplified",
        "recommendation": "inspect", "cluster_id": "aaaaaaaaaaaaaaaa",
        "evidence": {"actual": 500.0, "threshold": 100},
        "query_id": "", "plan_file": "", "node_path": "",
    }
    candidate.update(overrides)
    return candidate


def test_finding_identity_is_stable_across_suppression():
    candidate = _candidate()
    before = build_findings([candidate])[0]
    after = build_findings(
        [candidate],
        baselines=[FindingBaseline(baseline_id="bl-1", rule_id="COST-AMP-001")],
    )[0]
    assert before.finding_id == after.finding_id
    assert after.original_severity == "high"
    assert after.severity == "high"          # original severity is never rewritten
    assert after.effective_severity == "info"
    assert after.suppressed is True
    assert before.effective_severity == "high"


def test_suppression_is_idempotent_and_leaves_unregistered_findings_alone():
    registered = _candidate(rule_id="RULE-A", cluster_id="aaaaaaaaaaaaaaaa")
    unrelated = _candidate(rule_id="RULE-B", cluster_id="bbbbbbbbbbbbbbbb",
                           evidence={"actual": 1.0})
    baseline = FindingBaseline(baseline_id="bl-a", rule_id="RULE-A")
    once = build_findings([registered, unrelated], baselines=[baseline])
    twice = apply_finding_baselines(once, [baseline, baseline])
    by_rule = {finding.rule_id: finding for finding in twice}
    assert by_rule["RULE-A"].suppressed is True
    assert by_rule["RULE-A"].baseline_id == "bl-a"
    assert by_rule["RULE-B"].suppressed is False
    assert by_rule["RULE-B"].effective_severity == "high"
    assert [finding.finding_id for finding in once] == [finding.finding_id for finding in twice]
    assert high_finding_ids(twice) == {finding_id_for(unrelated)}


def test_baseline_matching_ignores_volatile_plan_evidence():
    baseline = FindingBaseline(
        baseline_id="bl-plan", rule_id="PLAN-FULLSCAN-001",
        fingerprint="ffffffffffffffff",
    )
    moved = _candidate(
        category="plan", rule_id="PLAN-FULLSCAN-001", cluster_id="ffffffffffffffff",
        plan_file="fixtures/plans/moved.json", node_path="1.3.2",
        evidence={"node_path": "1.3.2", "table": "orders"},
    )
    suppressed = apply_finding_baselines(build_findings([moved]), [baseline])
    assert suppressed[0].suppressed is True
    stored = baseline.as_dict()
    assert "node_path" not in json.dumps(stored)
    assert "plan_file" not in json.dumps(stored)
    assert stored["rule_id"] == "PLAN-FULLSCAN-001"
    assert stored["fingerprint"] == "ffffffffffffffff"


def test_pipeline_suppression_reports_both_distributions(temp_config):
    baseline_config = replace(
        temp_config,
        finding_baselines=[FindingBaseline(
            baseline_id="bl-amp", rule_id="COST-AMP-001", origin="config",
        )],
    )
    result = build_result(baseline_config, created_at="2026-01-12T00:00:00Z")
    suppressed = [finding for finding in result.findings if finding.suppressed]
    assert len(suppressed) == 1
    assert suppressed[0].rule_id == "COST-AMP-001"
    assert suppressed[0].original_severity == "high"
    assert suppressed[0].effective_severity == "info"

    original = result.finding_counts()
    effective = result.effective_finding_counts()
    assert original["high"] == 9
    assert effective["high"] == 8
    assert effective["info"] == original["info"] + 1
    assert result.summary["severity_counts"] == original
    assert result.summary["effective_severity_counts"] == effective
    assert result.summary["counts"]["high_findings"] == 8
    assert result.summary["counts"]["suppressed_findings"] == 1

    payload = build_json_report(result)
    assert payload["severity_counts"] == original
    assert payload["effective_severity_counts"] == effective
    text = render_markdown(result)
    assert "原始严重级别分布" in text
    assert "生效严重级别分布" in text
    assert "基线豁免" in text


def test_duplicate_batches_do_not_duplicate_suppression(temp_config):
    result = build_result(temp_config, created_at="2026-01-12T00:00:00Z")
    assert persist_result(temp_config, result) is True
    with Ledger(temp_config.ledger_path) as ledger:
        first = ledger.add_finding_baseline(
            rule_id="COST-AMP-001", baseline_id="bl-amp", created_at="2026-01-12T01:00:00Z",
        )
        second = ledger.add_finding_baseline(
            rule_id="COST-AMP-001", baseline_id="bl-amp", created_at="2026-01-12T01:00:00Z",
        )
        assert first.baseline_id == second.baseline_id
        assert len(ledger.list_finding_baselines()) == 1
        suppressed = ledger.refresh_finding_suppression(result.batch_id)
        assert suppressed == 1
        assert ledger.refresh_finding_suppression(result.batch_id) == 1
        rows = ledger.list_findings(result.batch_id)
        assert sum(1 for row in rows if row["suppressed"]) == 1
        assert ledger.save_batch(result) is False
        assert len(ledger.list_findings(result.batch_id)) == len(result.findings)

    # Rebuilding the same batch after registration keeps suppression single-shot.
    rebuilt = build_result(temp_config, created_at="2026-01-12T00:00:00Z")
    assert sum(1 for finding in rebuilt.findings if finding.suppressed) == 1


def test_diff_does_not_report_suppression_as_disappeared_or_new_high():
    found_id = "fnd-stable"
    base = [{
        "finding_id": found_id, "severity": "high", "original_severity": "high",
        "effective_severity": "high", "suppressed": False, "rule_id": "R",
    }]
    head = [{
        "finding_id": found_id, "severity": "high", "original_severity": "high",
        "effective_severity": "info", "suppressed": True, "rule_id": "R",
    }]
    diff = diff_batches("b", "h", [], [], base, head)
    assert diff["counts"]["new_high_findings"] == 0
    assert diff["counts"]["disappeared_high_findings"] == 0
    assert diff["counts"]["newly_suppressed_findings"] == 1
    assert diff["counts"]["original_high_findings"] == 1
    assert diff["counts"]["effective_high_findings"] == 0
    assert diff["high_findings"]["new"] == []
    assert diff["high_findings"]["disappeared"] == []
    assert diff["severity"]["head"]["original_high"] == 1
    assert diff["severity"]["head"]["effective_high"] == 0


def test_ledger_finding_baseline_lookup_and_removal(temp_config):
    result = build_result(temp_config, created_at="2026-01-12T00:00:00Z")
    with Ledger(temp_config.ledger_path) as ledger:
        ledger.init_schema()
        ledger.save_batch(result)
        added = ledger.register_finding_baselines(
            [FindingBaseline(baseline_id="bl-1", rule_id="COST-AMP-001", origin="config")],
            created_at="2026-01-12T00:00:00Z",
        )
        assert added[0].origin == "config"
        assert ledger.get_finding_baseline("bl-1").rule_id == "COST-AMP-001"
        assert ledger.match_finding_baselines("COST-AMP-001", "other").baseline_id == "bl-1"
        assert ledger.match_finding_baselines("OTHER", "x") is None
        assert ledger.refresh_finding_suppression(result.batch_id) == 1
        assert ledger.remove_finding_baseline("bl-1") is True
        assert ledger.remove_finding_baseline("bl-1") is False
        assert ledger.refresh_finding_suppression(result.batch_id, []) == 0
        rows = ledger.list_findings(result.batch_id)
        assert all(row["suppressed"] == 0 for row in rows)
        assert all(row["effective_severity"] == row["severity"] for row in rows)


def test_stored_findings_keep_identity_after_suppression_rescan(temp_config):
    result = build_result(temp_config, created_at="2026-01-12T00:00:00Z")
    with Ledger(temp_config.ledger_path) as ledger:
        ledger.init_schema()
        ledger.save_batch(result)
        before = {row["finding_id"] for row in ledger.list_findings(result.batch_id)}
        ledger.add_finding_baseline(rule_id="COST-AMP-001", created_at="2026-01-12T01:00:00Z")
        ledger.refresh_finding_suppression(result.batch_id)
        after = {row["finding_id"] for row in ledger.list_findings(result.batch_id)}
        assert before == after
        summary = ledger.get_batch(result.batch_id)["summary"]
        assert summary["counts"]["suppressed_findings"] == 1
        assert summary["severity_counts"]["high"] == 9
        assert summary["effective_severity_counts"]["high"] == 8
    with open_readonly(temp_config.ledger_path) as ledger:
        assert len(ledger.list_findings(result.batch_id)) == len(result.findings)


def test_validate_rejects_baseline_without_selector(tmp_path, project_root):
    import yaml

    from slowquery_autopsy.config import ConfigError, load_config

    config_path = tmp_path / "pipeline.yaml"
    raw = yaml.safe_load((project_root / "configs/pipeline.yaml").read_text(encoding="utf-8"))
    raw["paths"]["root"] = str(project_root)
    raw["risk"]["baselines"] = [{"note": "missing selector"}]
    config_path.write_text(yaml.safe_dump(raw, allow_unicode=True), encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(config_path)


def test_config_baselines_do_not_change_batch_identity(temp_config):
    baseline_config = replace(
        temp_config,
        finding_baselines=[FindingBaseline(
            baseline_id="bl-amp", rule_id="COST-AMP-001", origin="config",
        )],
    )
    plain = build_result(temp_config, created_at="2026-01-12T00:00:00Z")
    suppressed = build_result(baseline_config, created_at="2026-01-12T00:00:00Z")
    assert plain.batch_id == suppressed.batch_id
    # Sorting uses the effective severity, so compare identity as a set.
    assert {f.finding_id for f in plain.findings} == {f.finding_id for f in suppressed.findings}
    assert {f.finding_id for f in suppressed.findings if f.suppressed} == {
        f.finding_id for f in suppressed.findings if f.rule_id == "COST-AMP-001"
    }


def test_config_declared_baselines_are_persisted_and_deduplicated(temp_config):
    from dataclasses import replace

    config = replace(
        temp_config,
        finding_baselines=[
            FindingBaseline(baseline_id="bl-amp", rule_id="COST-AMP-001", origin="config"),
        ],
    )
    result = build_result(config, created_at="2026-01-12T00:00:00Z")
    assert persist_result(config, result) is True
    assert persist_result(config, result) is False
    with Ledger(config.ledger_path) as ledger:
        registered = ledger.list_finding_baselines()
        assert [item.baseline_id for item in registered] == ["bl-amp"]
        assert registered[0].origin == "config"
        assert registered[0].created_at == "2026-01-12T00:00:00Z"


def test_register_and_remove_baseline_via_pipeline(temp_config):
    from slowquery_autopsy.pipeline import register_baseline, remove_baseline, stored_result

    result = build_result(temp_config, created_at="2026-01-12T00:00:00Z")
    assert persist_result(temp_config, result) is True
    baseline, affected = register_baseline(
        temp_config, rule_id="COST-AMP-001", note="known", created_at="2026-01-12T01:00:00Z",
    )
    assert baseline.baseline_id.startswith("bl-")
    assert affected == 1
    again, affected_again = register_baseline(
        temp_config, rule_id="COST-AMP-001", created_at="2026-01-12T02:00:00Z",
    )
    assert again.baseline_id == baseline.baseline_id
    assert affected_again == 1

    stored = stored_result(temp_config, result.batch_id)
    suppressed = [finding for finding in stored.findings if finding.suppressed]
    assert len(suppressed) == 1
    assert suppressed[0].finding_id == next(
        finding.finding_id for finding in result.findings if finding.rule_id == "COST-AMP-001"
    )
    assert suppressed[0].original_severity == "high"
    assert suppressed[0].effective_severity == "info"
    assert stored.finding_counts()["high"] == 9
    assert stored.effective_finding_counts()["high"] == 8

    assert remove_baseline(temp_config, baseline.baseline_id) is True
    stored = stored_result(temp_config, result.batch_id)
    assert all(not finding.suppressed for finding in stored.findings)
    assert stored.summary["counts"]["suppressed_findings"] == 0


def test_stored_report_rerender_matches_suppression(temp_config):
    from slowquery_autopsy.pipeline import register_baseline, stored_result
    from slowquery_autopsy.report import write_reports

    result = build_result(temp_config, created_at="2026-01-12T00:00:00Z")
    assert persist_result(temp_config, result) is True
    register_baseline(temp_config, rule_id="PLAN-FULLSCAN-001",
                      created_at="2026-01-12T01:00:00Z")
    stored = stored_result(temp_config, result.batch_id)
    written = write_reports(temp_config, stored)
    text = (temp_config.reports_dir / result.batch_id / "report.md").read_text(encoding="utf-8")
    assert written["markdown"].endswith("report.md")
    assert "基线抑制：2" in text
    assert "原始严重级别分布：critical=0 · high=9" in text
    assert "生效严重级别分布：critical=0 · high=7 · medium=5 · low=0 · info=2" in text
    payload = build_json_report(stored)
    assert payload["severity_counts"]["high"] == 9
    assert payload["effective_severity_counts"]["high"] == 7
    assert payload["effective_severity_counts"]["info"] == 2


def test_fail_on_severity_uses_effective_level(temp_config):
    config = replace(
        temp_config,
        fail_on_severity=["high"],
        finding_baselines=[FindingBaseline(
            baseline_id="bl-amp", rule_id="COST-AMP-001", origin="config",
        )],
    )
    result = build_result(config, created_at="2026-01-12T00:00:00Z")
    failing = [finding for finding in result.findings if config.finding_can_fail(finding)]
    # 9 original high findings, one suppressed by an explicit baseline id.
    assert len(failing) == 8
    assert config.severity_can_fail("high") is True
    assert config.severity_can_fail("info") is False
    assert all(not finding.suppressed for finding in failing)


def test_ledger_accepts_legacy_v1_findings_read_only(tmp_path, project_root):
    import sqlite3

    from slowquery_autopsy.store.ledger import open_readonly

    path = tmp_path / "legacy.sqlite3"
    conn = sqlite3.connect(path)
    conn.executescript("""
    CREATE TABLE batches (batch_id TEXT PRIMARY KEY, config_hash TEXT NOT NULL,
      input_hash TEXT NOT NULL, created_at TEXT NOT NULL, status TEXT NOT NULL,
      summary_json TEXT NOT NULL);
    CREATE TABLE findings (
      batch_id TEXT NOT NULL, finding_id TEXT NOT NULL, category TEXT NOT NULL,
      severity TEXT NOT NULL, cluster_id TEXT NOT NULL, query_id TEXT NOT NULL,
      rule_id TEXT NOT NULL, plan_file TEXT NOT NULL, node_path TEXT NOT NULL,
      title TEXT NOT NULL, description TEXT NOT NULL, evidence_json TEXT NOT NULL,
      recommendation TEXT NOT NULL, PRIMARY KEY (batch_id, finding_id));
    INSERT INTO batches VALUES ('b1', 'c', 'i', 't', 'complete', '{"counts": {}}');
    INSERT INTO findings VALUES ('b1', 'fnd-old', 'cost', 'high', 'fp', '', 'R','','',
      't', 'd', '{}', 'r');
    """)
    conn.commit()
    conn.close()
    with open_readonly(path) as ledger:
        row = ledger.get_finding("b1", "fnd-old")
        assert row["original_severity"] == "high"
        assert row["effective_severity"] == "high"
        assert row["suppressed"] == 0
        assert ledger.list_findings("b1", "high")[0]["finding_id"] == "fnd-old"


def test_migration_from_v1_adds_suppression_columns(tmp_path):
    import sqlite3

    from slowquery_autopsy.store.ledger import Ledger

    path = tmp_path / "legacy.sqlite3"
    conn = sqlite3.connect(path)
    conn.executescript("""
    CREATE TABLE findings (
      batch_id TEXT NOT NULL, finding_id TEXT NOT NULL, category TEXT NOT NULL,
      severity TEXT NOT NULL, cluster_id TEXT NOT NULL, query_id TEXT NOT NULL,
      rule_id TEXT NOT NULL, plan_file TEXT NOT NULL, node_path TEXT NOT NULL,
      title TEXT NOT NULL, description TEXT NOT NULL, evidence_json TEXT NOT NULL,
      recommendation TEXT NOT NULL, PRIMARY KEY (batch_id, finding_id));
    INSERT INTO findings VALUES ('b1', 'fnd-old', 'cost', 'high', 'fp', '', 'R','','',
      't', 'd', '{}', 'r');
    """)
    conn.commit()
    conn.close()
    with Ledger(path) as ledger:
        ledger.init_schema()
        columns = {row["name"] for row in ledger.conn.execute("PRAGMA table_info(findings)")}
        assert {"original_severity", "effective_severity", "suppressed"} <= columns
        row = ledger.get_finding("b1", "fnd-old")
        assert row["original_severity"] == "high"
        version = ledger.conn.execute(
            "SELECT value FROM schema_meta WHERE key = 'version'"
        ).fetchone()["value"]
        assert version == "2"
