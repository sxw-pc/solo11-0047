from __future__ import annotations

import pytest

from slowquery_autopsy.analysis.risk_rules import (
    build_findings,
    finding_id_for,
    high_finding_ids,
    rule_catalog,
)


def _candidate(**overrides):
    candidate = {
        "category": "cost", "rule_id": "COST-AMP-001", "severity": "high",
        "title": "amplification", "description": "amplified",
        "recommendation": "inspect", "cluster_id": "aaaaaaaaaaaaaaaa",
        "evidence": {"actual": 500.0, "threshold": 100, "cluster_id": "aaaaaaaaaaaaaaaa"},
        "query_id": "", "plan_file": "", "node_path": "",
    }
    candidate.update(overrides)
    return candidate


def test_finding_id_is_stable_and_deterministic():
    first = finding_id_for(_candidate())
    second = finding_id_for(_candidate())
    assert first == second
    assert first.startswith("fnd-") and len(first) == 20
    assert finding_id_for(_candidate(evidence={"actual": 900.0})) != first


def test_build_findings_deduplicates_and_sorts():
    low = _candidate(rule_id="Z-RULE", severity="low", cluster_id="bbbbbbbbbbbbbbbb")
    high = _candidate(severity="high", cluster_id="cccccccccccccccc")
    findings = build_findings([low, high, high])
    assert len(findings) == 2
    assert [finding.severity for finding in findings] == ["high", "low"]
    assert findings[0].finding_id == finding_id_for(high)


def test_overrides_disable_and_change_severity():
    candidate = _candidate()
    upgraded = build_findings([candidate], {"COST-AMP-001": {"severity": "critical"}})
    assert len(upgraded) == 1 and upgraded[0].severity == "critical"
    disabled = build_findings([candidate], {"COST-AMP-001": {"enabled": False}})
    assert disabled == []


def test_invalid_severity_and_high_ids():
    with pytest.raises(ValueError):
        build_findings([_candidate()], {"COST-AMP-001": {"severity": "urgent"}})
    findings = build_findings([
        _candidate(rule_id="A", severity="critical", evidence={"x": 1}),
        _candidate(rule_id="B", severity="medium", evidence={"x": 2}),
    ])
    assert len(high_finding_ids(findings)) == 1


def test_rule_catalog_merges_cost_and_plan_rules():
    catalog = rule_catalog(
        [{"id": "C1", "severity": "high", "title": "Cost", "metric": "amplification"}],
        [{"id": "P1", "severity": "medium", "title": "Plan", "type": "sort_temp_large"}],
        {"P1": {"enabled": False}},
    )
    assert [item["rule_id"] for item in catalog] == ["C1", "P1"]
    assert catalog[1]["enabled"] is False
