from __future__ import annotations

import shutil

import pytest
import yaml

from slowquery_autopsy.config import ConfigError, load_config
from slowquery_autopsy.pipeline import build_result


def _project(tmp_path, project_root):
    shutil.copytree(project_root / "fixtures", tmp_path / "fixtures")
    shutil.copytree(project_root / "configs", tmp_path / "configs")
    return tmp_path / "configs/pipeline.yaml"


def _rewrite_rules(config_path, rules):
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    raw["cost"]["rules"] = rules
    config_path.write_text(yaml.safe_dump(raw, sort_keys=False, allow_unicode=True),
                           encoding="utf-8")


BASE_RULE = {
    "id": "T-REL",
    "title": "relative",
    "metric": "total_duration_ms",
    "operator": "gte",
    "threshold": 0.30,
    "min_count": 1,
    "severity": "medium",
    "basis": "batch_share",
    "description": "{actual} / {baseline_value} = {relative_value}",
    "recommendation": "inspect",
}


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"basis": "batch_footprint"}, "unsupported"),
        ({"operator": "lt"}, "requires gt or gte"),
        ({"threshold": 1.5}, "fraction in (0, 1]"),
        ({"threshold": 0}, "fraction in (0, 1]"),
        ({"metric": "avg_duration_ms"}, "additive metric"),
        ({"metric": "no_such_metric"}, "unsupported cost metric"),
        ({"threshold": "abc"}, "expected a number"),
    ],
)
def test_config_rejects_meaningless_relative_rules(tmp_path, project_root, mutation, message):
    config_path = _project(tmp_path, project_root)
    _rewrite_rules(config_path, [dict(BASE_RULE, **mutation)])
    with pytest.raises(ConfigError) as excinfo:
        load_config(config_path)
    assert message in str(excinfo.value)


def test_config_rejects_median_threshold_not_above_one(tmp_path, project_root):
    config_path = _project(tmp_path, project_root)
    rule = dict(BASE_RULE, basis="batch_median", threshold=1.0)
    _rewrite_rules(config_path, [rule])
    with pytest.raises(ConfigError, match="multiple greater than 1"):
        load_config(config_path)


def test_config_accepts_relative_rules_and_keeps_absolute_ones(tmp_path, project_root):
    config_path = _project(tmp_path, project_root)
    rules = [
        {"id": "T-ABS", "title": "abs", "metric": "amplification", "operator": "gt",
         "threshold": 100, "severity": "high"},
        {"id": "T-SHARE", "title": "share", "metric": "total_duration_ms",
         "operator": "gte", "threshold": 0.3, "severity": "medium", "basis": "batch_share"},
        {"id": "T-MEDIAN", "title": "median", "metric": "total_duration_ms",
         "operator": "gte", "threshold": 2.0, "severity": "medium", "basis": "batch_median"},
    ]
    _rewrite_rules(config_path, rules)
    config = load_config(config_path)
    assert [rule["id"] for rule in config.cost_rules] == ["T-ABS", "T-SHARE", "T-MEDIAN"]
    # The rule catalog carries the basis so a DBA can tell the two apart.
    result = build_result(config, created_at="2026-01-11T00:00:00Z")
    catalog = {item["rule_id"]: item for item in result.summary["rule_catalog"]}
    assert catalog["T-ABS"]["basis"] == "absolute"
    assert catalog["T-SHARE"]["basis"] == "batch_share"
    assert catalog["T-MEDIAN"]["basis"] == "batch_median"


def test_project_defaults_expose_absolute_and_relative_evidence(config):
    result = build_result(config, created_at="2026-01-11T00:00:00Z")
    relative = [f for f in result.findings
                if f.rule_id in ("COST-SHARE-001", "COST-MEDIAN-001")]
    assert {f.rule_id for f in relative} == {"COST-SHARE-001", "COST-MEDIAN-001"}
    for finding in relative:
        evidence = finding.evidence
        # Absolute value plus the distributional comparison, for DBA review.
        assert "actual" in evidence and "threshold" in evidence
        assert "relative_value" in evidence and "baseline_value" in evidence
        assert evidence["batch_clusters"] == len(result.clusters)
    top = result.clusters[0]
    share = next(f for f in relative if f.rule_id == "COST-SHARE-001")
    assert share.cluster_id == top.fingerprint
    assert share.evidence["actual"] == pytest.approx(top.total_duration_ms, abs=1e-3)
    assert share.evidence["relative_value"] == pytest.approx(top.duration_share, abs=1e-6)
