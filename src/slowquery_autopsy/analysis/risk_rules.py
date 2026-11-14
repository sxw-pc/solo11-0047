"""Unified risk-rule engine: enablement, severity overrides and stable ids."""

from __future__ import annotations

from typing import Any, Iterable

from ..models import SEVERITY_ORDER, Finding, FindingBaseline, sort_findings
from ..util.hashing import stable_id


def _target(candidate: dict[str, Any]) -> dict[str, str]:
    return {
        "cluster_id": str(candidate.get("cluster_id", "")),
        "plan_file": str(candidate.get("plan_file", "")),
        "node_path": str(candidate.get("node_path", "")),
    }


def finding_id_for(candidate: dict[str, Any]) -> str:
    """Derive the identity of a finding.

    The id deliberately excludes severity, suppression state and baseline
    metadata.  Overrides and baseline suppression therefore cannot change the
    identity that batch diffing relies on.
    """
    return stable_id(
        "fnd",
        candidate["rule_id"],
        _target(candidate),
        candidate.get("evidence", {}),
    )


def _as_baseline(value: FindingBaseline | dict[str, Any]) -> FindingBaseline:
    if isinstance(value, FindingBaseline):
        return value
    return FindingBaseline.from_row(value)


def apply_finding_baselines(
    findings: Iterable[Finding],
    baselines: Iterable[FindingBaseline | dict[str, Any]] | None,
) -> list[Finding]:
    """Mark matching findings as suppressed without touching their severity.

    Suppression is a pure presentation/alerting state: ``finding.severity`` keeps
    its original rule value, while ``finding.effective_severity`` becomes
    ``info``.  Application is idempotent and never creates or removes findings,
    so finding ids stay stable across suppression.
    """
    prepared = [_as_baseline(item) for item in baselines or []]
    result: list[Finding] = []
    for finding in findings:
        if not finding.suppressed:
            for baseline in prepared:
                if baseline.matches(finding):
                    finding.suppressed = True
                    finding.baseline_id = baseline.baseline_id
                    finding.suppression_source = baseline.origin or "ledger"
                    finding.suppression_reason = baseline.describe()
                    break
        result.append(finding)
    return sort_findings(result)


def build_findings(
    candidates: Iterable[dict[str, Any]],
    overrides: dict[str, dict[str, Any]] | None = None,
    baselines: Iterable[FindingBaseline | dict[str, Any]] | None = None,
) -> list[Finding]:
    overrides = overrides or {}
    findings: list[Finding] = []
    seen: set[str] = set()
    for candidate in candidates:
        rule_id = str(candidate["rule_id"])
        override = overrides.get(rule_id, {})
        if override.get("enabled", candidate.get("enabled", True)) is False:
            continue
        severity = str(override.get("severity", candidate["severity"]))
        if severity not in SEVERITY_ORDER:
            raise ValueError(f"rule {rule_id}: invalid severity {severity!r}")
        candidate = dict(candidate)
        candidate["severity"] = severity
        finding_id = finding_id_for(candidate)
        if finding_id in seen:
            continue
        seen.add(finding_id)
        findings.append(Finding(
            finding_id=finding_id,
            category=str(candidate.get("category", "rule")),
            severity=severity,
            rule_id=rule_id,
            title=str(candidate.get("title", rule_id)),
            description=str(candidate.get("description", "")),
            evidence=dict(candidate.get("evidence", {})),
            recommendation=str(candidate.get("recommendation", "")),
            cluster_id=str(candidate.get("cluster_id", "")),
            query_id=str(candidate.get("query_id", "")),
            plan_file=str(candidate.get("plan_file", "")),
            node_path=str(candidate.get("node_path", "")),
        ))
    return apply_finding_baselines(findings, baselines)


def rule_catalog(
    cost_rules: list[dict[str, Any]],
    plan_rules: list[dict[str, Any]],
    overrides: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    overrides = overrides or {}
    catalog: list[dict[str, Any]] = []
    for source, rules in (("cost", cost_rules), ("plan", plan_rules)):
        for rule in rules:
            override = overrides.get(rule["id"], {})
            catalog.append({
                "rule_id": rule["id"],
                "category": source,
                "enabled": bool(override.get("enabled", rule.get("enabled", True))),
                "severity": str(override.get("severity", rule["severity"])),
                "title": rule.get("title", rule["id"]),
                "description": rule.get("description", ""),
                "recommendation": rule.get("recommendation", ""),
                "type": rule.get("type", rule.get("metric", "")),
            })
    catalog.sort(key=lambda item: (item["category"], item["rule_id"]))
    return catalog


def high_finding_ids(findings: Iterable[Finding]) -> set[str]:
    """Ids that still alert after baseline suppression is applied."""
    return {finding.finding_id for finding in findings
            if finding.effective_severity in ("critical", "high")}
