"""Unified risk-rule engine: enablement, severity overrides and stable ids."""

from __future__ import annotations

from typing import Any, Iterable

from ..models import SEVERITY_ORDER, Finding, sort_findings
from ..util.hashing import stable_id


def _target(candidate: dict[str, Any]) -> dict[str, str]:
    return {
        "cluster_id": str(candidate.get("cluster_id", "")),
        "plan_file": str(candidate.get("plan_file", "")),
        "node_path": str(candidate.get("node_path", "")),
    }


def finding_id_for(candidate: dict[str, Any]) -> str:
    return stable_id(
        "fnd",
        candidate["rule_id"],
        _target(candidate),
        candidate.get("evidence", {}),
    )


def build_findings(
    candidates: Iterable[dict[str, Any]],
    overrides: dict[str, dict[str, Any]] | None = None,
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
    return sort_findings(findings)


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
            catalog_entry = {
                "rule_id": rule["id"],
                "category": source,
                "enabled": bool(override.get("enabled", rule.get("enabled", True))),
                "severity": str(override.get("severity", rule["severity"])),
                "title": rule.get("title", rule["id"]),
                "description": rule.get("description", ""),
                "recommendation": rule.get("recommendation", ""),
                "type": rule.get("type", rule.get("metric", "")),
            }
            if source == "cost":
                catalog_entry["basis"] = str(rule.get("basis", "absolute"))
                catalog_entry["operator"] = rule.get("operator", "")
                catalog_entry["threshold"] = rule.get("threshold", "")
            catalog.append(catalog_entry)
    catalog.sort(key=lambda item: (item["category"], item["rule_id"]))
    return catalog


def high_finding_ids(findings: Iterable[Finding]) -> set[str]:
    return {finding.finding_id for finding in findings if finding.severity in ("critical", "high")}
