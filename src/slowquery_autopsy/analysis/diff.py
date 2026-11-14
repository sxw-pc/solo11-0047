"""Batch-to-batch regression comparison.

Finding identity is the stable ``finding_id``.  Alerting ("high") is judged on
``effective_severity`` so baseline-suppressed findings never register as new
high/critical items, while the original severity distribution stays available
in ``counts`` for visibility.
"""

from __future__ import annotations

from typing import Any


ALERT_SEVERITIES = ("critical", "high")


def effective_severity(item: dict[str, Any]) -> str:
    """Read the alerting severity, tolerating rows written before suppression."""
    return str(item.get("effective_severity") or item.get("severity") or "info")


def original_severity(item: dict[str, Any]) -> str:
    return str(item.get("original_severity") or item.get("severity") or "info")


def _high_findings(findings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {
        item["finding_id"]: item
        for item in findings
        if effective_severity(item) in ALERT_SEVERITIES
    }


def _suppression_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {level: 0 for level in ("critical", "high", "medium", "low", "info")}
    suppressed = 0
    for item in findings:
        counts[original_severity(item)] = counts.get(original_severity(item), 0) + 1
        if item.get("suppressed"):
            suppressed += 1
    return {"original": counts, "suppressed": suppressed}


def _high_counts(findings: list[dict[str, Any]]) -> dict[str, Any]:
    original_high = sum(
        1 for item in findings if original_severity(item) in ALERT_SEVERITIES
    )
    effective_high = sum(
        1 for item in findings if effective_severity(item) in ALERT_SEVERITIES
    )
    return {
        "original_high": original_high,
        "effective_high": effective_high,
        "suppressed": sum(1 for item in findings if item.get("suppressed")),
        "total": len(findings),
    }


def _suppressed_ids(findings: list[dict[str, Any]]) -> set[str]:
    return {item["finding_id"] for item in findings if item.get("suppressed")}


def diff_batches(
    base_batch_id: str,
    head_batch_id: str,
    base_clusters: list[dict[str, Any]],
    head_clusters: list[dict[str, Any]],
    base_findings: list[dict[str, Any]],
    head_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    base_cluster_map = {item["cluster_id"]: item for item in base_clusters}
    head_cluster_map = {item["cluster_id"]: item for item in head_clusters}
    new_cluster_ids = sorted(set(head_cluster_map) - set(base_cluster_map))
    gone_cluster_ids = sorted(set(base_cluster_map) - set(head_cluster_map))
    base_high = _high_findings(base_findings)
    head_high = _high_findings(head_findings)
    new_high_ids = sorted(set(head_high) - set(base_high))
    # A finding that is present in head but suppressed was not "fixed": reporting
    # it as disappeared would mislead the operator and un-suppressing it later
    # would then look like a brand-new high finding.
    suppressed_transition_ids = {
        finding_id for finding_id in (set(base_high) - set(head_high))
        if finding_id in _suppressed_ids(head_findings)
    }
    gone_high_ids = sorted((set(base_high) - set(head_high)) - suppressed_transition_ids)
    return {
        "base_batch_id": base_batch_id,
        "head_batch_id": head_batch_id,
        "clusters": {
            "new": [
                {
                    "cluster_id": cluster_id,
                    "query_count": head_cluster_map[cluster_id]["query_count"],
                    "total_duration_ms": head_cluster_map[cluster_id]["total_duration_ms"],
                    "sample_sql": head_cluster_map[cluster_id]["sample_sql"],
                }
                for cluster_id in new_cluster_ids
            ],
            "disappeared": [
                {
                    "cluster_id": cluster_id,
                    "query_count": base_cluster_map[cluster_id]["query_count"],
                    "total_duration_ms": base_cluster_map[cluster_id]["total_duration_ms"],
                    "sample_sql": base_cluster_map[cluster_id]["sample_sql"],
                }
                for cluster_id in gone_cluster_ids
            ],
        },
        "high_findings": {
            "new": [head_high[finding_id] for finding_id in new_high_ids],
            "disappeared": [base_high[finding_id] for finding_id in gone_high_ids],
        },
        "suppressed_findings": {
            "base": _suppression_counts(base_findings),
            "head": _suppression_counts(head_findings),
            "newly_suppressed": [
                item for item in head_findings
                if item.get("suppressed")
                and item["finding_id"] not in _suppressed_ids(base_findings)
            ],
        },
        "severity": {
            "base": _high_counts(base_findings),
            "head": _high_counts(head_findings),
        },
        "counts": {
            "new_clusters": len(new_cluster_ids),
            "disappeared_clusters": len(gone_cluster_ids),
            "new_high_findings": len(new_high_ids),
            "disappeared_high_findings": len(gone_high_ids),
            "newly_suppressed_findings": sum(
                1 for item in head_findings
                if item.get("suppressed")
                and item["finding_id"] not in _suppressed_ids(base_findings)
            ),
            "suppressed_findings": len(_suppressed_ids(head_findings)),
            "original_high_findings": _high_counts(head_findings)["original_high"],
            "effective_high_findings": _high_counts(head_findings)["effective_high"],
        },
    }
