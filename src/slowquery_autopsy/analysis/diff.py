"""Batch-to-batch regression comparison."""

from __future__ import annotations

from typing import Any


def _high_findings(findings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {
        item["finding_id"]: item
        for item in findings
        if item.get("severity") in ("critical", "high")
    }


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
    gone_high_ids = sorted(set(base_high) - set(head_high))
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
        "counts": {
            "new_clusters": len(new_cluster_ids),
            "disappeared_clusters": len(gone_cluster_ids),
            "new_high_findings": len(new_high_ids),
            "disappeared_high_findings": len(gone_high_ids),
        },
    }
