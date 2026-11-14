"""Row-level builders for the cross-batch fingerprint trace.

Kept apart from :mod:`slowquery_autopsy.analysis.trace` so the orchestration
module stays small and the per-batch payload shape is easy to test on its own.
"""

from __future__ import annotations

from typing import Any

from ..models import SEVERITY_ORDER

HIGH_SEVERITIES = ("critical", "high")

# Per-batch states.
OBSERVED = "observed"
ABSENT = "absent"
NOT_COLLECTED = "not_collected"

# Persistence statuses over the batches that actually covered the fingerprint.
STATUS_SINGLE = "single_batch"
STATUS_CONTINUOUS = "continuous"
STATUS_NEW = "new"
STATUS_REAPPEARED = "reappeared"
STATUS_DISAPPEARED = "disappeared"

STATUS_LEGEND = {
    STATUS_SINGLE: "只在一个已采集批次中出现，无法判断持续性。",
    STATUS_CONTINUOUS: "在所有已采集批次中连续出现。",
    STATUS_NEW: "首次出现后一直存在；之前的已采集批次中没有它。",
    STATUS_REAPPEARED: "出现过，至少一个已采集批次中消失，之后又重现。",
    STATUS_DISAPPEARED: "曾在已采集批次中出现，但在最近一个已采集批次中消失。",
}

TRACE_SCHEMA_VERSION = 1


def cluster_fingerprint(row: dict[str, Any]) -> str:
    return str(row.get("fingerprint") or row.get("cluster_id") or "")


def finding_key(row: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(row.get("rule_id", "")),
        str(row.get("plan_file", "")),
        str(row.get("node_path", "")),
    )


def key_text(key: tuple[str, str, str]) -> str:
    return "|".join(key)


def round_ms(value: Any) -> float:
    return round(float(value or 0.0), 3)


def status_from_flags(observed_flags: list[bool]) -> str:
    """Classify persistence using covered batches only (unknowns skipped)."""
    if not observed_flags:
        return STATUS_DISAPPEARED
    if len(observed_flags) == 1:
        return STATUS_SINGLE if observed_flags[0] else STATUS_DISAPPEARED
    if all(observed_flags):
        return STATUS_CONTINUOUS
    if not observed_flags[-1]:
        return STATUS_DISAPPEARED
    first = observed_flags.index(True)
    return STATUS_NEW if all(observed_flags[first + 1:]) else STATUS_REAPPEARED


def batch_record(batch_id: str, state: str, cluster: dict[str, Any] | None,
                 findings: list[dict[str, Any]],
                 missing_sources: list[str] | None = None,
                 coverage_known: bool = True) -> dict[str, Any]:
    severity_counts: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity", ""))
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    ordered = sorted(severity_counts,
                     key=lambda value: (SEVERITY_ORDER.get(value, 99), value))
    return {
        "batch_id": batch_id,
        "state": state,
        "query_count": int(cluster["query_count"]) if cluster else None,
        "p95_duration_ms": round_ms(cluster["p95_duration_ms"]) if cluster else None,
        "total_duration_ms": round_ms(cluster["total_duration_ms"]) if cluster else None,
        "high_finding_count": len(findings),
        "high_finding_keys": sorted({key_text(finding_key(item)) for item in findings}),
        "high_finding_ids": sorted({str(item.get("finding_id", "")) for item in findings}),
        "high_severity_counts": {key: severity_counts[key] for key in ordered},
        "coverage_known": coverage_known,
        "missing_sources": list(missing_sources or []),
    }


def finding_summary(rows: list[dict[str, Any]], order: dict[str, int]) -> dict[str, Any]:
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(finding_key(row), []).append(row)
    keys: list[dict[str, Any]] = []
    for key, items in grouped.items():
        items.sort(key=lambda item: (order.get(item["batch_id"], 0),
                                     str(item.get("finding_id", ""))))
        severities = sorted(
            {str(item.get("severity", "")) for item in items},
            key=lambda value: (SEVERITY_ORDER.get(value, 99), value),
        )
        finding_ids = [str(item.get("finding_id", "")) for item in items]
        batch_ids = sorted(
            {str(item["batch_id"]) for item in items},
            key=lambda batch_id: (order.get(batch_id, 0), batch_id),
        )
        keys.append({
            "key": key_text(key),
            "rule_id": key[0],
            "plan_file": key[1],
            "node_path": key[2],
            "category": str(items[0].get("category", "")),
            "title": str(items[0].get("title", "")),
            "severity": severities[0],
            "severities": severities,
            "first_batch": batch_ids[0],
            "last_batch": batch_ids[-1],
            "present_in_batches": batch_ids,
            "finding_ids": finding_ids,
            "finding_ids_changed": len(set(finding_ids)) > 1,
            "batches": [
                {
                    "batch_id": str(item["batch_id"]),
                    "finding_id": str(item.get("finding_id", "")),
                    "severity": str(item.get("severity", "")),
                }
                for item in items
            ],
        })
    keys.sort(key=lambda item: (order.get(item["first_batch"], 0), item["key"]))
    present = sorted(
        {str(item["batch_id"]) for item in rows},
        key=lambda batch_id: (order.get(batch_id, 0), batch_id),
    )
    return {
        "count": len(keys),
        "first_batch": present[0] if present else None,
        "last_batch": present[-1] if present else None,
        "present_in_batches": present,
        "keys": keys,
    }


def batch_metadata(batch_id: str, metadata: dict[str, Any] | None,
                   cluster_count: int, collected_sources: list[str]) -> dict[str, Any]:
    # ``created_at`` deliberately stays in the ledger: the trace document must
    # be reproducible when the same batch set is traced again.
    metadata = metadata or {}
    return {
        "batch_id": batch_id,
        "query_count": int(metadata.get("query_count") or 0),
        "cluster_count": cluster_count,
        "collected_sources": collected_sources,
    }
