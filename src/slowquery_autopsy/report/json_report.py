"""Stable, diff-friendly JSON report."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import AnalysisResult


def _query_payload(result: AnalysisResult) -> list[dict[str, Any]]:
    return [query.as_dict() for query in result.queries]


def _duplicate_payload(result: AnalysisResult) -> list[dict[str, Any]]:
    """Flattened audit trail: every folded row keeps its file and line number."""
    items: list[dict[str, Any]] = []
    for query in result.queries:
        for source in query.redundant_sources:
            items.append({
                "representative_query_id": query.query_id,
                "event_id": query.event_id,
                **source,
            })
    items.sort(key=lambda item: (item["source_file"], item["line_no"], item["representative_query_id"]))
    return items


def _plan_payload(result: AnalysisResult) -> list[dict[str, Any]]:
    plans = []
    for plan in result.plans:
        item = plan.as_dict()
        item["linked"] = bool(plan.linked_cluster_id and not plan.error)
        plans.append(item)
    return plans


def build_json_report(result: AnalysisResult) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "report_type": "slowquery-autopsy-batch",
        "metadata": {
            "batch_id": result.batch_id,
            "config_hash": result.config_hash,
            "input_hash": result.input_hash,
            "project": result.summary.get("project", "slowquery-autopsy"),
        },
        "summary": result.summary,
        "file_stats": [stat.as_dict() for stat in result.file_stats],
        "clusters": [cluster.as_dict() for cluster in result.clusters],
        "queries": _query_payload(result),
        "duplicate_sources": _duplicate_payload(result),
        "plans": _plan_payload(result),
        "findings": [finding.as_dict() for finding in result.findings],
        "unparsed": [item.as_dict() for item in result.unparsed],
        "excluded_statements": result.excluded,
    }


def write_json_report(result: AnalysisResult, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = build_json_report(result)
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


def load_json_report(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))
