"""End-to-end offline analysis orchestration."""

from __future__ import annotations

import re
import sqlite3
from typing import Any

from .analysis.cost import attach_query_costs, evaluate_cost
from .analysis.fingerprint import build_clusters, fingerprint_id
from .analysis.normalize import normalize_sql
from .analysis.plan_audit import audit_plans
from .analysis.risk_rules import build_findings, rule_catalog
from .config import AppConfig
from .ingest.log_parser import parse_inputs
from .ingest.plan_parser import load_plans
from .ingest.schema_loader import load_schema
from .models import (
    AnalysisResult,
    Cluster,
    Finding,
    FindingBaseline,
    LogFileStat,
    PlanDocument,
    PlanNode,
    SlowQuery,
    UnparsedLine,
)
from .store.ledger import Ledger
from .util.hashing import combined_file_hash, short_hash, stable_id
from .util.timefmt import utc_now_iso


def _exclusion(sql: str, prefixes: list[str]) -> tuple[bool, str]:
    match = re.match(r"\s*([A-Za-z]+)", sql)
    word = match.group(1).upper() if match else ""
    if word in prefixes:
        return True, f"excluded statement prefix: {word}"
    return False, ""


def attach_fingerprints(queries: list[SlowQuery], config: AppConfig) -> None:
    for query in queries:
        normalized = normalize_sql(query.sql, config.fingerprint_rules)
        query.normalized_sql = normalized.text
        query.tokens = normalized.tokens
        query.fingerprint = fingerprint_id(normalized.text, normalized.tokens)
        query.excluded, query.exclusion_reason = _exclusion(query.sql, config.excluded_prefixes)
        query.cluster_id = "" if query.excluded else query.fingerprint
        query.query_id = stable_id(
            "q", query.source_file, query.line_no, query.fingerprint
        )


def _input_hash(config: AppConfig) -> str:
    items = [(spec.display_path, spec.log_format, spec.path) for spec in config.inputs]
    for path in config.plan_files:
        items.append((config.display(path), "plan", path))
    items.append((config.display(config.schema_path), "schema", config.schema_path))
    return combined_file_hash(items)


def _excluded_payload(queries: list[SlowQuery]) -> list[dict[str, Any]]:
    items = []
    for query in queries:
        if not query.excluded:
            continue
        items.append({
            "query_id": query.query_id,
            "source_file": query.source_file,
            "line_no": query.line_no,
            "prefix": query.exclusion_reason.rsplit(":", 1)[-1].strip(),
            "sql": query.sql,
            "duration_ms": round(query.duration_ms, 3),
        })
    items.sort(key=lambda item: (item["source_file"], item["line_no"]))
    return items


def _unassociated_payload(plans: list[Any]) -> list[dict[str, Any]]:
    items = []
    for plan in plans:
        if plan.linked_cluster_id and not plan.error:
            continue
        items.append({
            "source_file": plan.source_file,
            "plan_id": plan.plan_id,
            "fingerprint": plan.fingerprint,
            "node_count": plan.node_count,
            "reason": plan.error or "fingerprint did not match any cluster",
        })
    items.sort(key=lambda item: item["source_file"])
    return items


def _load_persisted_baselines(config: AppConfig) -> list[FindingBaseline]:
    """Read registered baselines from the ledger, if it exists and has the table."""
    if not config.ledger_path.is_file():
        return []
    try:
        with Ledger(config.ledger_path, readonly=True) as ledger:
            if "finding_baselines" not in ledger.table_names():
                return []
            return ledger.list_finding_baselines()
    except (sqlite3.Error, OSError):
        return []


def stored_result(config: AppConfig, batch_id: str) -> AnalysisResult:
    """Rehydrate a persisted batch so its report can be re-rendered after suppression."""
    with Ledger(config.ledger_path, readonly=True) as ledger:
        batch = ledger.get_batch(batch_id)
        if not batch:
            raise ValueError(f"unknown batch: {batch_id}")
        summary = dict(batch["summary"])
        summary.setdefault("severity_counts", {
            level: 0 for level in ("critical", "high", "medium", "low", "info")
        })
        summary.setdefault("effective_severity_counts", dict(summary["severity_counts"]))
        summary.setdefault("counts", {})
        summary.setdefault("finding_baselines", {"count": 0, "items": [], "suppressed_findings": 0})
        summary.setdefault("unparsed_preview", 10)
        summary.setdefault("top_clusters", 8)
        findings = [_stored_finding(row) for row in ledger.list_findings(batch_id)]
        clusters = [_stored_cluster(row) for row in ledger.list_clusters(batch_id)]
        queries = [_stored_query(row) for row in ledger.list_queries(batch_id)]
        file_stats = [
            LogFileStat(
                path=row["path"], log_format=row["log_format"], encoding=row["encoding"],
                sha256=row["sha256"], line_count=row["line_count"],
                parsed_count=row["parsed_count"], unparsed_count=row["unparsed_count"],
                excluded_count=row["excluded_count"],
            )
            for row in ledger.list_log_files(batch_id)
        ]
        unparsed = [
            UnparsedLine(file=row["file_path"], line_no=row["line_no"], text=row["text"],
                         reason=row["reason"])
            for row in ledger.list_unparsed(batch_id)
        ]
        plans = [_stored_plan(ledger, batch_id, row) for row in ledger.list_plans(batch_id)]
    return AnalysisResult(
        batch_id=batch_id,
        config_hash=batch["config_hash"],
        input_hash=batch["input_hash"],
        created_at=batch["created_at"],
        queries=queries,
        clusters=clusters,
        findings=findings,
        plans=plans,
        unparsed=unparsed,
        file_stats=file_stats,
        excluded=summary.get("excluded_statements", []),
        summary=summary,
    )


def _stored_finding(row: dict[str, Any]) -> Finding:
    return Finding(
        finding_id=row["finding_id"], category=row["category"], severity=row["severity"],
        rule_id=row["rule_id"], title=row["title"], description=row["description"],
        evidence=row.get("evidence", {}), recommendation=row["recommendation"],
        cluster_id=row["cluster_id"], query_id=row["query_id"], plan_file=row["plan_file"],
        node_path=row["node_path"], suppressed=bool(row.get("suppressed", 0)),
        baseline_id=row.get("baseline_id", "") or "",
        suppression_source=row.get("suppression_source", "") or "",
        suppression_reason=row.get("suppression_reason", "") or "",
    )


def _stored_cluster(row: dict[str, Any]) -> Cluster:
    return Cluster(
        fingerprint=row["cluster_id"], sample_sql=row["sample_sql"],
        normalized_sql=row["normalized_sql"], query_count=row["query_count"],
        total_duration_ms=row["total_duration_ms"], avg_duration_ms=row["avg_duration_ms"],
        min_duration_ms=row["min_duration_ms"], max_duration_ms=row["max_duration_ms"],
        p50_duration_ms=row["p50_duration_ms"], p95_duration_ms=row["p95_duration_ms"],
        total_rows_examined=row["total_rows_examined"], total_rows_sent=row["total_rows_sent"],
        amplification=row["amplification"], lock_ratio=row["lock_ratio"],
        duration_share=row["duration_share"],
        projected_ms_per_1k_calls=row["projected_ms_per_1k_calls"], cost=row.get("cost", {}),
    )


def _stored_query(row: dict[str, Any]) -> SlowQuery:
    return SlowQuery(
        source_file=row["source_file"], line_no=row["line_no"], timestamp=row["timestamp"],
        duration_ms=row["duration_ms"], lock_time_ms=row["lock_time_ms"],
        rows_sent=row["rows_sent"], rows_examined=row["rows_examined"],
        user=row["user_name"], client=row["client"], database=row["database_name"],
        sql=row["sql_text"], log_format=row["log_format"], query_id=row["query_id"],
        normalized_sql=row["normalized_sql"], fingerprint=row["fingerprint"],
        cluster_id=row["cluster_id"], excluded=bool(row["excluded"]),
        exclusion_reason=row["exclusion_reason"], cost=row.get("cost", {}),
    )


def _stored_plan(ledger: Ledger, batch_id: str, row: dict[str, Any]) -> PlanDocument:
    nodes = [
        PlanNode(
            path=node["path"], operation=node["operation"], depth=node["depth"],
            table_name=node.get("table_name", ""), access_type=node.get("access_type", ""),
            rows=node.get("rows", 0), key_name=node.get("key_name", ""),
            condition=node.get("condition", ""),
        )
        for node in ledger.get_plan(batch_id, row["plan_id"])["nodes"]
    ]
    return PlanDocument(
        plan_id=row["plan_id"], source_file=row["source_file"],
        plan_format=row["plan_format"], fingerprint=row["fingerprint"],
        linked_cluster_id=row["linked_cluster_id"], nodes=nodes, error=row["error"],
    )


def resolve_baselines(config: AppConfig) -> list[FindingBaseline]:
    """Merge config-declared and ledger-registered baselines by stable id.

    Config entries win on identical ids so a reviewed pipeline config is the
    authoritative description, but ledger registrations survive config drift.
    """
    merged: dict[str, FindingBaseline] = {
        baseline.baseline_id: baseline
        for baseline in _load_persisted_baselines(config)
    }
    for baseline in config.finding_baselines:
        merged[baseline.baseline_id] = baseline
    return sorted(merged.values(), key=lambda item: (item.rule_id, item.fingerprint, item.baseline_id))


def build_result(config: AppConfig, created_at: str | None = None) -> AnalysisResult:
    parsed = parse_inputs(config)
    attach_fingerprints(parsed.queries, config)
    attach_query_costs(parsed.queries)
    clusters = build_clusters(parsed.queries)
    schema = load_schema(config.schema_path)
    plans = load_plans(config, {cluster.fingerprint for cluster in clusters})
    candidates = evaluate_cost(clusters, config.cost_rules)
    candidates.extend(audit_plans(plans, config.plan_rules.get("rules", []), schema))
    baselines = resolve_baselines(config)
    findings = build_findings(candidates, config.risk_overrides, baselines)
    excluded = _excluded_payload(parsed.queries)
    unassociated = _unassociated_payload(plans)
    excluded_by_file: dict[str, int] = {}
    for item in excluded:
        excluded_by_file[item["source_file"]] = excluded_by_file.get(item["source_file"], 0) + 1
    for stat in parsed.file_stats:
        stat.excluded_count = excluded_by_file.get(stat.path, 0)
    input_hash = _input_hash(config)
    config_hash = config.config_fingerprint()
    batch_id = stable_id("batch", config_hash, input_hash, length=20)
    included = [query for query in parsed.queries if not query.excluded]
    severity_counts = {level: 0 for level in ("critical", "high", "medium", "low", "info")}
    effective_counts = {level: 0 for level in ("critical", "high", "medium", "low", "info")}
    suppressed = 0
    for finding in findings:
        severity_counts[finding.original_severity] = severity_counts.get(
            finding.original_severity, 0) + 1
        effective_counts[finding.effective_severity] = effective_counts.get(
            finding.effective_severity, 0) + 1
        if finding.suppressed:
            suppressed += 1
    summary = {
        "batch_id": batch_id,
        "project": config.raw.get("project", {}).get("name", "slowquery-autopsy"),
        "counts": {
            "input_files": len(config.inputs),
            "queries": len(parsed.queries),
            "analyzed_queries": len(included),
            "excluded_queries": len(excluded),
            "clusters": len(clusters),
            "plans": len(plans),
            "plan_nodes": sum(plan.node_count for plan in plans),
            "unassociated_plans": len(unassociated),
            "findings": len(findings),
            "high_findings": effective_counts.get("high", 0) + effective_counts.get("critical", 0),
            "suppressed_findings": suppressed,
            "unparsed_lines": len(parsed.unparsed),
        },
        "durations": {
            "all_queries_total_ms": round(sum(query.duration_ms for query in parsed.queries), 3),
            "analyzed_total_ms": round(sum(query.duration_ms for query in included), 3),
            "max_query_ms": round(max((query.duration_ms for query in parsed.queries), default=0.0), 3),
        },
        "severity_counts": severity_counts,
        "effective_severity_counts": effective_counts,
        "finding_baselines": {
            "count": len(baselines),
            "suppressed_findings": suppressed,
            "items": [baseline.as_dict() for baseline in baselines],
        },
        "excluded_prefixes": config.excluded_prefixes,
        "excluded_statements": excluded,
        "unassociated_plans": unassociated,
        "normalization_rules": [
            rule.get("id") for rule in config.fingerprint_rules.get("rules", [])
            if rule.get("enabled", True)
        ],
        "quantile_method": config.quantile_method,
        "rule_catalog": rule_catalog(config.cost_rules, config.plan_rules.get("rules", []),
                                     config.risk_overrides),
        "plan_links": dict(sorted(config.plan_links.items())),
        "top_clusters": int(config.report_options.get("top_clusters", 8)),
        "unparsed_preview": int(config.report_options.get("unparsed_preview", 10)),
        "excluded_preview": int(config.report_options.get("excluded_preview", 10)),
        "report_formats": list(config.report_options.get("formats", [])),
        "fingerprint_rules_sha256": short_hash(
            config.source_hashes.get(config.display(config.fingerprint_rules_path), ""), 16
        ),
    }
    return AnalysisResult(
        batch_id=batch_id,
        config_hash=config_hash,
        input_hash=input_hash,
        created_at=created_at or utc_now_iso(),
        queries=parsed.queries,
        clusters=clusters,
        findings=findings,
        plans=plans,
        unparsed=parsed.unparsed,
        file_stats=parsed.file_stats,
        excluded=excluded,
        summary=summary,
    )


def persist_result(config: AppConfig, result: AnalysisResult) -> bool:
    with Ledger(config.ledger_path) as ledger:
        ledger.init_schema()
        if config.finding_baselines:
            ledger.register_finding_baselines(
                config.finding_baselines, created_at=result.created_at,
            )
        inserted = ledger.save_batch(result)
        # Keep the stored batch aligned with the full (config + ledger) baseline
        # set even when the batch id already existed. Only suppression metadata
        # changes; finding ids and original severities stay untouched.
        ledger.refresh_finding_suppression(result.batch_id)
        return inserted


def run(config: AppConfig, created_at: str | None = None,
        persist: bool = True) -> tuple[AnalysisResult, bool]:
    built_at = created_at or utc_now_iso()
    result = build_result(config, created_at=built_at)
    inserted = persist_result(config, result) if persist else False
    return result, inserted


def register_baseline(
    config: AppConfig,
    *,
    rule_id: str = "",
    fingerprint: str = "",
    note: str = "",
    created_at: str | None = None,
) -> tuple[FindingBaseline, int]:
    """Register a finding baseline and re-apply it to already stored batches.

    Returns the registered baseline and how many findings across the ledger are
    now suppressed by it. Registration is idempotent: the selector is keyed by
    a stable baseline id, so repeating the same command adds no duplicate rows.
    """
    baseline = FindingBaseline(
        baseline_id=FindingBaseline.auto_id(rule_id.strip(), fingerprint.strip()),
        rule_id=rule_id.strip(),
        fingerprint=fingerprint.strip(),
        note=note,
        source_batch_id="",
        created_at=created_at or utc_now_iso(),
        origin="ledger",
    )
    affected = 0
    with Ledger(config.ledger_path) as ledger:
        ledger.init_schema()
        stored = ledger.add_finding_baseline(
            rule_id=baseline.rule_id,
            fingerprint=baseline.fingerprint,
            baseline_id=baseline.baseline_id,
            note=baseline.note,
            created_at=baseline.created_at,
            origin=baseline.origin,
        )
        baselines = ledger.list_finding_baselines()
        for batch in ledger.list_batches():
            affected += ledger.refresh_finding_suppression(batch["batch_id"], baselines)
    return stored, affected


def list_finding_baselines(config: AppConfig) -> list[FindingBaseline]:
    if not config.ledger_path.is_file():
        return []
    with Ledger(config.ledger_path, readonly=True) as ledger:
        if "finding_baselines" not in ledger.table_names():
            return []
        return ledger.list_finding_baselines()


def remove_baseline(config: AppConfig, baseline_id: str) -> bool:
    with Ledger(config.ledger_path) as ledger:
        ledger.init_schema()
        removed = ledger.remove_finding_baseline(baseline_id)
        if removed:
            baselines = ledger.list_finding_baselines()
            for batch in ledger.list_batches():
                ledger.refresh_finding_suppression(batch["batch_id"], baselines)
        return removed


def validate_configuration(config: AppConfig) -> list[str]:
    errors: list[str] = []
    if not config.schema_path.is_file():
        errors.append(f"{config.display(config.schema_path)}: schema snapshot is missing")
    for plan_path in config.plan_files:
        if not plan_path.is_file():
            errors.append(f"{config.display(plan_path)}: plan file is missing")
    try:
        parsed = parse_inputs(config)
    except (OSError, UnicodeError, ValueError) as exc:
        errors.append(str(exc))
        return errors
    try:
        attach_fingerprints(parsed.queries, config)
    except (ValueError, re.error) as exc:
        errors.append(f"fingerprint rules: {exc}")
    try:
        schema = load_schema(config.schema_path)
    except ValueError as exc:
        errors.append(str(exc))
        return errors
    plans = load_plans(config, {query.cluster_id for query in parsed.queries if query.cluster_id})
    for plan in plans:
        if plan.error:
            errors.append(f"{plan.source_file}: {plan.error}")
    try:
        audit_plans(plans, config.plan_rules.get("rules", []), schema)
    except ValueError as exc:
        errors.append(f"plan rules: {exc}")
    return errors
