"""Core, dependency-free data models for the analysis pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from .util.hashing import stable_id


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class UnparsedLine:
    file: str
    line_no: int
    text: str
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line_no": self.line_no,
            "text": self.text,
            "reason": self.reason,
        }


@dataclass
class SlowQuery:
    source_file: str
    line_no: int
    timestamp: str
    duration_ms: float
    lock_time_ms: float
    rows_sent: int
    rows_examined: int
    user: str
    client: str
    database: str
    sql: str
    log_format: str
    query_id: str = ""
    normalized_sql: str = ""
    tokens: list[str] = field(default_factory=list)
    fingerprint: str = ""
    cluster_id: str = ""
    excluded: bool = False
    exclusion_reason: str = ""
    cost: dict[str, Any] = field(default_factory=dict)

    @property
    def amplification(self) -> float:
        return self.rows_examined / max(self.rows_sent, 1)

    @property
    def lock_ratio(self) -> float:
        return self.lock_time_ms / self.duration_ms if self.duration_ms > 0 else 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "query_id": self.query_id,
            "source_file": self.source_file,
            "line_no": self.line_no,
            "timestamp": self.timestamp,
            "duration_ms": round(self.duration_ms, 3),
            "lock_time_ms": round(self.lock_time_ms, 3),
            "rows_sent": self.rows_sent,
            "rows_examined": self.rows_examined,
            "user": self.user,
            "client": self.client,
            "database": self.database,
            "log_format": self.log_format,
            "sql": self.sql,
            "normalized_sql": self.normalized_sql,
            "fingerprint": self.fingerprint,
            "cluster_id": self.cluster_id,
            "excluded": self.excluded,
            "exclusion_reason": self.exclusion_reason,
            "cost": self.cost,
        }


@dataclass
class Cluster:
    fingerprint: str
    sample_sql: str
    normalized_sql: str
    query_count: int
    total_duration_ms: float
    avg_duration_ms: float
    min_duration_ms: float
    max_duration_ms: float
    p50_duration_ms: float
    p95_duration_ms: float
    total_rows_examined: int
    total_rows_sent: int
    amplification: float
    lock_ratio: float
    duration_share: float
    projected_ms_per_1k_calls: float
    query_ids: list[str] = field(default_factory=list)
    cost: dict[str, Any] = field(default_factory=dict)

    @property
    def cluster_id(self) -> str:
        return self.fingerprint

    def as_dict(self) -> dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "fingerprint": self.fingerprint,
            "sample_sql": self.sample_sql,
            "normalized_sql": self.normalized_sql,
            "query_count": self.query_count,
            "total_duration_ms": round(self.total_duration_ms, 3),
            "avg_duration_ms": round(self.avg_duration_ms, 3),
            "min_duration_ms": round(self.min_duration_ms, 3),
            "max_duration_ms": round(self.max_duration_ms, 3),
            "p50_duration_ms": round(self.p50_duration_ms, 3),
            "p95_duration_ms": round(self.p95_duration_ms, 3),
            "total_rows_examined": self.total_rows_examined,
            "total_rows_sent": self.total_rows_sent,
            "amplification": round(self.amplification, 3),
            "lock_ratio": round(self.lock_ratio, 6),
            "duration_share": round(self.duration_share, 6),
            "projected_ms_per_1k_calls": round(self.projected_ms_per_1k_calls, 3),
            "query_ids": self.query_ids,
            "cost": self.cost,
        }


@dataclass
class PlanNode:
    path: str
    operation: str
    depth: int
    table_name: str = ""
    access_type: str = ""
    rows: int = 0
    key_name: str = ""
    condition: str = ""
    parent_path: str = ""
    in_nested_loop: bool = False
    nested_loop_position: int = -1
    using_filesort: bool = False
    using_temporary: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "operation": self.operation,
            "depth": self.depth,
            "table_name": self.table_name,
            "access_type": self.access_type,
            "rows": self.rows,
            "key_name": self.key_name,
            "condition": self.condition,
            "parent_path": self.parent_path,
            "in_nested_loop": self.in_nested_loop,
            "nested_loop_position": self.nested_loop_position,
            "using_filesort": self.using_filesort,
            "using_temporary": self.using_temporary,
            "extra": self.extra,
        }


@dataclass
class PlanDocument:
    plan_id: str
    source_file: str
    plan_format: str
    fingerprint: str = ""
    linked_cluster_id: str = ""
    nodes: list[PlanNode] = field(default_factory=list)
    error: str = ""

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    def as_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "source_file": self.source_file,
            "plan_format": self.plan_format,
            "fingerprint": self.fingerprint,
            "linked_cluster_id": self.linked_cluster_id,
            "node_count": self.node_count,
            "nodes": [node.as_dict() for node in self.nodes],
            "error": self.error,
        }


@dataclass
class Finding:
    finding_id: str
    category: str
    severity: str
    rule_id: str
    title: str
    description: str
    evidence: dict[str, Any]
    recommendation: str
    cluster_id: str = ""
    query_id: str = ""
    plan_file: str = ""
    node_path: str = ""
    suppressed: bool = False
    baseline_id: str = ""
    suppression_source: str = ""
    suppression_reason: str = ""

    @property
    def original_severity(self) -> str:
        """Rule severity before baseline suppression; kept immutable for reports."""
        return self.severity

    @property
    def effective_severity(self) -> str:
        """Alerting severity: baseline-suppressed findings are downgraded to info."""
        return "info" if self.suppressed else self.severity

    def as_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "category": self.category,
            "severity": self.severity,
            "original_severity": self.original_severity,
            "effective_severity": self.effective_severity,
            "suppressed": self.suppressed,
            "baseline_id": self.baseline_id,
            "suppression_source": self.suppression_source,
            "suppression_reason": self.suppression_reason,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "cluster_id": self.cluster_id,
            "query_id": self.query_id,
            "plan_file": self.plan_file,
            "node_path": self.node_path,
        }


@dataclass(frozen=True)
class FindingBaseline:
    """A finding-baseline selector that intentionally excludes volatile evidence.

    Matching uses only the stable rule id and/or the SQL fingerprint (cluster id).
    Plan node paths, log line numbers and changing evidence values are never stored
    in a baseline record, so a moved/re-numbered plan node cannot invalidate it.
    """

    baseline_id: str
    rule_id: str = ""
    fingerprint: str = ""
    note: str = ""
    source_batch_id: str = ""
    created_at: str = ""
    origin: str = ""

    def __post_init__(self) -> None:
        if not self.rule_id and not self.fingerprint:
            raise ValueError("finding baseline requires rule_id or fingerprint")

    def matches_fields(self, rule_id: str, fingerprint: str) -> bool:
        if self.rule_id and self.rule_id != rule_id:
            return False
        if self.fingerprint and self.fingerprint != fingerprint:
            return False
        return bool(self.rule_id or self.fingerprint)

    def matches(self, finding: Finding) -> bool:
        return self.matches_fields(finding.rule_id, finding.cluster_id)

    def describe(self) -> str:
        parts = []
        if self.rule_id:
            parts.append(f"rule={self.rule_id}")
        if self.fingerprint:
            parts.append(f"fingerprint={self.fingerprint}")
        return f"baseline {self.baseline_id}: " + ", ".join(parts)

    def as_dict(self) -> dict[str, Any]:
        return {
            "baseline_id": self.baseline_id,
            "rule_id": self.rule_id,
            "fingerprint": self.fingerprint,
            "note": self.note,
            "source_batch_id": self.source_batch_id,
            "created_at": self.created_at,
            "origin": self.origin,
        }

    @classmethod
    def auto_id(cls, rule_id: str, fingerprint: str) -> str:
        return stable_id("bl", rule_id, fingerprint)

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "FindingBaseline":
        return cls(
            baseline_id=str(row["baseline_id"]),
            rule_id=str(row.get("rule_id", "") or ""),
            fingerprint=str(row.get("fingerprint", "") or ""),
            note=str(row.get("note", "") or ""),
            source_batch_id=str(row.get("source_batch_id", "") or ""),
            created_at=str(row.get("created_at", "") or ""),
            origin=str(row.get("origin", "") or ""),
        )


@dataclass
class LogFileStat:
    path: str
    log_format: str
    encoding: str
    sha256: str
    line_count: int
    parsed_count: int
    unparsed_count: int
    excluded_count: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "format": self.log_format,
            "encoding": self.encoding,
            "sha256": self.sha256,
            "line_count": self.line_count,
            "parsed_count": self.parsed_count,
            "unparsed_count": self.unparsed_count,
            "excluded_count": self.excluded_count,
        }


@dataclass
class AnalysisResult:
    batch_id: str
    config_hash: str
    input_hash: str
    created_at: str
    queries: list[SlowQuery]
    clusters: list[Cluster]
    findings: list[Finding]
    plans: list[PlanDocument]
    unparsed: list[UnparsedLine]
    file_stats: list[LogFileStat]
    excluded: list[dict[str, Any]]
    summary: dict[str, Any]
    reports: dict[str, str] = field(default_factory=dict)

    def finding_counts(self) -> dict[str, int]:
        """Original-severity distribution, independent of baseline suppression."""
        counts = {level: 0 for level in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.original_severity] = counts.get(finding.original_severity, 0) + 1
        return counts

    def effective_finding_counts(self) -> dict[str, int]:
        """Effective-severity distribution; suppressed findings count as info."""
        counts = {level: 0 for level in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.effective_severity] = counts.get(finding.effective_severity, 0) + 1
        return counts

    def suppressed_findings(self) -> list[Finding]:
        return [finding for finding in self.findings if finding.suppressed]

    def high_findings(self) -> Iterable[Finding]:
        """Findings that still alert (effective severity critical/high)."""
        return (
            f for f in self.findings
            if f.effective_severity in ("critical", "high")
        )


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(severity, 99)


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            severity_rank(f.effective_severity),
            f.category,
            f.rule_id,
            f.cluster_id,
            f.plan_file,
            f.node_path,
            f.finding_id,
        ),
    )
