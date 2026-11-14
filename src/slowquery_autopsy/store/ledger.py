"""SQLite ledger: deterministic batch persistence and read-only access."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from ..models import (
    SEVERITY_ORDER,
    AnalysisResult,
    Finding,
    FindingBaseline,
)
from ..util.hashing import canonical_json
from .schema import FINDINGS_MIGRATION_COLUMNS, SCHEMA_SQL, SCHEMA_VERSION


class LedgerError(RuntimeError):
    """Raised on invalid ledger usage."""


class Ledger:
    def __init__(self, path: Path | str, readonly: bool = False):
        self.path = Path(path)
        self.readonly = readonly
        if readonly:
            if not self.path.is_file():
                raise FileNotFoundError(f"ledger not found: {self.path}")
            uri = self.path.resolve().as_uri() + "?mode=ro"
            self.conn = sqlite3.connect(uri, uri=True)
            self.conn.execute("PRAGMA query_only = ON")
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Ledger":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _assert_writable(self) -> None:
        if self.readonly:
            raise LedgerError("ledger is open read-only")

    def _migrate_findings(self) -> None:
        """Add suppression columns to ledgers created by schema version 1."""
        existing = {
            row["name"] for row in self.conn.execute("PRAGMA table_info(findings)")
        }
        for column, ddl in FINDINGS_MIGRATION_COLUMNS.items():
            if column not in existing:
                self.conn.execute(f"ALTER TABLE findings ADD COLUMN {column} {ddl}")
        # Backfill the original/effective split for rows written before v2.
        self.conn.execute(
            "UPDATE findings SET original_severity = severity "
            "WHERE original_severity = ''"
        )
        self.conn.execute(
            "UPDATE findings SET effective_severity = severity "
            "WHERE effective_severity = ''"
        )

    def init_schema(self) -> None:
        self._assert_writable()
        self.conn.executescript(SCHEMA_SQL)
        self._migrate_findings()
        self.conn.execute(
            "INSERT OR REPLACE INTO schema_meta(key, value) VALUES ('version', ?)",
            (str(SCHEMA_VERSION),),
        )
        self.conn.commit()

    def batch_exists(self, batch_id: str) -> bool:
        row = self.conn.execute("SELECT 1 FROM batches WHERE batch_id = ?", (batch_id,)).fetchone()
        return row is not None

    # -- finding baselines -------------------------------------------------

    def add_finding_baseline(
        self,
        rule_id: str = "",
        fingerprint: str = "",
        *,
        baseline_id: str = "",
        note: str = "",
        source_batch_id: str = "",
        created_at: str = "",
        origin: str = "ledger",
    ) -> FindingBaseline:
        """Register one finding baseline; re-registering the same selector is a no-op."""
        self._assert_writable()
        baseline = FindingBaseline(
            baseline_id=baseline_id or FindingBaseline.auto_id(rule_id, fingerprint),
            rule_id=rule_id.strip(),
            fingerprint=fingerprint.strip(),
            note=note,
            source_batch_id=source_batch_id,
            created_at=created_at,
            origin=origin,
        )
        with self.conn:
            self.conn.execute(
                "INSERT OR IGNORE INTO finding_baselines"
                "(baseline_id, rule_id, fingerprint, note, source_batch_id, created_at, origin)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (baseline.baseline_id, baseline.rule_id, baseline.fingerprint, baseline.note,
                 baseline.source_batch_id, baseline.created_at, baseline.origin),
            )
        return baseline

    def register_finding_baselines(
        self,
        baselines: Iterable[FindingBaseline],
        *,
        created_at: str = "",
    ) -> list[FindingBaseline]:
        """Persist config-declared baselines. Deterministic rows make reruns idempotent."""
        self._assert_writable()
        registered: list[FindingBaseline] = []
        with self.conn:
            for baseline in baselines:
                item = FindingBaseline(
                    baseline_id=baseline.baseline_id,
                    rule_id=baseline.rule_id,
                    fingerprint=baseline.fingerprint,
                    note=baseline.note,
                    source_batch_id=baseline.source_batch_id,
                    created_at=baseline.created_at or created_at,
                    origin=baseline.origin or "config",
                )
                self.conn.execute(
                    "INSERT OR IGNORE INTO finding_baselines"
                    "(baseline_id, rule_id, fingerprint, note, source_batch_id, created_at, origin)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (item.baseline_id, item.rule_id, item.fingerprint, item.note,
                     item.source_batch_id, item.created_at, item.origin),
                )
                registered.append(item)
        return registered

    def list_finding_baselines(self) -> list[FindingBaseline]:
        rows = self.conn.execute(
            "SELECT * FROM finding_baselines ORDER BY rule_id, fingerprint, baseline_id"
        ).fetchall()
        return [FindingBaseline.from_row(dict(row)) for row in rows]

    def get_finding_baseline(self, baseline_id: str) -> FindingBaseline | None:
        row = self.conn.execute(
            "SELECT * FROM finding_baselines WHERE baseline_id = ?", (baseline_id,)
        ).fetchone()
        return FindingBaseline.from_row(dict(row)) if row else None

    def remove_finding_baseline(self, baseline_id: str) -> bool:
        self._assert_writable()
        with self.conn:
            cursor = self.conn.execute(
                "DELETE FROM finding_baselines WHERE baseline_id = ?", (baseline_id,)
            )
        return cursor.rowcount > 0

    def match_finding_baselines(
        self, rule_id: str, fingerprint: str
    ) -> FindingBaseline | None:
        """Look up the first stored baseline matching a rule/fingerprint pair."""
        for baseline in self.list_finding_baselines():
            if baseline.matches_fields(rule_id, fingerprint):
                return baseline
        return None

    def apply_baselines_to_findings(
        self, findings: Iterable[Finding]
    ) -> list[Finding]:
        """Suppress stored findings on demand without rewriting their severity."""
        from ..analysis.risk_rules import apply_finding_baselines

        return apply_finding_baselines(findings, self.list_finding_baselines())

    # -- batches -----------------------------------------------------------

    def save_batch(self, result: AnalysisResult) -> bool:
        self._assert_writable()
        if self.batch_exists(result.batch_id):
            return False
        try:
            with self.conn:
                self.conn.execute(
                    "INSERT INTO batches VALUES (?, ?, ?, ?, ?, ?)",
                    (result.batch_id, result.config_hash, result.input_hash, result.created_at,
                     "complete", canonical_json(result.summary)),
                )
                for stat in result.file_stats:
                    self.conn.execute(
                        "INSERT INTO log_files VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (result.batch_id, stat.path, stat.log_format, stat.encoding, stat.sha256,
                         stat.line_count, stat.parsed_count, stat.unparsed_count, stat.excluded_count),
                    )
                for query in result.queries:
                    self.conn.execute(
                        "INSERT INTO slow_queries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (result.batch_id, query.query_id, query.source_file, query.line_no,
                         query.timestamp, query.duration_ms, query.lock_time_ms, query.rows_sent,
                         query.rows_examined, query.user, query.client, query.database, query.sql,
                         query.normalized_sql, query.fingerprint, query.cluster_id, query.log_format,
                         int(query.excluded), query.exclusion_reason, canonical_json(query.cost)),
                    )
                for cluster in result.clusters:
                    self.conn.execute(
                        "INSERT INTO clusters VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (result.batch_id, cluster.cluster_id, cluster.sample_sql, cluster.normalized_sql,
                         cluster.query_count, cluster.total_duration_ms, cluster.avg_duration_ms,
                         cluster.min_duration_ms, cluster.max_duration_ms, cluster.p50_duration_ms,
                         cluster.p95_duration_ms, cluster.total_rows_examined, cluster.total_rows_sent,
                         cluster.amplification, cluster.lock_ratio, cluster.duration_share,
                         cluster.projected_ms_per_1k_calls, canonical_json(cluster.cost)),
                    )
                for plan in result.plans:
                    self.conn.execute(
                        "INSERT INTO plans VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (result.batch_id, plan.plan_id, plan.source_file, plan.plan_format,
                         plan.fingerprint, plan.linked_cluster_id, plan.node_count, plan.error),
                    )
                    for node in plan.nodes:
                        self.conn.execute(
                            "INSERT INTO plan_nodes VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (result.batch_id, plan.plan_id, node.path, node.operation, node.depth,
                             node.table_name, node.access_type, node.rows, node.key_name,
                             node.condition, canonical_json(node.as_dict())),
                        )
                for finding in result.findings:
                    self.conn.execute(
                        "INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (result.batch_id, finding.finding_id, finding.category, finding.severity,
                         finding.cluster_id, finding.query_id, finding.rule_id, finding.plan_file,
                         finding.node_path, finding.title, finding.description,
                         canonical_json(finding.evidence), finding.recommendation,
                         finding.original_severity, finding.effective_severity,
                         int(finding.suppressed), finding.baseline_id,
                         finding.suppression_source, finding.suppression_reason),
                    )
                for item in result.unparsed:
                    self.conn.execute(
                        "INSERT OR IGNORE INTO unparsed_lines VALUES (?, ?, ?, ?, ?)",
                        (result.batch_id, item.file, item.line_no, item.text, item.reason),
                    )
        except sqlite3.IntegrityError:
            self.conn.rollback()
            return False
        return True

    def list_batches(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM batches ORDER BY created_at DESC, batch_id ASC"
        ).fetchall()
        return [_batch_row(row) for row in rows]

    def get_batch(self, batch_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM batches WHERE batch_id = ?", (batch_id,)).fetchone()
        return _batch_row(row) if row else None

    def latest_batch_id(self) -> str | None:
        row = self.conn.execute(
            "SELECT batch_id FROM batches ORDER BY created_at DESC, batch_id ASC LIMIT 1"
        ).fetchone()
        return row["batch_id"] if row else None

    def batch_ids(self) -> list[str]:
        return [row["batch_id"] for row in self.list_batches()]

    def list_clusters(self, batch_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM clusters WHERE batch_id = ? "
            "ORDER BY total_duration_ms DESC, cluster_id ASC", (batch_id,)
        ).fetchall()
        return [_json_row(row, "cost_json", "cost") for row in rows]

    def get_cluster(self, batch_id: str, cluster_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM clusters WHERE batch_id = ? AND cluster_id = ?", (batch_id, cluster_id)
        ).fetchone()
        return _json_row(row, "cost_json", "cost") if row else None

    def list_queries(self, batch_id: str, cluster_id: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM slow_queries WHERE batch_id = ?"
        args: list[Any] = [batch_id]
        if cluster_id is not None:
            sql += " AND cluster_id = ?"
            args.append(cluster_id)
        sql += " ORDER BY source_file ASC, line_no ASC, query_id ASC"
        return [_json_row(row, "cost_json", "cost") for row in self.conn.execute(sql, args)]

    def get_query(self, batch_id: str, query_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM slow_queries WHERE batch_id = ? AND query_id = ?", (batch_id, query_id)
        ).fetchone()
        return _json_row(row, "cost_json", "cost") if row else None

    def list_plans(self, batch_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM plans WHERE batch_id = ? ORDER BY source_file ASC", (batch_id,)
        ).fetchall()
        return [dict(row) for row in rows]

    def get_plan(self, batch_id: str, plan_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM plans WHERE batch_id = ? AND plan_id = ?", (batch_id, plan_id)
        ).fetchone()
        if not row:
            return None
        plan = dict(row)
        node_rows = self.conn.execute(
            "SELECT node_json FROM plan_nodes WHERE batch_id = ? AND plan_id = ? ORDER BY path",
            (batch_id, plan_id),
        ).fetchall()
        plan["nodes"] = [json.loads(item["node_json"]) for item in node_rows]
        return plan

    def list_findings(
        self,
        batch_id: str,
        severity: str | None = None,
        *,
        effective: bool = True,
    ) -> list[dict[str, Any]]:
        columns = self._finding_columns()
        has_effective = "effective_severity" in columns
        sql = "SELECT * FROM findings WHERE batch_id = ?"
        args: list[Any] = [batch_id]
        if severity:
            if effective and has_effective:
                sql += " AND effective_severity = ?"
            else:
                sql += " AND severity = ?"
            args.append(severity)
        items = [
            _normalized_finding_row(row)
            for row in self.conn.execute(sql, args)
        ]
        items.sort(key=lambda item: (
            SEVERITY_ORDER.get(item["effective_severity"], 99), item["category"], item["rule_id"],
            item["cluster_id"], item["plan_file"], item["node_path"], item["finding_id"],
        ))
        return items

    def _finding_columns(self) -> set[str]:
        cached = getattr(self, "_finding_column_cache", None)
        if cached is None:
            cached = {row["name"] for row in self.conn.execute("PRAGMA table_info(findings)")}
            self._finding_column_cache = cached
        return cached

    def get_finding(self, batch_id: str, finding_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM findings WHERE batch_id = ? AND finding_id = ?", (batch_id, finding_id)
        ).fetchone()
        return _normalized_finding_row(row) if row else None

    def refresh_finding_suppression(
        self,
        batch_id: str,
        baselines: Iterable[FindingBaseline] | None = None,
    ) -> int:
        """Recompute suppression state for one stored batch.

        Finding ids and original severities are left untouched; only the
        effective severity and suppression metadata change, and the stored
        batch summary is updated so the read-only UI stays consistent.
        Returns the number of rows now marked suppressed.
        """
        self._assert_writable()
        baselines = list(baselines) if baselines is not None else self.list_finding_baselines()
        rows = self.conn.execute(
            "SELECT finding_id, rule_id, cluster_id, severity FROM findings WHERE batch_id = ?",
            (batch_id,),
        ).fetchall()
        suppressed = 0
        with self.conn:
            for row in rows:
                match = next(
                    (b for b in baselines
                     if b.matches_fields(row["rule_id"], row["cluster_id"])),
                    None,
                )
                if match:
                    suppressed += 1
                    self.conn.execute(
                        "UPDATE findings SET suppressed = 1, effective_severity = 'info',"
                        " baseline_id = ?, suppression_source = ?, suppression_reason = ?"
                        " WHERE batch_id = ? AND finding_id = ?",
                        (match.baseline_id, match.origin or "ledger", match.describe(),
                         batch_id, row["finding_id"]),
                    )
                else:
                    self.conn.execute(
                        "UPDATE findings SET suppressed = 0, effective_severity = severity,"
                        " baseline_id = '', suppression_source = '', suppression_reason = ''"
                        " WHERE batch_id = ? AND finding_id = ?",
                        (batch_id, row["finding_id"]),
                    )
            self._refresh_batch_summary(batch_id, baselines)
        return suppressed

    def _refresh_batch_summary(
        self, batch_id: str, baselines: list[FindingBaseline]
    ) -> None:
        """Rewrite derived severity/suppression counters in the batch summary."""
        batch = self.get_batch(batch_id)
        if not batch:
            return
        rows = self.conn.execute(
            "SELECT original_severity, effective_severity, suppressed FROM findings"
            " WHERE batch_id = ?",
            (batch_id,),
        ).fetchall()
        summary = dict(batch["summary"])
        levels = ("critical", "high", "medium", "low", "info")
        original = {level: 0 for level in levels}
        effective = {level: 0 for level in levels}
        suppressed = 0
        for row in rows:
            original[row["original_severity"]] = original.get(row["original_severity"], 0) + 1
            effective[row["effective_severity"]] = effective.get(row["effective_severity"], 0) + 1
            if row["suppressed"]:
                suppressed += 1
        summary["severity_counts"] = original
        summary["effective_severity_counts"] = effective
        counts = dict(summary.get("counts", {}))
        counts["findings"] = len(rows)
        counts["high_findings"] = effective.get("high", 0) + effective.get("critical", 0)
        counts["suppressed_findings"] = suppressed
        summary["counts"] = counts
        summary["finding_baselines"] = {
            "count": len(baselines),
            "suppressed_findings": suppressed,
            "items": [baseline.as_dict() for baseline in baselines],
        }
        self.conn.execute(
            "UPDATE batches SET summary_json = ? WHERE batch_id = ?",
            (canonical_json(summary), batch_id),
        )

    def list_unparsed(self, batch_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM unparsed_lines WHERE batch_id = ? ORDER BY file_path, line_no, reason",
            (batch_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def list_log_files(self, batch_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM log_files WHERE batch_id = ? ORDER BY path", (batch_id,)
        ).fetchall()
        return [dict(row) for row in rows]

    def set_baseline(self, name: str, batch_id: str, created_at: str) -> None:
        self._assert_writable()
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO baselines(name, batch_id, created_at) VALUES (?, ?, ?)",
                (name, batch_id, created_at),
            )

    def get_baseline(self, name: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM baselines WHERE name = ?", (name,)).fetchone()
        return dict(row) if row else None

    def list_baselines(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self.conn.execute("SELECT * FROM baselines ORDER BY name")]

    def record_comparison(self, comparison_id: str, base_batch_id: str, head_batch_id: str,
                          created_at: str, summary: dict[str, Any]) -> None:
        self._assert_writable()
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO comparisons VALUES (?, ?, ?, ?, ?)",
                (comparison_id, base_batch_id, head_batch_id, created_at, canonical_json(summary)),
            )

    def list_comparisons(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM comparisons ORDER BY created_at DESC, comparison_id ASC"
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["summary"] = json.loads(item.pop("summary_json"))
            items.append(item)
        return items

    def table_names(self) -> list[str]:
        rows = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
        ).fetchall()
        return [row["name"] for row in rows]


def _batch_row(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    item["summary"] = json.loads(item.pop("summary_json"))
    return item


def _json_row(row: sqlite3.Row, source_key: str, target_key: str) -> dict[str, Any]:
    item = dict(row)
    item[target_key] = json.loads(item.pop(source_key))
    return item


def _normalized_finding_row(row: sqlite3.Row) -> dict[str, Any]:
    """Return a finding row with original/effective severities always populated.

    Ledgers created before schema v2 may still be opened read-only without a
    migration pass, so fall back to the legacy ``severity`` column.
    """
    item = _json_row(row, "evidence_json", "evidence")
    item["original_severity"] = item.get("original_severity") or item["severity"]
    item["effective_severity"] = item.get("effective_severity") or item["severity"]
    item["suppressed"] = int(item.get("suppressed") or 0)
    item["baseline_id"] = item.get("baseline_id") or ""
    item["suppression_source"] = item.get("suppression_source") or ""
    item["suppression_reason"] = item.get("suppression_reason") or ""
    return item


def open_readonly(path: Path | str) -> Ledger:
    return Ledger(path, readonly=True)
