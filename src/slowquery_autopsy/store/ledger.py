"""SQLite ledger: deterministic batch persistence and read-only access."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from ..models import SEVERITY_ORDER, AnalysisResult
from ..util.hashing import canonical_json
from ..util.timefmt import utc_now_iso
from .schema import SCHEMA_SQL

SCHEMA_VERSION = 1


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

    def init_schema(self) -> None:
        self._assert_writable()
        self.conn.executescript(SCHEMA_SQL)
        self.conn.execute(
            "INSERT OR REPLACE INTO schema_meta(key, value) VALUES ('version', ?)",
            (str(SCHEMA_VERSION),),
        )
        self.conn.commit()

    def batch_exists(self, batch_id: str) -> bool:
        row = self.conn.execute("SELECT 1 FROM batches WHERE batch_id = ?", (batch_id,)).fetchone()
        return row is not None

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
                        "INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (result.batch_id, finding.finding_id, finding.category, finding.severity,
                         finding.cluster_id, finding.query_id, finding.rule_id, finding.plan_file,
                         finding.node_path, finding.title, finding.description,
                         canonical_json(finding.evidence), finding.recommendation),
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

    def get_parse_cache(self, cache_key: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT display_path, sha256, payload_json FROM parse_cache WHERE cache_key = ?",
            (cache_key,),
        ).fetchone()
        if row is None:
            return None
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, json.JSONDecodeError):
            # A corrupt row is treated as a cache miss so the caller re-parses
            # and overwrites it instead of crashing the batch build.
            return None
        return {
            "display_path": row["display_path"],
            "sha256": row["sha256"],
            "payload": payload,
        }

    def put_parse_cache(
        self, cache_key: str, display_path: str, file_sha256: str, payload: dict[str, Any]
    ) -> None:
        self._assert_writable()
        with self.conn:
            self.conn.execute(
                "INSERT INTO parse_cache "
                "(cache_key, display_path, sha256, payload_json, created_at) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(cache_key) DO UPDATE SET "
                "display_path = excluded.display_path, sha256 = excluded.sha256, "
                "payload_json = excluded.payload_json, created_at = excluded.created_at",
                (cache_key, display_path, file_sha256,
                 canonical_json(payload), utc_now_iso()),
            )

    def prune_parse_cache(self, active_keys: set[str]) -> int:
        """Drop stale entries whose key no longer matches any current input.

        Only rows for paths still present in the configuration are removed;
        entries belonging to files that left the input list are retained so
        re-adding the file keeps its warm cache. Returns the number deleted.
        """
        self._assert_writable()
        if not active_keys:
            return 0
        placeholders = ",".join("?" for _ in active_keys)
        with self.conn:
            cursor = self.conn.execute(
                f"DELETE FROM parse_cache "
                f"WHERE cache_key NOT IN ({placeholders}) "
                f"AND display_path IN ("
                f"  SELECT DISTINCT display_path FROM parse_cache "
                f"  WHERE cache_key IN ({placeholders}))",
                tuple(active_keys) * 2,
            )
            return cursor.rowcount

    def parse_cache_size(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) AS n FROM parse_cache").fetchone()
        return int(row["n"])

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

    def list_findings(self, batch_id: str, severity: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM findings WHERE batch_id = ?"
        args: list[Any] = [batch_id]
        if severity:
            sql += " AND severity = ?"
            args.append(severity)
        items = [_json_row(row, "evidence_json", "evidence") for row in self.conn.execute(sql, args)]
        items.sort(key=lambda item: (
            SEVERITY_ORDER.get(item["severity"], 99), item["category"], item["rule_id"],
            item["cluster_id"], item["plan_file"], item["node_path"], item["finding_id"],
        ))
        return items

    def get_finding(self, batch_id: str, finding_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM findings WHERE batch_id = ? AND finding_id = ?", (batch_id, finding_id)
        ).fetchone()
        return _json_row(row, "evidence_json", "evidence") if row else None

    def list_unparsed(self, batch_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM unparsed_lines WHERE batch_id = ? ORDER BY file_path, line_no, reason",
            (batch_id,),
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


def open_readonly(path: Path | str) -> Ledger:
    return Ledger(path, readonly=True)
