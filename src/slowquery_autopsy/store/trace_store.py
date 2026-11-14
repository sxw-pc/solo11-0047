"""Trace support persistence: per-fingerprint source coverage and trace records.

``Ledger`` delegates its trace-related reads/writes here so the core module
stays focused on batches, queries and findings.  Every function takes the open
``sqlite3.Connection``; the read paths are safe on a read-only ledger.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from ..models import AnalysisResult
from ..util.hashing import canonical_json


def source_rows(result: AnalysisResult) -> list[tuple[str, str, str, int]]:
    """Per-batch fingerprint/source coverage, counted from analyzed queries."""
    counts: dict[tuple[str, str], int] = {}
    for query in result.queries:
        if query.excluded or not query.fingerprint:
            continue
        key = (query.fingerprint, query.source_file)
        counts[key] = counts.get(key, 0) + 1
    return [
        (result.batch_id, fingerprint, source_file, count)
        for (fingerprint, source_file), count in sorted(counts.items())
    ]


def insert_sources(conn: sqlite3.Connection, result: AnalysisResult) -> None:
    for row in source_rows(result):
        conn.execute("INSERT INTO fingerprint_sources VALUES (?, ?, ?, ?)", row)


def backfill_sources(conn: sqlite3.Connection) -> int:
    """Rebuild ``fingerprint_sources`` rows from ``slow_queries``.

    Older ledgers (schema v1) predate the table, but the rows are derivable from
    the queries they already store, so an upgrade can recover real coverage
    instead of reporting every historical batch as ``not_collected``.
    """
    rows = conn.execute(
        "SELECT batch_id, fingerprint, source_file, COUNT(*) AS query_count "
        "FROM slow_queries WHERE excluded = 0 AND fingerprint <> '' "
        "GROUP BY batch_id, fingerprint, source_file "
        "ORDER BY batch_id, fingerprint, source_file"
    ).fetchall()
    inserted = 0
    for row in rows:
        cursor = conn.execute(
            "INSERT OR IGNORE INTO fingerprint_sources VALUES (?, ?, ?, ?)",
            (row["batch_id"], row["fingerprint"], row["source_file"],
             row["query_count"]),
        )
        inserted += cursor.rowcount
    return inserted


def has_sources(conn: sqlite3.Connection) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'fingerprint_sources'"
    ).fetchone()
    return row is not None


def list_sources(conn: sqlite3.Connection, batch_id: str) -> list[dict[str, Any]]:
    if not has_sources(conn):
        return []
    rows = conn.execute(
        "SELECT * FROM fingerprint_sources WHERE batch_id = ? "
        "ORDER BY fingerprint, source_file", (batch_id,)
    ).fetchall()
    return [dict(row) for row in rows]


def record_trace(conn: sqlite3.Connection, trace_id: str, batch_ids: list[str],
                 created_at: str, summary: dict[str, Any]) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO traces VALUES (?, ?, ?, ?)",
        (trace_id, canonical_json(list(batch_ids)), created_at,
         canonical_json(summary)),
    )


def list_traces(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM traces ORDER BY created_at DESC, trace_id ASC"
    ).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        item["batch_ids"] = json.loads(item.pop("batch_ids_json"))
        item["summary"] = json.loads(item.pop("summary_json"))
        items.append(item)
    return items


class TraceStoreMixin:
    """Ledger mixin for coverage/backfill/trace persistence.

    The host class provides ``conn``, ``_assert_writable`` and ``batch_exists``.
    """

    def backfill_fingerprint_sources(self) -> int:
        """Fill ``fingerprint_sources`` for batches written before schema v2.

        Returns the number of inserted rows.  Idempotent: existing rows stay.
        """
        self._assert_writable()
        with self.conn:
            return backfill_sources(self.conn)

    def list_log_files(self, batch_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM log_files WHERE batch_id = ? ORDER BY path", (batch_id,)
        ).fetchall()
        return [dict(row) for row in rows]

    def list_fingerprint_sources(self, batch_id: str) -> list[dict[str, Any]]:
        """Files that covered each fingerprint in a batch (trace coverage).

        Legacy ledgers written before schema v2 have no such table and return
        an empty list; the trace then reports those batches as
        ``not_collected`` rather than guessing ``absent``.
        """
        return list_sources(self.conn, batch_id)

    def has_fingerprint_sources(self) -> bool:
        return has_sources(self.conn)

    def record_trace(self, trace_id: str, batch_ids: list[str], created_at: str,
                     summary: dict[str, Any]) -> None:
        self._assert_writable()
        with self.conn:
            record_trace(self.conn, trace_id, batch_ids, created_at, summary)

    def list_traces(self) -> list[dict[str, Any]]:
        return list_traces(self.conn)
