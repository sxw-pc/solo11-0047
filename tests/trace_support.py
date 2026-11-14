"""Shared helpers for the cross-batch trace tests."""

from __future__ import annotations

import shutil
from dataclasses import replace
from pathlib import Path

from slowquery_autopsy.config import load_config

TRACE_KEYS = {
    "trace_type", "schema_version", "status_basis", "status_legend",
    "batches", "fingerprints", "counts",
}

UNIQUE_BLOCK = (
    "# Time: 2026-03-01T11:00:00Z\n"
    "# User@Host: svc_app[svc_app] @ node-z [synthetic]  Id: 901\n"
    "# Schema: shopdemo\n"
    "# Query_time: 7.500000  Lock_time: 0.010000 Rows_sent: 2  Rows_examined: 300000\n"
    "SET timestamp=1768039200;\n"
    "SELECT sku FROM warehouse_items WHERE bin_code = 'A-17';\n"
)


def project(tmp_path: Path, project_root: Path) -> Path:
    """Copy fixtures and configs into a temp project; return its config path."""
    shutil.copytree(project_root / "fixtures", tmp_path / "fixtures")
    shutil.copytree(project_root / "configs", tmp_path / "configs")
    return tmp_path / "configs/pipeline.yaml"


def trace_config(config_path: Path, tmp_path: Path):
    """Load the project config but put its ledger in the temp directory."""
    return replace(load_config(config_path), ledger_path=tmp_path / "data/ledger.sqlite3")


def drop_fingerprint(log_path: Path, marker: str) -> None:
    """Remove the slow-log blocks whose SQL contains ``marker``."""
    blocks = log_path.read_text(encoding="utf-8").split("\n\n")
    kept = [block for block in blocks if marker not in block]
    log_path.write_text("\n\n".join(kept), encoding="utf-8")


def append_block(log_path: Path, extra: str) -> None:
    log_path.write_text(
        log_path.read_text(encoding="utf-8").rstrip("\n") + "\n\n" + extra,
        encoding="utf-8",
    )
