from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from slowquery_autopsy.config import load_config  # noqa: E402
from slowquery_autopsy.pipeline import build_result, persist_result  # noqa: E402


@pytest.fixture(scope="session")
def project_root() -> Path:
    return ROOT


@pytest.fixture(scope="session")
def config():
    return load_config(ROOT / "configs" / "pipeline.yaml")


@pytest.fixture(scope="session")
def result(config):
    return build_result(config, created_at="2026-01-11T00:00:00Z")


@pytest.fixture
def temp_config(config, tmp_path):
    return replace(config, ledger_path=tmp_path / "ledger.sqlite3", reports_dir=tmp_path / "reports")


@pytest.fixture
def ledger_result(temp_config, result):
    assert persist_result(temp_config, result)
    return temp_config, result
