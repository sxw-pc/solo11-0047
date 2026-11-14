from __future__ import annotations

import shutil
from pathlib import Path

from slowquery_autopsy.analysis.dedup import DedupRules
from slowquery_autopsy.config import load_config
from slowquery_autopsy.pipeline import build_result


MYSQL_A = """# Time: 2026-03-01T00:00:00Z
# User@Host: svc_app[svc_app] @ node-a [synthetic]  Id: 1
# Schema: shopdemo
# Query_time: 1.000000  Lock_time: 0.010000 Rows_sent: 10  Rows_examined: 100000
SELECT id, status FROM orders WHERE customer_id = 7 AND status = 'PAID' ORDER BY created_at DESC LIMIT 10;
"""

MYSQL_B = """# Time: 2026-03-01T00:00:05Z
# User@Host: svc_app[svc_app] @ node-b [synthetic]  Id: 2
# Schema: shopdemo
# Query_time: 1.500000  Lock_time: 0.010000 Rows_sent: 10  Rows_examined: 100000
SELECT id, status FROM orders WHERE customer_id = 9 AND status = 'NEW' ORDER BY created_at DESC LIMIT 10;
"""

PG_DUPLICATE_OF_A = (
    '2026-03-01 00:00:00,svc_report,shopdemo,1.000,0.010,10,100000,node-a,"'
    "SELECT id, status FROM orders WHERE customer_id = 7 AND status = 'PAID' "
    'ORDER BY created_at DESC LIMIT 10;"\n'
)

PG_DUPLICATE_OF_B = (
    '2026-03-01 00:00:05,svc_report,shopdemo,1.500,0.010,10,100000,node-b,"'
    "SELECT id, status FROM orders WHERE customer_id = 9 AND status = 'NEW' "
    'ORDER BY created_at DESC LIMIT 10;"\n'
)

# Same normalized SQL and token sequence as MYSQL_A / PG_DUPLICATE_OF_A, one
# second later and 10% slower. This is a *different* execution and must not
# fold under the shipped tolerance; an over-wide window would merge it.
PG_NEAR_DISTINCT = (
    '2026-03-01 00:00:01,svc_report,shopdemo,1.100,0.010,10,100000,node-c,"'
    "SELECT id, status FROM orders WHERE customer_id = 11 AND status = 'NEW' "
    'ORDER BY created_at DESC LIMIT 10;"\n'
)


def _config_path(tmp_path: Path, project_root: Path, dedup: dict | None,
                 near_file: bool = False) -> Path:
    shutil.copytree(project_root / "fixtures", tmp_path / "fixtures")
    shutil.copytree(project_root / "configs", tmp_path / "configs")
    logs = tmp_path / "fixtures" / "logs"
    for path in logs.glob("*.log"):
        path.unlink()
    (logs / "mysql.log").write_text(MYSQL_A + "\n" + MYSQL_B, encoding="utf-8")
    (logs / "pg.csv").write_text(PG_DUPLICATE_OF_A + PG_DUPLICATE_OF_B, encoding="utf-8")
    config_path = tmp_path / "configs" / "pipeline.yaml"
    import yaml

    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    raw["inputs"] = [
        {"path": "fixtures/logs/mysql.log", "format": "mysql_slow", "encoding": "utf-8"},
        {"path": "fixtures/logs/pg.csv", "format": "postgres_csv", "encoding": "utf-8"},
    ]
    if near_file:
        # A third source file lets the near-but-distinct row be a fold candidate
        # for the same event (a file contributes at most one row per event).
        (logs / "pg_near.csv").write_text(PG_NEAR_DISTINCT, encoding="utf-8")
        raw["inputs"].append(
            {"path": "fixtures/logs/pg_near.csv", "format": "postgres_csv", "encoding": "utf-8"}
        )
    raw["plan"]["files"] = []
    if dedup is None:
        raw.pop("dedup", None)
    else:
        raw["dedup"] = dedup
    config_path.write_text(yaml.safe_dump(raw, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return config_path


def _config(tmp_path: Path, project_root: Path, dedup: dict | None,
            near_file: bool = False):
    return load_config(_config_path(tmp_path, project_root, dedup, near_file))


def test_default_tolerance_folds_identical_cross_format_rows(tmp_path, project_root):
    config = _config(tmp_path, project_root, None)
    result = build_result(config)
    counts = result.summary["counts"]
    assert counts["queries"] == 4
    assert counts["duplicate_queries"] == 2
    assert counts["analyzed_queries"] == 2
    assert sum(cluster.query_count for cluster in result.clusters) == 2
    assert counts["analyzed_queries"] == sum(cluster.query_count for cluster in result.clusters)
    folded = [query for query in result.queries if query.duplicate_of]
    assert {query.source_file for query in folded} == {"fixtures/logs/pg.csv"}
    representatives = [query for query in result.queries if query.redundant_sources]
    assert all(source["source_file"] == "fixtures/logs/pg.csv" for rep in representatives
               for source in rep.redundant_sources)
    assert all(source["line_no"] >= 1 for rep in representatives
               for source in rep.redundant_sources)
    for finding in result.findings:
        if finding.category != "cost":
            continue
        cluster = next(c for c in result.clusters if c.fingerprint == finding.cluster_id)
        assert finding.evidence["query_count"] == cluster.query_count


def test_default_tolerance_keeps_near_but_distinct_execution_separate(tmp_path, project_root):
    """The shipped window must not merge a 1 s / 10% different execution.

    The folded source list is still required to carry file and line numbers.
    """
    config = _config(tmp_path, project_root, None, near_file=True)
    result = build_result(config)
    counts = result.summary["counts"]
    assert counts["queries"] == 5
    assert counts["duplicate_queries"] == 2
    assert counts["analyzed_queries"] == 3
    near = next(query for query in result.queries if query.source_file.endswith("pg_near.csv"))
    assert near.duplicate_of == ""
    assert near.redundant_sources == []
    assert counts["analyzed_queries"] == sum(c.query_count for c in result.clusters)
    for finding in result.findings:
        if finding.category == "cost":
            cluster = next(c for c in result.clusters if c.fingerprint == finding.cluster_id)
            assert finding.evidence["query_count"] == cluster.query_count


def test_over_tolerant_dedup_merges_distinct_rows_and_drifts_traceability(tmp_path, project_root):
    """Failure path guard: a too-wide window *does* merge distinct executions.

    The test proves the risk is real so the defaults stay tight -- and asserts
    the invariant that is sacrificed when the window is widened: the folded row's
    ``query_count`` can no longer be reconciled against row-level details.
    """
    strict = build_result(_config(tmp_path / "strict", project_root, None,
                                  near_file=True))
    assert strict.summary["counts"]["analyzed_queries"] == 3

    loose_rules = {
        "time_tolerance_seconds": 30,
        "duration_tolerance_ms": 1000,
        "duration_tolerance_ratio": 0.5,
        "rows_tolerance_ratio": 0.5,
        "lock_tolerance_ratio": 0.5,
    }
    loose = build_result(_config(tmp_path / "loose", project_root, loose_rules,
                                 near_file=True))
    assert loose.summary["counts"]["duplicate_queries"] == 3
    assert loose.summary["counts"]["analyzed_queries"] == 2
    # The 1.1 s execution was folded away; its row survives only as a source
    # entry under the representative, with file and line, but it no longer has
    # its own cluster. That is exactly the drift the tight defaults prevent.
    near = next(query for query in loose.queries if query.source_file.endswith("pg_near.csv"))
    assert near.duplicate_of != ""
    assert near.cluster_id == ""
    representative = next(query for query in loose.queries
                          if query.query_id == near.duplicate_of)
    assert any(item["source_file"].endswith("pg_near.csv") and item["line_no"] == 1
               for item in representative.redundant_sources)
    assert loose.summary["counts"]["analyzed_queries"] == sum(
        c.query_count for c in loose.clusters
    )


def test_dedup_rule_validation_rejects_negative_tolerance(tmp_path, project_root):
    config_path = _config_path(tmp_path, project_root, {"time_tolerance_seconds": -5})
    assert DedupRules.from_mapping({"time_tolerance_seconds": 0}).time_tolerance_seconds == 0.0
    try:
        load_config(config_path)
    except ValueError as exc:
        assert "dedup.time_tolerance_seconds" in str(exc)
    else:
        raise AssertionError("expected ConfigError for negative tolerance")
