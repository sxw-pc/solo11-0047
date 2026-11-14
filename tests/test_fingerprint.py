from __future__ import annotations

from slowquery_autopsy.analysis.fingerprint import (
    build_clusters,
    fingerprint_id,
    nearest_rank,
)
from slowquery_autopsy.analysis.normalize import normalize_sql
from slowquery_autopsy.models import SlowQuery


def _fp(sql: str, config) -> str:
    normalized = normalize_sql(sql, config.fingerprint_rules)
    return fingerprint_id(normalized.text, normalized.tokens)


def test_hardcoded_fingerprint_is_stable(config):
    sql = (
        "SELECT *\nFROM orders\nWHERE customer_id = 42\n  AND status = 'PAID'\n"
        "ORDER BY created_at DESC\nLIMIT 20;"
    )
    assert _fp(sql, config) == "b6b972a308926333"


def test_same_structure_same_fingerprint_and_structure_change_differs(config):
    left = _fp("SELECT * FROM orders WHERE id = 1 AND status = 'A';", config)
    right = _fp("SELECT * FROM orders WHERE id = 999 AND status = 'B';", config)
    changed = _fp("SELECT * FROM orders WHERE status = 'A' ORDER BY id DESC;", config)
    assert left == right
    assert left != changed


def test_nearest_rank_quantiles_are_deterministic():
    values = [1.0, 2.0, 3.0, 4.0]
    assert nearest_rank(values, 0.5) == 2.0
    assert nearest_rank(values, 0.95) == 4.0
    assert nearest_rank([], 0.5) == 0.0
    assert nearest_rank([7.0], 0.0) == 7.0


def _query(fingerprint: str, duration: float, excluded: bool = False) -> SlowQuery:
    return SlowQuery(
        source_file="synthetic.log", line_no=1, timestamp="2026-01-01T00:00:00Z",
        duration_ms=duration, lock_time_ms=0.0, rows_sent=1, rows_examined=100,
        user="u", client="c", database="d", sql="SELECT 1;",
        log_format="mysql_slow", query_id=f"q-{duration}-{excluded}",
        normalized_sql="SELECT ?;", tokens=["SELECT", "?"], fingerprint=fingerprint,
        cluster_id="" if excluded else fingerprint, excluded=excluded,
    )


def test_cluster_aggregation_excludes_metadata_and_sorts():
    queries = [
        _query("ffffffffffffffff", 20.0),
        _query("0000000000000000", 10.0),
        _query("ffffffffffffffff", 20.0),
        _query("eeeeeeeeeeeeeeee", 999.0, excluded=True),
    ]
    clusters = build_clusters(queries)
    assert [cluster.fingerprint for cluster in clusters] == [
        "ffffffffffffffff", "0000000000000000"
    ]
    first = clusters[0]
    assert first.query_count == 2
    assert first.total_duration_ms == 40.0
    assert first.p50_duration_ms == 20.0
    assert first.p95_duration_ms == 20.0
    assert first.amplification == 100.0
    assert first.projected_ms_per_1k_calls == 20000.0
    assert "eeeeeeeeeeeeeeee" not in {cluster.fingerprint for cluster in clusters}
