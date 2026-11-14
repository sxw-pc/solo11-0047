"""Two-level clustering: structural parent fingerprints and text children."""

from __future__ import annotations

from slowquery_autopsy.analysis.fingerprint import (
    build_clusters,
    build_parent_clusters,
    fingerprint_id,
    structural_fingerprint_id,
)
from slowquery_autopsy.analysis.normalize import normalize_sql, structural_signature
from slowquery_autopsy.models import SlowQuery


def _structural(config, sql: str) -> str:
    normalized = normalize_sql(sql, config.fingerprint_rules)
    _, tokens = structural_signature(normalized.tokens)
    return structural_fingerprint_id(tokens)


def _text(config, sql: str) -> str:
    normalized = normalize_sql(sql, config.fingerprint_rules)
    return fingerprint_id(normalized.text, normalized.tokens)


def test_alias_and_column_order_merge_under_same_parent(config):
    left = (
        "SELECT c.id, c.name FROM customers c "
        "WHERE c.id = 1 AND c.region = 'north';"
    )
    right = (
        "SELECT k.name, k.id FROM customers k "
        "WHERE k.region = 'south' AND k.id = 2;"
    )
    assert _text(config, left) != _text(config, right)
    assert _structural(config, left) == _structural(config, right)


def test_explicit_aliases_and_join_alias_noise_merge(config):
    left = (
        "SELECT COUNT(o.id) AS order_count "
        "FROM customers c JOIN orders o ON o.customer_id = c.id "
        "WHERE c.region = 'north';"
    )
    right = (
        "SELECT COUNT(x.id) AS cnt "
        "FROM customers p JOIN orders x ON x.customer_id = p.id "
        "WHERE p.region = 'west';"
    )
    assert _text(config, left) != _text(config, right)
    assert _structural(config, left) == _structural(config, right)


def test_case_writing_style_is_absorbed(config):
    simple = (
        "SELECT id FROM orders "
        "WHERE CASE status WHEN 'PAID' THEN 1 ELSE 0 END = 1;"
    )
    searched = (
        "SELECT id FROM orders "
        "WHERE CASE WHEN status = 'PAID' THEN 1 ELSE 0 END = 1;"
    )
    assert _structural(config, simple) == _structural(config, searched)


def test_different_where_filter_columns_never_merge(config):
    base = "SELECT * FROM orders WHERE customer_id = 1 AND status = 'x';"
    other_column = "SELECT * FROM orders WHERE customer_id = 1 AND region = 'x';"
    dropped_column = "SELECT * FROM orders WHERE customer_id = 1;"
    base_fp = _structural(config, base)
    assert _structural(config, other_column) != base_fp
    assert _structural(config, dropped_column) != base_fp


def test_different_table_never_merges(config):
    orders = "SELECT id, name FROM orders WHERE id = 1;"
    products = "SELECT id, name FROM products WHERE id = 1;"
    assert _structural(config, orders) != _structural(config, products)


def _query(query_id: str, sql: str, structural: str, text_fp: str,
           duration: float, rows_examined: int, rows_sent: int,
           lock_time: float = 0.0) -> SlowQuery:
    return SlowQuery(
        source_file="synthetic.log", line_no=1, timestamp="2026-01-01T00:00:00Z",
        duration_ms=duration, lock_time_ms=lock_time, rows_sent=rows_sent,
        rows_examined=rows_examined, user="u", client="c", database="d",
        sql=sql, log_format="mysql_slow", query_id=query_id,
        normalized_sql=sql, fingerprint=text_fp,
        structural_fingerprint=structural, structural_sql=sql,
        cluster_id=text_fp,
    )


def test_parent_cluster_aggregates_queries_not_child_sums():
    # Two text children (alias variants) under one structural parent.
    parent_fp = "p-parent000000000"
    queries = [
        _query("q1", "SELECT c.id FROM t c WHERE c.id = 1;", parent_fp,
               "child-aaaaaaaa", 100.0, 1000, 10),
        _query("q2", "SELECT c.id FROM t c WHERE c.id = 2;", parent_fp,
               "child-aaaaaaaa", 300.0, 3000, 10),
        _query("q3", "SELECT k.id FROM t k WHERE k.id = 3;", parent_fp,
               "child-bbbbbbbb", 200.0, 2000, 10),
    ]
    parents = build_parent_clusters(queries)
    children = build_clusters(queries)
    assert len(parents) == 1
    parent = parents[0]
    assert parent.structural_fingerprint == parent_fp
    assert parent.child_fingerprints == ["child-aaaaaaaa", "child-bbbbbbbb"]
    assert parent.child_query_counts == {"child-aaaaaaaa": 2, "child-bbbbbbbb": 1}
    assert parent.query_count == 3
    # Recomputed from raw members rather than averaging/summing child stats.
    assert parent.total_duration_ms == 600.0
    assert parent.avg_duration_ms == 200.0
    assert parent.p50_duration_ms == 200.0
    assert parent.p95_duration_ms == 300.0
    assert parent.total_rows_examined == 6000
    assert parent.total_rows_sent == 30
    assert parent.amplification == 200.0
    assert parent.duration_share == 1.0
    assert parent.projected_ms_per_1k_calls == 200000.0
    # Parent/child totals reconcile without double counting.
    assert sum(child.query_count for child in children) == parent.query_count
    assert sum(child.total_duration_ms for child in children) == parent.total_duration_ms
    assert sum(child.duration_share for child in children) == parent.duration_share


def test_duration_share_scales_with_overall_total():
    parent_a, parent_b = "p-aaaa", "p-bbbb"
    queries = [
        _query("q1", "SELECT 1;", parent_a, "c-a1", 100.0, 10, 1),
        _query("q2", "SELECT 2;", parent_b, "c-b1", 300.0, 10, 1),
    ]
    parents = build_parent_clusters(queries)
    by_id = {p.structural_fingerprint: p for p in parents}
    assert by_id[parent_a].duration_share == 0.25
    assert by_id[parent_b].duration_share == 0.75
    assert round(sum(p.duration_share for p in parents), 9) == 1.0


def test_excluded_queries_are_ignored_by_parent_clusters():
    included = _query("q1", "SELECT 1;", "p1", "c1", 100.0, 10, 1)
    excluded = _query("q2", "SET timestamp=1;", "p2", "c2", 50.0, 0, 0)
    excluded.excluded = True
    excluded.cluster_id = ""
    parents = build_parent_clusters([included, excluded])
    assert [p.structural_fingerprint for p in parents] == ["p1"]


def test_structural_fingerprint_is_deterministic(config):
    sql = (
        "SELECT c.id, c.name, COUNT(o.id) AS order_count "
        "FROM customers c JOIN orders o ON o.customer_id = c.id "
        "WHERE lower(c.region) = 'south' AND c.id = 7 "
        "GROUP BY c.id, c.name ORDER BY order_count DESC LIMIT 100;"
    )
    runs = {_structural(config, sql) for _ in range(5)}
    assert runs == {_structural(config, sql)}
    assert len(runs) == 1
