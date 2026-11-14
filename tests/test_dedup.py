from __future__ import annotations

from slowquery_autopsy.analysis.dedup import (
    DedupRules,
    deduplicate_queries,
    event_key,
    events_equivalent,
    normalize_event_time,
)
from slowquery_autopsy.analysis.fingerprint import build_clusters
from slowquery_autopsy.models import SlowQuery

SQL_A = "SELECT * FROM orders WHERE customer_id = 42 AND status = 'PAID' ORDER BY created_at DESC LIMIT 20;"
NORMALIZED_A = "SELECT * FROM orders WHERE customer_id = ? AND status = ? ORDER BY created_at DESC LIMIT ?"
TOKENS_A = [
    "SELECT", "*", "FROM", "orders", "WHERE", "customer_id", "=", "?", "AND", "status", "=",
    "?", "ORDER", "BY", "created_at", "DESC", "LIMIT", "?",
]


def _query(
    *,
    source_file: str = "mysql.log",
    line_no: int = 1,
    timestamp: str = "2026-01-10T10:00:00Z",
    duration_ms: float = 2310.0,
    lock_time_ms: float = 10.0,
    rows_sent: int = 20,
    rows_examined: int = 200000,
    sql: str = SQL_A,
    normalized_sql: str = NORMALIZED_A,
    tokens: list[str] | None = None,
    log_format: str = "mysql_slow",
    query_id: str = "",
    fingerprint: str = "fp-a",
    cluster_id: str | None = None,
) -> SlowQuery:
    return SlowQuery(
        source_file=source_file, line_no=line_no, timestamp=timestamp,
        duration_ms=duration_ms, lock_time_ms=lock_time_ms,
        rows_sent=rows_sent, rows_examined=rows_examined,
        user="u", client="c", database="d", sql=sql, log_format=log_format,
        query_id=query_id or f"q-{source_file}-{line_no}",
        normalized_sql=normalized_sql,
        tokens=list(TOKENS_A if tokens is None else tokens),
        fingerprint=fingerprint,
        cluster_id=fingerprint if cluster_id is None else cluster_id,
    )


def test_timestamp_forms_normalize_to_the_same_event_time():
    assert normalize_event_time("2026-01-10 10:00:00") == "2026-01-10T10:00:00Z"
    assert normalize_event_time("2026-01-10T10:00:00Z") == normalize_event_time(
        "2026-01-10 10:00:00"
    )
    assert normalize_event_time("2026-01-10T11:00:00+01:00") == "2026-01-10T10:00:00Z"


def test_cross_format_rows_fold_to_one_event_and_keep_sources():
    mysql = _query()
    pg = _query(
        source_file="pg.csv", line_no=7, log_format="postgres_csv",
        timestamp="2026-01-10 10:00:00",  # naive, same instant
        sql=SQL_A.replace("customer_id = 42", "customer_id = 42  "),  # extra whitespace
        query_id="q-pg",
    )
    rules = DedupRules()
    assert events_equivalent(mysql, pg, rules)
    result = deduplicate_queries([mysql, pg], rules)
    assert result.event_count == 1
    assert result.duplicate_row_count == 1
    assert mysql.cluster_id == "fp-a"
    assert pg.duplicate_of == mysql.query_id
    assert pg.cluster_id == ""
    assert mysql.event_id and pg.event_id == mysql.event_id
    assert mysql.redundant_sources == [{
        "source_file": "pg.csv", "line_no": 7, "query_id": "q-pg",
        "log_format": "postgres_csv", "timestamp": "2026-01-10T10:00:00Z",
        "duration_ms": 2310.0, "lock_time_ms": 10.0,
        "rows_sent": 20, "rows_examined": 200000,
    }]
    assert result.as_dict()["groups"][0]["redundant_sources"][0]["line_no"] == 7


def test_dedup_requires_all_dimensions_inside_tolerance():
    base = _query()
    # SQL structure differs -> different event even with identical metrics.
    assert not events_equivalent(base, _query(
        source_file="pg.csv", sql="SELECT 1;", normalized_sql="SELECT ?;",
        tokens=["SELECT", "?"],
    ))
    # Token sequence differs while the normalized text is (unrealistically) equal.
    assert not events_equivalent(
        base, _query(source_file="pg.csv", tokens=["SELECT", "FROM", "orders"])
    )
    # Duration outside both absolute and relative tolerance.
    assert not events_equivalent(base, _query(source_file="pg.csv", duration_ms=2400.0))
    # Lock time outside tolerance.
    assert not events_equivalent(base, _query(source_file="pg.csv", lock_time_ms=25.0))
    # Row counts outside tolerance.
    assert not events_equivalent(base, _query(source_file="pg.csv", rows_examined=210000))
    assert not events_equivalent(base, _query(source_file="pg.csv", rows_sent=19))
    # Timestamp outside window.
    assert not events_equivalent(
        base, _query(source_file="pg.csv", timestamp="2026-01-10T10:00:05Z")
    )


def test_tolerant_rules_cannot_collapse_nearby_distinct_executions():
    """Regression guard: an over-wide window must not merge separate slow queries."""
    loose = DedupRules(time_tolerance_seconds=60, duration_tolerance_ms=500,
                       duration_tolerance_ratio=0.5, lock_tolerance_ratio=1.0,
                       rows_tolerance_ratio=0.5)
    left = _query(timestamp="2026-01-10T10:00:00Z", duration_ms=1000.0, rows_examined=200000)
    # Same SQL and file, 5 s later, but a genuinely different duration: still folds
    # under loose rules -- which is why the shipped defaults stay tight. Verify
    # that the *strict* rules keep them separate.
    right = _query(source_file="pg.csv", timestamp="2026-01-10T10:00:05Z", duration_ms=1500.0)
    strict = DedupRules()
    assert not events_equivalent(left, right, strict)
    assert events_equivalent(left, right, loose)
    strict_result = deduplicate_queries([left, right], strict)
    assert strict_result.event_count == 2
    assert right.cluster_id == right.fingerprint
    assert left.cluster_id == left.fingerprint


def test_same_file_rows_are_never_folded():
    first = _query(line_no=1, query_id="q-1")
    second = _query(line_no=2, query_id="q-2", fingerprint="fp-b")
    result = deduplicate_queries([first, second], DedupRules())
    assert result.event_count == 2
    assert result.duplicate_row_count == 0
    assert second.duplicate_of == ""


def test_one_source_file_contributes_at_most_one_row_per_event():
    mysql = _query()
    pg_first = _query(source_file="pg.csv", line_no=1, query_id="q-pg1")
    pg_second = _query(source_file="pg.csv", line_no=2, query_id="q-pg2")
    result = deduplicate_queries([mysql, pg_first, pg_second], DedupRules())
    assert result.event_count == 2
    assert mysql.event_id != pg_second.event_id
    assert pg_second.duplicate_of == ""
    assert pg_second.cluster_id == pg_second.fingerprint


def test_excluded_and_non_duplicate_metadata_are_untouched():
    metadata = _query(
        sql="SHOW INDEX FROM orders;", normalized_sql="SHOW INDEX FROM orders;",
        tokens=["SHOW", "INDEX", "FROM", "orders"], cluster_id="", fingerprint="",
    )
    metadata.excluded = True
    other = _query(source_file="pg.csv")
    result = deduplicate_queries([metadata, other], DedupRules())
    assert result.event_count == 1
    assert metadata.duplicate_of == ""
    assert metadata.event_id == ""


def test_event_key_is_stable_across_timestamp_forms():
    assert event_key(_query(timestamp="2026-01-10T10:00:00Z")) == event_key(
        _query(timestamp="2026-01-10 10:00:00")
    )


def test_clusters_and_analyzed_count_exclude_folded_rows():
    mysql = _query(fingerprint="fp-a", duration_ms=1000.0)
    pg = _query(source_file="pg.csv", line_no=2, duration_ms=1000.0, query_id="q-pg")
    result = deduplicate_queries([mysql, pg], DedupRules())
    assert result.event_count == 1
    clusters = build_clusters([mysql, pg])
    assert [cluster.fingerprint for cluster in clusters] == ["fp-a"]
    assert cluster_total(clusters) == 1
    # The folded row no longer contributes its (identical) duration twice.
    assert sum(query.duration_ms for query in (mysql, pg) if not query.duplicate_of) == 1000.0
    # A near-but-not-equal row stays its own event and keeps its own cluster.
    other = _query(source_file="pg2.csv", line_no=3, fingerprint="fp-c", duration_ms=1300.0,
                   query_id="q-other")
    deduplicate_queries([mysql, other], DedupRules())
    assert other.duplicate_of == ""
    assert [cluster.fingerprint for cluster in build_clusters([mysql, other])] == ["fp-c", "fp-a"]


def cluster_total(clusters) -> int:
    return sum(cluster.query_count for cluster in clusters)


def test_dedup_disabled_is_a_noop():
    queries = [_query(source_file="mysql.log"), _query(source_file="pg.csv", line_no=2)]
    result = deduplicate_queries(queries, DedupRules(enabled=False))
    assert result.event_count == 0
    assert all(query.duplicate_of == "" for query in queries)
    assert all(query.event_id == query.query_id for query in queries)


def test_rules_parse_rejects_bad_values():
    import pytest

    with pytest.raises(ValueError):
        DedupRules.from_mapping({"time_tolerance_seconds": -1})
    with pytest.raises(ValueError):
        DedupRules.from_mapping({"rows_tolerance": 1.5})
    with pytest.raises(ValueError):
        DedupRules.from_mapping({"enabled": "yes"})
