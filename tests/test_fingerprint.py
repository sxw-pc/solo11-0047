from __future__ import annotations

import pytest

from slowquery_autopsy.analysis.fingerprint import (
    DEFAULT_WINDOW_SECONDS,
    build_clusters,
    build_window_events,
    fingerprint_id,
    nearest_rank,
    parse_event_time,
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


# --- window-level burst attribution ---------------------------------------

def _timed_query(
    timestamp: str,
    duration: float,
    examined: int,
    *,
    fp: str = "aaaaaaaaaaaaaaaa",
    source_file: str = "mysql.log",
    line_no: int = 1,
    log_format: str = "mysql_slow",
    sent: int = 1,
) -> SlowQuery:
    return SlowQuery(
        source_file=source_file, line_no=line_no, timestamp=timestamp,
        duration_ms=duration, lock_time_ms=0.0, rows_sent=sent,
        rows_examined=examined, user="u", client="c", database="d",
        sql="SELECT 1;", log_format=log_format,
        query_id=f"q-{source_file}-{line_no}", fingerprint=fp, cluster_id=fp,
        normalized_sql="SELECT ?;", tokens=["SELECT", "?"],
    )


def test_window_groups_occurrences_into_events_with_metrics():
    # Two tight bursts (00:00/00:02 and 00:10/00:11) inside a 300s gap window.
    queries = [
        _timed_query("2026-01-10T00:00:00Z", 100.0, 1000, line_no=1),
        _timed_query("2026-01-10T00:02:00Z", 300.0, 3000, line_no=2),
        _timed_query("2026-01-10T00:10:00Z", 200.0, 2000, line_no=3),
        _timed_query("2026-01-10T00:11:00Z", 50.0, 500, line_no=4),
    ]
    cluster = build_clusters(queries, window_seconds=300)[0]
    assert cluster.window_seconds == 300
    assert cluster.window_event_count == 2
    events = cluster.window_events
    assert [event.event_index for event in events] == [1, 2]
    assert events[0].started_at == "2026-01-10T00:00:00Z"
    assert events[0].ended_at == "2026-01-10T00:02:00Z"
    assert events[0].occurrence_count == 2
    assert events[0].total_duration_ms == 400.0
    assert events[0].max_query_duration_ms == 300.0
    assert events[0].rows_examined == 4000
    assert events[0].rows_sent == 2
    assert events[1].occurrence_count == 2
    assert events[1].total_duration_ms == 250.0
    assert events[1].max_query_duration_ms == 200.0
    assert events[1].rows_examined == 2500
    # Cluster-level rollups take the largest single event.
    assert cluster.window_max_duration_ms == 400.0
    assert cluster.window_max_rows_examined == 4000
    assert cluster.cost["window_event_count"] == 2
    assert cluster.cost["window_max_duration_ms"] == 400.0
    assert cluster.cost["window_max_rows_examined"] == 4000


def test_window_endpoint_gap_is_inclusive_and_just_over_gap_splits():
    base = "2026-01-10T00:00:00Z"
    # Gap exactly 60s stays in the event; 61s opens a new one.
    queries = [
        _timed_query(base, 10.0, 10, line_no=1),
        _timed_query("2026-01-10T00:01:00Z", 10.0, 10, line_no=2),
        _timed_query("2026-01-10T00:02:01Z", 10.0, 10, line_no=3),
    ]
    events = build_window_events(queries, window_seconds=60)
    assert [event.occurrence_count for event in events] == [2, 1]
    assert events[0].ended_at == "2026-01-10T00:01:00Z"
    # The strict-greater boundary stays identical when rerun on shuffled input.
    shuffled = [queries[2], queries[0], queries[1]]
    assert build_window_events(shuffled, 60) == events


def test_windowing_is_reproducible_and_does_not_create_extra_clusters():
    queries = [
        _timed_query("2026-01-10T00:11:00Z", 50.0, 500, line_no=3),
        _timed_query("2026-01-10T00:00:00Z", 100.0, 1000, line_no=1),
        _timed_query("2026-01-10T00:10:00Z", 200.0, 2000, line_no=2),
        _timed_query("2026-01-10T00:02:00Z", 300.0, 3000, line_no=4,
                     source_file="other.log"),
    ]
    first = build_clusters(queries, window_seconds=300)
    second = build_clusters(list(reversed(queries)), window_seconds=300)
    assert len(first) == 1 and len(second) == 1
    # Window attribution is order-independent even though ingestion-order
    # query_ids (an existing cluster field) intentionally keep input order.
    window_fields = (
        "window_seconds", "window_event_count", "window_max_duration_ms",
        "window_max_rows_examined", "window_events",
    )
    for field in window_fields:
        assert first[0].as_dict()[field] == second[0].as_dict()[field]
    assert first[0].window_event_count == 2
    # Occurrences interleaved from two source files keep one fingerprint cluster.
    assert first[0].query_count == 4
    assert first[0].window_events[0].query_ids == ["q-mysql.log-1", "q-other.log-4"]


def test_mysql_and_postgres_timestamps_compare_on_one_timeline():
    queries = [
        # Same fingerprint seen in a PG CSV row and a MySQL slow-log block.
        _timed_query("2026-01-10T12:00:00Z", 100.0, 100,
                     source_file="pg.csv", line_no=10, log_format="postgres_csv"),
        _timed_query("2026-01-10T12:04:00Z", 100.0, 100,
                     source_file="mysql.log", line_no=20, log_format="mysql_slow"),
        _timed_query("2026-01-10T12:09:01Z", 100.0, 100,
                     source_file="pg.csv", line_no=11, log_format="postgres_csv"),
    ]
    events = build_window_events(queries, window_seconds=300)
    # 4-minute and 5-minute gaps are both within 300s; 5m01s splits.
    assert [event.occurrence_count for event in events] == [2, 1]
    assert events[0].query_ids == ["q-pg.csv-10", "q-mysql.log-20"]
    # Both ingestion timestamp shapes parse to the same comparable UTC instant.
    assert parse_event_time("2026-01-10T12:00:00Z") == parse_event_time(
        "2026-01-10T12:00:00+00:00"
    )


def test_unparseable_timestamps_become_singleton_events_without_undercount():
    queries = [
        _timed_query("2026-01-10T00:00:00Z", 100.0, 100, line_no=1),
        _timed_query("", 100.0, 100, line_no=2),
        _timed_query("not-a-timestamp", 100.0, 100, line_no=3),
        _timed_query("2026-01-10T00:01:00Z", 100.0, 100, line_no=4),
    ]
    events = build_window_events(queries, window_seconds=300)
    # One real burst plus two standalone events: unknown data is never merged.
    assert [event.occurrence_count for event in events] == [2, 1, 1]
    assert events[1].started_at == ""
    assert events[2].started_at == "not-a-timestamp"
    cluster = build_clusters(queries, window_seconds=300)[0]
    assert cluster.window_event_count == 3
    assert cluster.query_count == 4
    assert parse_event_time("") is None
    assert parse_event_time("garbage") is None


def test_zero_window_splits_every_distinct_occurrence_and_negative_rejected():
    queries = [
        _timed_query("2026-01-10T00:00:00Z", 10.0, 10),
        _timed_query("2026-01-10T00:00:01Z", 20.0, 20, line_no=2),
    ]
    events = build_window_events(queries, window_seconds=0)
    # Any positive gap exceeds a zero window, so each instant is its own event.
    assert len(events) == 2
    with pytest.raises(ValueError, match="window_seconds"):
        build_window_events(queries, window_seconds=-1)


def test_default_window_constant_and_event_dict_shape():
    assert DEFAULT_WINDOW_SECONDS == 300
    queries = [_timed_query("2026-01-10T00:00:00Z", 12.3456, 7)]
    cluster = build_clusters(queries)[0]
    payload = cluster.as_dict()
    assert payload["window_seconds"] == 300
    assert payload["window_event_count"] == 1
    assert payload["window_max_duration_ms"] == 12.346
    assert payload["window_max_rows_examined"] == 7
    event = payload["window_events"][0]
    assert set(event) == {
        "event_index", "started_at", "ended_at", "occurrence_count",
        "total_duration_ms", "max_query_duration_ms", "rows_examined",
        "rows_sent", "query_ids",
    }
