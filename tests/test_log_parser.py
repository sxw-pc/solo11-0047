from __future__ import annotations

from collections import Counter

from slowquery_autopsy.ingest.log_parser import (
    detect_encoding,
    parse_inputs,
    parse_mysql_slow,
    parse_postgres_csv,
)


def test_fixture_inputs_mixed_formats(config):
    outcome = parse_inputs(config)
    assert len(outcome.queries) == 22
    assert Counter(query.log_format for query in outcome.queries) == {
        "mysql_slow": 16, "postgres_csv": 6
    }
    assert len(outcome.unparsed) == 3
    assert len(outcome.file_stats) == 5
    first = outcome.queries[0]
    assert first.source_file == "fixtures/logs/mysql_slow_01.log"
    assert first.line_no == 1
    assert first.sql.startswith("SELECT *\nFROM orders")
    assert first.duration_ms == 2310.0
    assert first.lock_time_ms == 10.0
    assert first.rows_sent == 20 and first.rows_examined == 200000
    assert first.user == "svc_app" and first.client == "node-a"
    assert first.database == "shopdemo"
    assert first.timestamp == "2026-01-10T10:00:00Z"


def test_mysql_multiline_and_blank_lines():
    text = """# Time: 2026-02-01T10:00:00Z
# User@Host: svc_x[svc_x] @ node-x [synthetic]  Id: 1
# Schema: syntheticdb
# Query_time: 1.500000  Lock_time: 0.020000 Rows_sent: 4  Rows_examined: 900
SET timestamp=123;
SELECT id,
       name
FROM widgets
WHERE id IN (1, 2);
"""
    queries, unparsed = parse_mysql_slow(text, "inline.log")
    assert not unparsed
    assert len(queries) == 1
    assert queries[0].sql.count("\n") == 3
    assert queries[0].duration_ms == 1500.0
    assert queries[0].database == "syntheticdb"


def test_mysql_unparsed_blocks_never_crash():
    text = """junk outside
# Time: 2026-02-01T10:00:00Z
# User@Host: svc_x[svc_x] @ node-x [synthetic]  Id: 2
# Query_time: broken
SELECT 1;
# Time: 2026-02-01T10:01:00Z
# Query_time: 1.0  Lock_time: 0.0 Rows_sent: 1 Rows_examined: 1
"""
    queries, unparsed = parse_mysql_slow(text, "broken.log")
    assert queries == []
    assert [(item.file, item.line_no) for item in unparsed] == [
        ("broken.log", 1), ("broken.log", 2), ("broken.log", 6)
    ]
    assert "outside" in unparsed[0].reason


def test_postgres_csv_mapping_and_quoted_statement(config):
    text = (
        '2026-02-01T00:00:00Z,svc_r,syntheticdb,0.250,0.000,2,20,node-q,"SELECT id, name '
        'FROM widgets WHERE id = 9;"\n'
        "2026-02-01T00:01:00Z,svc_r,syntheticdb\n"
    )
    queries, unparsed = parse_postgres_csv(
        text, "pg.csv", config.formats["postgres_csv"]
    )
    assert len(queries) == 1 and len(unparsed) == 1
    assert queries[0].duration_ms == 250.0
    assert queries[0].sql == "SELECT id, name FROM widgets WHERE id = 9;"
    assert unparsed[0].line_no == 2
    assert "statement" in unparsed[0].reason


def test_encoding_detection_auto_and_explicit(tmp_path):
    gbk = tmp_path / "gbk.log"
    gbk.write_bytes("SELECT '客户';".encode("gbk"))
    text, encoding = detect_encoding(gbk, "auto")
    assert text == "SELECT '客户';" and encoding == "gbk"
    text, encoding = detect_encoding(gbk, "gbk")
    assert encoding == "gbk" and "客户" in text
