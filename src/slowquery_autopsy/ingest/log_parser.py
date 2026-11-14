"""Parsers for synthetic MySQL slow logs and PostgreSQL CSV logs."""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import AppConfig, InputSpec
from ..models import LogFileStat, SlowQuery, UnparsedLine
from ..util.hashing import sha256_file
from ..util.timefmt import mysql_timestamp_to_iso, normalize_timestamp

METRICS_RE = re.compile(
    r"#\s*Query_time:\s*(?P<duration>[0-9.]+).*?"
    r"Lock_time:\s*(?P<lock>[0-9.]+).*?"
    r"Rows_sent:\s*(?P<sent>\d+).*?"
    r"Rows_examined:\s*(?P<examined>\d+)",
    re.I,
)
USER_HOST_RE = re.compile(r"#\s*User@Host:\s*(?P<user>[^\s\[]+).*?@\s*(?P<host>[^\s\[]+)", re.I)
SCHEMA_RE = re.compile(r"#\s*Schema:\s*(?P<schema>\S+)", re.I)
TIME_RE = re.compile(r"^#\s*Time:\s*(?P<time>.+)$", re.I)
CSV_DEFAULTS = {
    "delimiter": ",",
    "quotechar": '"',
    "fields": {
        "timestamp": 0,
        "user": 1,
        "database": 2,
        "duration_sec": 3,
        "lock_sec": 4,
        "rows_sent": 5,
        "rows_examined": 6,
        "client": 7,
        "statement": 8,
    },
}


@dataclass
class ParseOutcome:
    queries: list[SlowQuery] = field(default_factory=list)
    unparsed: list[UnparsedLine] = field(default_factory=list)
    file_stats: list[LogFileStat] = field(default_factory=list)


def detect_encoding(path: Path, configured: str = "auto") -> tuple[str, str]:
    data = path.read_bytes()
    if configured not in ("auto", ""):
        return data.decode(configured), configured
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig"), "utf-8-sig"
    for encoding in ("utf-8", "gbk"):
        try:
            return data.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    raise ValueError(f"{path}: unable to decode as UTF-8-SIG, UTF-8 or GBK")


def _snippet(text: str, limit: int = 300) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[: limit - 3] + "..."


def _mysql_block(
    lines: list[str], start_index: int, block: list[str], display_path: str
) -> tuple[SlowQuery | None, list[UnparsedLine]]:
    first_line = start_index + 1
    unparsed: list[UnparsedLine] = []
    time_value = ""
    user = ""
    client = ""
    database = ""
    metrics_match = None
    metrics_offset = -1
    for offset, line in enumerate(block):
        time_match = TIME_RE.match(line)
        if time_match:
            time_value = time_match.group("time").strip()
        user_match = USER_HOST_RE.search(line)
        if user_match:
            user = user_match.group("user")
            client = user_match.group("host").strip("[]")
        schema_match = SCHEMA_RE.search(line)
        if schema_match:
            database = schema_match.group("schema")
        if metrics_match is None:
            metrics_match = METRICS_RE.search(line)
            if metrics_match:
                metrics_offset = offset
    if not metrics_match:
        return None, [
            UnparsedLine(display_path, first_line, _snippet(" ".join(block)), "missing # Query_time metadata")
        ]
    sql_lines: list[str] = []
    for line in block[metrics_offset + 1 :]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.match(r"(?i)^SET\s+timestamp\s*=", stripped):
            continue
        sql_lines.append(line.rstrip())
    sql = "\n".join(sql_lines).strip()
    if not sql:
        return None, [
            UnparsedLine(display_path, first_line, _snippet(" ".join(block)), "slow-log block contains no SQL")
        ]
    try:
        duration_ms = float(metrics_match.group("duration")) * 1000.0
        lock_ms = float(metrics_match.group("lock")) * 1000.0
        rows_sent = int(metrics_match.group("sent"))
        rows_examined = int(metrics_match.group("examined"))
    except ValueError:
        return None, [
            UnparsedLine(display_path, first_line, _snippet(" ".join(block)), "invalid numeric metadata")
        ]
    query = SlowQuery(
        source_file=display_path,
        line_no=first_line,
        timestamp=mysql_timestamp_to_iso(time_value),
        duration_ms=duration_ms,
        lock_time_ms=lock_ms,
        rows_sent=rows_sent,
        rows_examined=rows_examined,
        user=user,
        client=client,
        database=database,
        sql=sql,
        log_format="mysql_slow",
    )
    return query, unparsed


def parse_mysql_slow(text: str, display_path: str) -> tuple[list[SlowQuery], list[UnparsedLine]]:
    lines = text.splitlines()
    queries: list[SlowQuery] = []
    unparsed: list[UnparsedLine] = []
    index = 0
    while index < len(lines):
        if not lines[index].lstrip().startswith("# Time:"):
            if lines[index].strip():
                unparsed.append(
                    UnparsedLine(display_path, index + 1, _snippet(lines[index]), "line outside a slow-log block")
                )
            index += 1
            continue
        end = index + 1
        while end < len(lines) and not lines[end].lstrip().startswith("# Time:"):
            end += 1
        query, block_unparsed = _mysql_block(lines, index, lines[index:end], display_path)
        if query:
            queries.append(query)
        unparsed.extend(block_unparsed)
        index = end
    return queries, unparsed


def _csv_field(row: list[str], fields: dict[str, int], name: str, default: str = "") -> str:
    raw_index = fields.get(name)
    if raw_index is None:
        return default
    try:
        index = int(raw_index)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid CSV field index for {name!r}") from exc
    if index < 0 or index >= len(row):
        raise ValueError(f"missing CSV field {name!r} at index {index}")
    return row[index].strip()


def parse_postgres_csv(
    text: str, display_path: str, format_config: dict[str, Any]
) -> tuple[list[SlowQuery], list[UnparsedLine]]:
    config = dict(CSV_DEFAULTS)
    config.update(format_config)
    fields = dict(CSV_DEFAULTS["fields"])
    fields.update(config.get("fields", {}))
    delimiter = str(config.get("delimiter", ","))
    if len(delimiter) != 1:
        raise ValueError("CSV delimiter must be exactly one character")
    quotechar = str(config.get("quotechar", '"'))[:1] or '"'
    has_header = bool(config.get("header", False))
    queries: list[SlowQuery] = []
    unparsed: list[UnparsedLine] = []
    reader = csv.reader(io.StringIO(text), delimiter=delimiter, quotechar=quotechar)
    try:
        for row_index, row in enumerate(reader, start=1):
            line_no = reader.line_num or row_index
            if not row or all(not cell.strip() for cell in row):
                continue
            if has_header and row_index == 1:
                continue
            try:
                sql = _csv_field(row, fields, "statement")
                if not sql:
                    raise ValueError("empty statement")
                duration = float(_csv_field(row, fields, "duration_sec"))
                lock = float(_csv_field(row, fields, "lock_sec", "0") or 0)
                rows_sent = int(_csv_field(row, fields, "rows_sent", "0") or 0)
                rows_examined = int(_csv_field(row, fields, "rows_examined", "0") or 0)
                query = SlowQuery(
                    source_file=display_path,
                    line_no=line_no,
                    timestamp=normalize_timestamp(_csv_field(row, fields, "timestamp")),
                    duration_ms=duration * 1000.0,
                    lock_time_ms=lock * 1000.0,
                    rows_sent=rows_sent,
                    rows_examined=rows_examined,
                    user=_csv_field(row, fields, "user"),
                    client=_csv_field(row, fields, "client"),
                    database=_csv_field(row, fields, "database"),
                    sql=sql,
                    log_format="postgres_csv",
                )
                queries.append(query)
            except (ValueError, IndexError) as exc:
                unparsed.append(UnparsedLine(display_path, line_no, _snippet(",".join(row)), str(exc)))
    except csv.Error as exc:
        unparsed.append(UnparsedLine(display_path, reader.line_num, "", f"CSV error: {exc}"))
    return queries, unparsed


def parse_file(input_spec: InputSpec, format_config: dict[str, Any]) -> ParseOutcome:
    text, encoding = detect_encoding(input_spec.path, input_spec.encoding)
    if format_config["type"] == "mysql_slow":
        queries, unparsed = parse_mysql_slow(text, input_spec.display_path)
    else:
        queries, unparsed = parse_postgres_csv(text, input_spec.display_path, format_config)
    stat = LogFileStat(
        path=input_spec.display_path,
        log_format=input_spec.log_format,
        encoding=encoding,
        sha256=sha256_file(input_spec.path),
        line_count=len(text.splitlines()),
        parsed_count=len(queries),
        unparsed_count=len(unparsed),
    )
    return ParseOutcome(queries=queries, unparsed=unparsed, file_stats=[stat])


def parse_inputs(config: AppConfig) -> ParseOutcome:
    outcome = ParseOutcome()
    for input_spec in config.inputs:
        if not input_spec.path.is_file():
            raise FileNotFoundError(f"input file not found: {input_spec.display_path}")
        parsed = parse_file(input_spec, config.formats[input_spec.log_format])
        outcome.queries.extend(parsed.queries)
        outcome.unparsed.extend(parsed.unparsed)
        outcome.file_stats.extend(parsed.file_stats)
    outcome.unparsed.sort(key=lambda item: (item.file, item.line_no, item.reason))
    return outcome
