"""Parsers for synthetic MySQL slow logs and PostgreSQL CSV logs."""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from ..config import AppConfig, InputSpec
from ..models import LogFileStat, SlowQuery, UnparsedLine
from ..util.hashing import (
    file_parse_cache_key,
    sha256_bytes,
)
from ..util.timefmt import mysql_timestamp_to_iso, normalize_timestamp

# Bump whenever the output of parse_mysql_slow / parse_postgres_csv / file
# stat derivation changes shape or semantics. Stored inside every parse-cache
# key so a parser upgrade silently invalidates every cached entry.
LOG_PARSER_VERSION = 1

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
    cache_hits: list[str] = field(default_factory=list)
    cache_misses: list[str] = field(default_factory=list)


class ParseCache(Protocol):
    """File-level parse result cache shared between batches."""

    def get_parse_cache(self, cache_key: str) -> dict[str, Any] | None: ...

    def put_parse_cache(
        self, cache_key: str, display_path: str, file_sha256: str, payload: dict[str, Any]
    ) -> None: ...

    def prune_parse_cache(self, active_keys: set[str]) -> int: ...


class InMemoryParseCache:
    """Dict-backed ParseCache used by tests and by cache-free call sites."""

    def __init__(self) -> None:
        self._rows: dict[str, dict[str, Any]] = {}

    def get_parse_cache(self, cache_key: str) -> dict[str, Any] | None:
        return self._rows.get(cache_key)

    def put_parse_cache(
        self, cache_key: str, display_path: str, file_sha256: str, payload: dict[str, Any]
    ) -> None:
        self._rows[cache_key] = {
            "display_path": display_path,
            "sha256": file_sha256,
            "payload": payload,
        }

    def prune_parse_cache(self, active_keys: set[str]) -> int:
        active_paths = {
            row["display_path"] for key, row in self._rows.items() if key in active_keys
        }
        stale = [
            key for key, row in self._rows.items()
            if key not in active_keys and row["display_path"] in active_paths
        ]
        for key in stale:
            del self._rows[key]
        return len(stale)


def detect_encoding(
    path: Path, configured: str = "auto", data: bytes | None = None
) -> tuple[str, str]:
    if data is None:
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


def parse_bytes(
    input_spec: InputSpec,
    format_config: dict[str, Any],
    data: bytes,
    file_sha256: str,
) -> ParseOutcome:
    """Parse one file from its raw bytes; no filesystem access beyond decode."""
    text, encoding = detect_encoding(input_spec.path, input_spec.encoding, data)
    if format_config["type"] == "mysql_slow":
        queries, unparsed = parse_mysql_slow(text, input_spec.display_path)
    else:
        queries, unparsed = parse_postgres_csv(text, input_spec.display_path, format_config)
    stat = LogFileStat(
        path=input_spec.display_path,
        log_format=input_spec.log_format,
        encoding=encoding,
        sha256=file_sha256,
        line_count=len(text.splitlines()),
        parsed_count=len(queries),
        unparsed_count=len(unparsed),
    )
    return ParseOutcome(queries=queries, unparsed=unparsed, file_stats=[stat])


def parse_file(input_spec: InputSpec, format_config: dict[str, Any]) -> ParseOutcome:
    data = input_spec.path.read_bytes()
    return parse_bytes(input_spec, format_config, data, sha256_bytes(data))


def outcome_to_payload(outcome: ParseOutcome) -> dict[str, Any]:
    """Serialize a single-file outcome into a JSON-safe cache payload."""
    if len(outcome.file_stats) != 1:
        raise ValueError("cache payload requires exactly one file stat")
    stat = outcome.file_stats[0]
    return {
        "parser_version": LOG_PARSER_VERSION,
        "queries": [query.as_dict() for query in outcome.queries],
        "unparsed": [item.as_dict() for item in outcome.unparsed],
        "file_stat": {
            "path": stat.path,
            "log_format": stat.log_format,
            "encoding": stat.encoding,
            "sha256": stat.sha256,
            "line_count": stat.line_count,
            "parsed_count": stat.parsed_count,
            "unparsed_count": stat.unparsed_count,
            "excluded_count": stat.excluded_count,
        },
    }


def outcome_from_payload(payload: dict[str, Any]) -> ParseOutcome:
    """Rebuild a fresh, mutable ParseOutcome from a cache payload.

    Deserialization always allocates new model instances so callers can never
    mutate shared cached state. excluded_count is reset to zero because it is a
    pipeline-level (fingerprint/exclusion) derivation, not a parser result.
    """
    if payload.get("parser_version") != LOG_PARSER_VERSION:
        raise ValueError("stale parser version in parse cache payload")
    stat_payload = dict(payload["file_stat"])
    stat_payload["excluded_count"] = 0
    stat = LogFileStat(**stat_payload)
    queries = [SlowQuery(**dict(item)) for item in payload.get("queries", [])]
    unparsed = [UnparsedLine(**dict(item)) for item in payload.get("unparsed", [])]
    return ParseOutcome(queries=queries, unparsed=unparsed, file_stats=[stat])


def _fingerprint_rules_hash(config: AppConfig) -> str:
    return config.source_hashes.get(config.display(config.fingerprint_rules_path), "")


def parse_inputs(
    config: AppConfig, cache: ParseCache | None = None
) -> ParseOutcome:
    """Parse every configured input, reusing unchanged files from ``cache``.

    Files are processed strictly in configuration order, so the merged
    queries keep each repeated source_file's line_no ordering and unparsed
    entries receive the same final (file, line_no, reason) sort as a full
    parse. A cache entry is only trusted when its key -- which binds content
    hash, format, format config, encoding, parser version and fingerprint
    rules -- matches and its stored identity/sha256 still describe the file
    currently on disk.
    """
    outcome = ParseOutcome()
    rules_hash = _fingerprint_rules_hash(config)
    active_keys: set[str] = set()
    for input_spec in config.inputs:
        if not input_spec.path.is_file():
            raise FileNotFoundError(f"input file not found: {input_spec.display_path}")
        format_config = config.formats[input_spec.log_format]
        data = input_spec.path.read_bytes()
        file_sha256 = sha256_bytes(data)
        cache_key = file_parse_cache_key(
            input_spec.display_path,
            file_sha256,
            input_spec.log_format,
            format_config,
            input_spec.encoding,
            LOG_PARSER_VERSION,
            rules_hash,
        )
        active_keys.add(cache_key)
        cached = cache.get_parse_cache(cache_key) if cache is not None else None
        if cached is not None and (
            cached.get("display_path") != input_spec.display_path
            or cached.get("sha256") != file_sha256
        ):
            cached = None
        parsed: ParseOutcome | None = None
        if cached is not None:
            try:
                candidate = outcome_from_payload(cached["payload"])
            except (KeyError, TypeError, ValueError):
                # Corrupt or schema-incompatible cache row: fall back to parsing.
                candidate = None
            # Never replay stale stats; file_stats must describe this run.
            if candidate is not None and (
                candidate.file_stats[0].sha256 != file_sha256
                or candidate.file_stats[0].path != input_spec.display_path
            ):
                candidate = None
            if candidate is not None:
                parsed = candidate
                outcome.cache_hits.append(input_spec.display_path)
        if parsed is None:
            parsed = parse_bytes(input_spec, format_config, data, file_sha256)
            if cache is not None:
                cache.put_parse_cache(
                    cache_key,
                    input_spec.display_path,
                    file_sha256,
                    outcome_to_payload(parsed),
                )
            outcome.cache_misses.append(input_spec.display_path)
        outcome.queries.extend(parsed.queries)
        outcome.unparsed.extend(parsed.unparsed)
        outcome.file_stats.extend(parsed.file_stats)
    outcome.unparsed.sort(key=lambda item: (item.file, item.line_no, item.reason))
    if cache is not None:
        # Remove stale variants of files still in the input set; entries for
        # inputs that were removed from the config are left warm on purpose.
        cache.prune_parse_cache(active_keys)
    return outcome
