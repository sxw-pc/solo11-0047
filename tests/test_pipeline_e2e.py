from __future__ import annotations

import json
import shutil
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from slowquery_autopsy.analysis.diff import diff_batches
from slowquery_autopsy.cli import main
from slowquery_autopsy.config import load_config
from slowquery_autopsy.ingest.log_parser import InMemoryParseCache, parse_inputs
from slowquery_autopsy.pipeline import build_result
from slowquery_autopsy.store.ledger import Ledger, open_readonly

NEW_BLOCK = """# Time: 2026-01-13T09:00:00Z
# User@Host: svc_app[svc_app] @ node-new [synthetic]  Id: 901
# Schema: shopdemo
# Query_time: 5.200000  Lock_time: 0.010000 Rows_sent: 1  Rows_examined: 42
SELECT COUNT(*) FROM order_items WHERE product_id = 77;
"""


def _project(tmp_path: Path, project_root: Path) -> Path:
    shutil.copytree(project_root / "fixtures", tmp_path / "fixtures")
    shutil.copytree(project_root / "configs", tmp_path / "configs")
    return tmp_path / "configs/pipeline.yaml"


def test_run_ledger_report_diff_chain(tmp_path, project_root, capsys):
    config_path = _project(tmp_path, project_root)
    assert main(["run", "--config", str(config_path), "--now", "2026-01-12T00:00:00Z"]) == 0
    ledger_path = tmp_path / "data/ledger.sqlite3"
    with open_readonly(ledger_path) as ledger:
        first = ledger.list_batches()[0]["batch_id"]
        assert ledger.get_batch(first)["summary"]["counts"]["queries"] == 20
    report_dir = tmp_path / "reports" / first
    assert (report_dir / "report.md").is_file()
    assert (report_dir / "report.json").is_file()
    assert (report_dir / "html/index.html").is_file()

    with (tmp_path / "fixtures/logs/mysql_slow_01.log").open("a", encoding="utf-8") as handle:
        handle.write(NEW_BLOCK)
    assert main(["run", "--config", str(config_path), "--now", "2026-01-12T01:00:00Z"]) == 0
    with open_readonly(ledger_path) as ledger:
        batches = ledger.list_batches()
        assert len(batches) == 2
        head = batches[0]["batch_id"]
        assert head != first
        assert ledger.get_batch(head)["summary"]["counts"]["queries"] == 21
    capsys.readouterr()
    assert main(["diff", "--config", str(config_path), "--base", first, "--head", head]) == 0
    captured = capsys.readouterr()
    diff = json.loads(captured.out)
    assert diff["base_batch_id"] == first and diff["head_batch_id"] == head
    assert diff["counts"]["new_clusters"] == 1
    assert diff["counts"]["disappeared_clusters"] == 0
    assert diff["clusters"]["new"][0]["query_count"] == 1
    with open_readonly(ledger_path) as ledger:
        assert len(ledger.list_comparisons()) == 1
    assert main(["validate", "--config", str(config_path)]) == 0


def test_fail_on_high_severity_exit_code(tmp_path, project_root):
    config_path = _project(tmp_path, project_root)
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    raw["risk"]["fail_on_severity"] = ["high"]
    config_path.write_text(yaml.safe_dump(raw, sort_keys=False, allow_unicode=True), encoding="utf-8")
    assert main(["run", "--config", str(config_path), "--now", "2026-01-12T00:00:00Z"]) == 1


def test_diff_pure_new_disappeared_and_high_findings():
    base_clusters = [
        {"cluster_id": "a", "query_count": 1, "total_duration_ms": 10.0, "sample_sql": "A"},
        {"cluster_id": "b", "query_count": 1, "total_duration_ms": 10.0, "sample_sql": "B"},
    ]
    head_clusters = [
        {"cluster_id": "b", "query_count": 2, "total_duration_ms": 20.0, "sample_sql": "B"},
        {"cluster_id": "c", "query_count": 1, "total_duration_ms": 30.0, "sample_sql": "C"},
    ]
    base_findings = [
        {"finding_id": "f1", "severity": "high", "rule_id": "R1"},
        {"finding_id": "f2", "severity": "low", "rule_id": "R2"},
    ]
    head_findings = [{"finding_id": "f3", "severity": "critical", "rule_id": "R3"}]
    diff = diff_batches("base", "head", base_clusters, head_clusters, base_findings, head_findings)
    assert [item["cluster_id"] for item in diff["clusters"]["new"]] == ["c"]
    assert [item["cluster_id"] for item in diff["clusters"]["disappeared"]] == ["a"]
    assert diff["counts"]["new_high_findings"] == 1
    assert diff["counts"]["disappeared_high_findings"] == 1


def _full_outcome(config):
    return parse_inputs(config, cache=None)


def _outcome_signature(outcome):
    """Everything the batch build_result derives from the parse stage."""
    return {
        "queries": [
            (q.source_file, q.line_no, q.timestamp, q.duration_ms, q.lock_time_ms,
             q.rows_sent, q.rows_examined, q.user, q.client, q.database, q.sql, q.log_format)
            for q in outcome.queries
        ],
        "unparsed": [(u.file, u.line_no, u.text, u.reason) for u in outcome.unparsed],
        "file_stats": [
            (s.path, s.log_format, s.encoding, s.sha256, s.line_count,
             s.parsed_count, s.unparsed_count, s.excluded_count)
            for s in outcome.file_stats
        ],
    }


def test_incremental_parse_all_cache_hits_matches_full_parse(tmp_path, project_root):
    config_path = _project(tmp_path, project_root)
    config = load_config(config_path)
    full = _full_outcome(config)

    cache = InMemoryParseCache()
    first = parse_inputs(config, cache=cache)
    assert set(first.cache_misses) == {spec.display_path for spec in config.inputs}
    assert first.cache_hits == []
    second = parse_inputs(config, cache=cache)
    assert set(second.cache_hits) == {spec.display_path for spec in config.inputs}
    assert second.cache_misses == []

    # queries / unparsed / file_stats must be identical to a full re-parse.
    assert _outcome_signature(second) == _outcome_signature(full)
    assert _outcome_signature(first) == _outcome_signature(full)
    # Cached rows deserialize into fresh objects, never shared mutable state.
    assert second.queries is not first.queries
    assert second.queries[0] is not first.queries[0]
    # Merge order preserves repeated source_file/line_no correspondence.
    assert [(q.source_file, q.line_no) for q in second.queries] == [
        (q.source_file, q.line_no) for q in full.queries
    ]


def test_incremental_parse_only_changed_file_reparsed(tmp_path, project_root):
    config_path = _project(tmp_path, project_root)
    config = load_config(config_path)
    changed = tmp_path / "fixtures/logs/mysql_slow_01.log"
    untouched = "fixtures/logs/mysql_slow_02.log"

    cache = InMemoryParseCache()
    before = parse_inputs(config, cache=cache)
    baseline_counts = {stat.path: stat for stat in before.file_stats}
    with changed.open("a", encoding="utf-8") as handle:
        handle.write(NEW_BLOCK)

    after = parse_inputs(config, cache=cache)
    changed_display = "fixtures/logs/mysql_slow_01.log"
    assert after.cache_misses == [changed_display]
    assert after.cache_hits == [
        spec.display_path for spec in config.inputs if spec.display_path != changed_display
    ]
    assert untouched in after.cache_hits

    full = _full_outcome(config)
    assert _outcome_signature(after) == _outcome_signature(full)
    changed_stat = next(stat for stat in after.file_stats if stat.path == "fixtures/logs/mysql_slow_01.log")
    old_stat = baseline_counts["fixtures/logs/mysql_slow_01.log"]
    assert changed_stat.sha256 != old_stat.sha256
    assert changed_stat.parsed_count == old_stat.parsed_count + 1
    untouched_stat = next(stat for stat in after.file_stats if stat.path == untouched)
    assert (untouched_stat.sha256, untouched_stat.line_count) == (
        baseline_counts[untouched].sha256,
        baseline_counts[untouched].line_count,
    )


def test_incremental_parse_encoding_change_invalidates_cache(tmp_path, project_root):
    config_path = _project(tmp_path, project_root)
    config = load_config(config_path)
    gbk_log = tmp_path / "fixtures/logs/gbk_encoded.log"
    gbk_log.write_bytes(
        "# Time: 2026-02-01T10:00:00Z\n"
        "# User@Host: svc_x[svc_x] @ node-x [synthetic]  Id: 1\n"
        "# Schema: 客户库\n"
        "# Query_time: 1.0  Lock_time: 0.0 Rows_sent: 1 Rows_examined: 2\n"
        "SELECT '客户' FROM dual;\n".encode("gbk")
    )
    config.inputs = list(config.inputs) + [
        _make_spec(config, gbk_log, "mysql_slow", "auto")
    ]
    gbk_display = config.inputs[-1].display_path

    cache = InMemoryParseCache()
    first = parse_inputs(config, cache=cache)
    gbk_stat = next(stat for stat in first.file_stats if stat.path == gbk_display)
    assert gbk_stat.encoding == "gbk"

    # Same bytes, different configured encoding: content hash is unchanged but
    # the cache key must still miss because decoding semantics changed.
    config.inputs[-1] = replace(config.inputs[-1], encoding="gbk")
    second = parse_inputs(config, cache=cache)
    assert second.cache_misses == [gbk_display]
    assert gbk_display not in second.cache_hits
    assert _outcome_signature(second) == _outcome_signature(_full_outcome(config))

    # A third run with stable config is fully cached again.
    third = parse_inputs(config, cache=cache)
    assert set(third.cache_hits) == {spec.display_path for spec in config.inputs}

    # Explicitly wrong encoding surfaces the same error with and without cache.
    config.inputs[-1] = replace(config.inputs[-1], encoding="utf-8")
    with pytest.raises(UnicodeDecodeError):
        parse_inputs(config, cache=cache)
    with pytest.raises(UnicodeDecodeError):
        parse_inputs(config, cache=None)


def test_incremental_parse_missing_file_raises_and_poisons_nothing(tmp_path, project_root):
    config_path = _project(tmp_path, project_root)
    config = load_config(config_path)
    cache = InMemoryParseCache()
    parse_inputs(config, cache=cache)

    vanished = tmp_path / "fixtures/logs/pg_log_01.log"
    vanished.unlink()
    with pytest.raises(FileNotFoundError, match="input file not found"):
        parse_inputs(config, cache=cache)

    # Restore the file: cached entries for the other files remain valid.
    shutil.copy(project_root / "fixtures/logs/pg_log_01.log", vanished)
    recovered = parse_inputs(config, cache=cache)
    assert "fixtures/logs/pg_log_01.log" in recovered.cache_hits
    assert _outcome_signature(recovered) == _outcome_signature(_full_outcome(config))


def test_incremental_parse_format_config_change_invalidates_cache(tmp_path, project_root):
    config_path = _project(tmp_path, project_root)
    config = load_config(config_path)
    cache = InMemoryParseCache()
    parse_inputs(config, cache=cache)

    pg_path = "fixtures/logs/pg_log_01.log"
    config.formats["postgres_csv"] = dict(config.formats["postgres_csv"])
    config.formats["postgres_csv"]["header"] = True
    changed = parse_inputs(config, cache=cache)
    assert changed.cache_misses == [pg_path]
    assert pg_path not in changed.cache_hits
    assert _outcome_signature(changed) == _outcome_signature(_full_outcome(config))


def test_incremental_parse_fingerprint_rules_change_invalidates_cache(tmp_path, project_root):
    config_path = _project(tmp_path, project_root)
    config = load_config(config_path)
    cache = InMemoryParseCache()
    parse_inputs(config, cache=cache)

    rules_path = tmp_path / "configs/fingerprint_rules.yaml"
    rules_text = rules_path.read_text(encoding="utf-8")
    rules_path.write_text(rules_text + "\n# parser-version-guard: rules payload changed\n",
                          encoding="utf-8")
    changed_config = load_config(config_path)
    changed = parse_inputs(changed_config, cache=cache)
    # Every key embeds the fingerprint rules hash, so no stale entry may hit.
    assert changed.cache_hits == []
    assert set(changed.cache_misses) == {spec.display_path for spec in changed_config.inputs}
    assert _outcome_signature(changed) == _outcome_signature(_full_outcome(changed_config))


def test_incremental_unparsed_sorted_with_mixed_new_and_cached_files(tmp_path, project_root):
    config_path = _project(tmp_path, project_root)
    config = load_config(config_path)
    cache = InMemoryParseCache()
    parse_inputs(config, cache=cache)

    # Append another malformed block to one file while others stay cached.
    malformed = tmp_path / "fixtures/logs/malformed_lines.log"
    with malformed.open("a", encoding="utf-8") as handle:
        handle.write("another stray line outside any block\n")
    outcome = parse_inputs(config, cache=cache)

    full = _full_outcome(config)
    keys = [(item.file, item.line_no) for item in outcome.unparsed]
    assert keys == sorted(keys)
    assert [(item.file, item.line_no, item.reason) for item in outcome.unparsed] == [
        (item.file, item.line_no, item.reason) for item in full.unparsed
    ]
    assert "fixtures/logs/malformed_lines.log" in outcome.cache_misses


def test_incremental_build_result_identical_and_batch_id_stable(tmp_path, project_root):
    config_path = _project(tmp_path, project_root)
    config = load_config(config_path)
    cache = InMemoryParseCache()

    first = build_result(config, created_at="2026-01-12T00:00:00Z", parse_cache=cache)
    second = build_result(config, created_at="2026-01-12T00:00:00Z", parse_cache=cache)
    full = build_result(config, created_at="2026-01-12T00:00:00Z")

    assert second.batch_id == first.batch_id == full.batch_id
    assert second.config_hash == first.config_hash
    assert second.input_hash == first.input_hash
    assert second.summary == full.summary
    assert [(q.source_file, q.line_no, q.query_id, q.fingerprint) for q in second.queries] == [
        (q.source_file, q.line_no, q.query_id, q.fingerprint) for q in full.queries
    ]
    assert [(u.file, u.line_no, u.reason) for u in second.unparsed] == [
        (u.file, u.line_no, u.reason) for u in full.unparsed
    ]
    assert [(s.path, s.sha256, s.line_count) for s in second.file_stats] == [
        (s.path, s.sha256, s.line_count) for s in full.file_stats
    ]


def test_ledger_parse_cache_powers_cli_runs_and_idempotent_noop(tmp_path, project_root, capsys):
    config_path = _project(tmp_path, project_root)
    ledger_path = tmp_path / "data/ledger.sqlite3"

    assert main(["run", "--config", str(config_path), "--now", "2026-01-12T00:00:00Z"]) in (0, 1)
    with Ledger(ledger_path) as ledger:
        assert ledger.parse_cache_size() == len(load_config(config_path).inputs)
        first_id = ledger.latest_batch_id()
        first_summary = ledger.get_batch(first_id)["summary"]
        first_stats = ledger.conn.execute(
            "SELECT path, sha256, line_count, parsed_count, unparsed_count "
            "FROM log_files ORDER BY path"
        ).fetchall()
        first_rows = [dict(row) for row in first_stats]

    # Identical rerun: every file is a cache hit and the batch is a no-op.
    assert main(["run", "--config", str(config_path), "--now", "2026-01-12T01:00:00Z"]) in (0, 1)
    with Ledger(ledger_path) as ledger:
        assert len(ledger.list_batches()) == 1
        assert ledger.latest_batch_id() == first_id
        second_rows = [
            dict(row) for row in ledger.conn.execute(
                "SELECT path, sha256, line_count, parsed_count, unparsed_count "
                "FROM log_files ORDER BY path"
            ).fetchall()
        ]
        assert second_rows == first_rows
        assert ledger.get_batch(first_id)["summary"] == first_summary
    output = capsys.readouterr().out
    assert "already existed (idempotent no-op)" in output

    # Change one file: only its cache entry is replaced; the new batch still
    # matches a from-scratch build of the same inputs.
    with (tmp_path / "fixtures/logs/mysql_slow_01.log").open("a", encoding="utf-8") as handle:
        handle.write(NEW_BLOCK)
    assert main(["run", "--config", str(config_path), "--now", "2026-01-12T02:00:00Z"]) in (0, 1)
    config = load_config(config_path)
    fresh = build_result(config, created_at="2026-01-12T02:00:00Z")
    with Ledger(ledger_path) as ledger:
        assert len(ledger.list_batches()) == 2
        head_id = ledger.latest_batch_id()
        assert head_id != first_id
        head_summary = ledger.get_batch(head_id)["summary"]
        assert head_summary["counts"] == fresh.summary["counts"]
        assert head_summary["counts"]["queries"] == first_summary["counts"]["queries"] + 1
        head_rows = [
            dict(row) for row in ledger.conn.execute(
                "SELECT path, sha256, line_count FROM log_files "
                "WHERE batch_id = ? ORDER BY path", (head_id,)
            ).fetchall()
        ]
        fresh_rows = [
            {"path": s.path, "sha256": s.sha256, "line_count": s.line_count}
            for s in sorted(fresh.file_stats, key=lambda s: s.path)
        ]
        assert head_rows == fresh_rows
        # Cached file_stats carry the current sha256/line_count, not stale ones.
        cached_row = next(
            row for row in head_rows
            if row["path"] == "fixtures/logs/mysql_slow_02.log"
        )
        assert cached_row["sha256"] == next(
            s.sha256 for s in fresh.file_stats if s.path == cached_row["path"]
        )
    capsys.readouterr()


def test_same_bytes_replaced_file_still_serves_correct_stats(tmp_path, project_root):
    config_path = _project(tmp_path, project_root)
    config = load_config(config_path)
    cache = InMemoryParseCache()
    first = parse_inputs(config, cache=cache)
    target = tmp_path / "fixtures/logs/mysql_slow_02.log"
    original_bytes = target.read_bytes()

    # Rewrite the file with identical bytes (new inode/mtime, same sha256).
    target.unlink()
    target.write_bytes(original_bytes)
    second = parse_inputs(config, cache=cache)
    assert "fixtures/logs/mysql_slow_02.log" in second.cache_hits
    stat = next(s for s in second.file_stats if s.path == "fixtures/logs/mysql_slow_02.log")
    assert stat.sha256 == next(s for s in first.file_stats
                               if s.path == "fixtures/logs/mysql_slow_02.log").sha256
    assert _outcome_signature(second) == _outcome_signature(first)


def test_prune_drops_stale_variants_but_keeps_removed_inputs_warm(tmp_path, project_root):
    config_path = _project(tmp_path, project_root)
    config = load_config(config_path)
    ledger_path = tmp_path / "data/ledger.sqlite3"
    with Ledger(ledger_path) as ledger:
        ledger.init_schema()
        parse_inputs(config, cache=ledger)
        assert ledger.parse_cache_size() == len(config.inputs)

        # Modifying one file replaces its key; the stale variant must be pruned.
        changed = tmp_path / "fixtures/logs/pg_log_01.log"
        with changed.open("a", encoding="utf-8") as handle:
            handle.write("2026-02-01T00:09:00Z,svc_r,db,0.1,0,1,1,node-z,\"SELECT 2;\"\n")
        parse_inputs(config, cache=ledger)
        assert ledger.parse_cache_size() == len(config.inputs)
        rows = ledger.conn.execute(
            "SELECT display_path, COUNT(*) n FROM parse_cache GROUP BY display_path"
        ).fetchall()
        assert {dict(row)["display_path"]: dict(row)["n"] for row in rows} == {
            spec.display_path: 1 for spec in config.inputs
        }

        # Removing an input from the config leaves its cache row warm (no
        # current key for that path, so prune must not touch it).
        removed = config.inputs[-1]
        config.inputs = config.inputs[:-1]
        parse_inputs(config, cache=ledger)
        kept = ledger.conn.execute(
            "SELECT COUNT(*) FROM parse_cache WHERE display_path = ?",
            (removed.display_path,),
        ).fetchone()[0]
        assert kept == 1


def test_repeated_source_file_keeps_line_no_correspondence(tmp_path, project_root):
    config_path = _project(tmp_path, project_root)
    config = load_config(config_path)
    # Reference the same physical file twice with distinct display paths is
    # impossible, so duplicate the spec as-is: repeated source_file entries.
    duplicated = list(config.inputs) + [config.inputs[0]]
    config.inputs = duplicated

    cache = InMemoryParseCache()
    cached_outcome = parse_inputs(config, cache=cache)
    full_outcome = parse_inputs(config, cache=None)

    ordering = [(q.source_file, q.line_no) for q in cached_outcome.queries]
    assert ordering == [(q.source_file, q.line_no) for q in full_outcome.queries]
    # Both occurrences of the repeated file appear in config order, and the
    # second copy's line numbers restart at 1 instead of shifting.
    repeated = [pair for pair in ordering if pair[0] == config.inputs[0].display_path]
    half = len(repeated) // 2
    assert repeated[:half] == repeated[half:]
    assert cached_outcome.file_stats[-1].path == config.inputs[0].display_path
    assert _outcome_signature(cached_outcome) == _outcome_signature(full_outcome)


def test_corrupt_cache_row_self_heals_without_losing_equivalence(tmp_path, project_root):
    config_path = _project(tmp_path, project_root)
    config = load_config(config_path)
    ledger_path = tmp_path / "data/ledger.sqlite3"
    with Ledger(ledger_path) as ledger:
        ledger.init_schema()
        warm = parse_inputs(config, cache=ledger)
        assert ledger.parse_cache_size() == len(config.inputs)

        # Corrupt every payload: getter treats corrupt rows as misses, so reads
        # fall back to parsing and repair the rows through put_parse_cache.
        ledger.conn.execute("UPDATE parse_cache SET payload_json = '{not json'")
        ledger.conn.commit()
        healed = parse_inputs(config, cache=ledger)
        assert healed.cache_hits == []
        assert set(healed.cache_misses) == {spec.display_path for spec in config.inputs}
        assert _outcome_signature(healed) == _outcome_signature(warm)

        # Repaired rows now serve normal hits again.
        rerun = parse_inputs(config, cache=ledger)
        assert set(rerun.cache_hits) == {spec.display_path for spec in config.inputs}
        assert ledger.parse_cache_size() == len(config.inputs)
        # Stored payloads are valid canonical JSON again.
        bad = ledger.conn.execute(
            "SELECT COUNT(*) FROM parse_cache WHERE payload_json NOT LIKE '{%'"
        ).fetchone()[0]
        assert bad == 0


def _make_spec(config, path: Path, log_format: str, encoding: str):
    from slowquery_autopsy.config import InputSpec

    display = config.display(path.resolve())
    return InputSpec(path=path.resolve(), display_path=display,
                     log_format=log_format, encoding=encoding)
