"""Command-line entry point for run, serve, diff and validate."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from . import PROJECT_SLUG, __version__
from .analysis.diff import diff_batches
from .config import AppConfig, ConfigError, load_config
from .pipeline import (
    build_result,
    list_finding_baselines,
    register_baseline,
    remove_baseline,
    run,
    stored_result,
    validate_configuration,
)
from .report import write_reports
from .server.app import build_server
from .store.ledger import Ledger, LedgerError
from .util.hashing import stable_id
from .util.timefmt import normalize_timestamp, utc_now_iso


def _load(path: str) -> AppConfig:
    return load_config(path)


def _error(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


def cmd_run(args: argparse.Namespace) -> int:
    try:
        config = _load(args.config)
        if args.report_batch:
            result = stored_result(config, args.report_batch)
            inserted = False
            state = "re-rendered from ledger"
        else:
            created_at = normalize_timestamp(args.now) if args.now else utc_now_iso()
            result, inserted = run(config, created_at=created_at, persist=True)
            state = "inserted" if inserted else "already existed (idempotent no-op)"
        written = write_reports(config, result)
    except (ConfigError, OSError, ValueError, LedgerError) as exc:
        _error(str(exc))
        return 2
    print(f"batch {result.batch_id}: {state}")
    print(
        "queries={queries} clusters={clusters} plans={plans} findings={findings} "
        "high={high} suppressed={suppressed} unparsed={unparsed}".format(
            queries=len(result.queries), clusters=len(result.clusters), plans=len(result.plans),
            findings=len(result.findings),
            high=sum(1 for finding in result.findings
                     if finding.effective_severity in ("critical", "high")),
            suppressed=sum(1 for finding in result.findings if finding.suppressed),
            unparsed=len(result.unparsed),
        )
    )
    for name, path in written.items():
        if name != "html_files":
            print(f"{name}: {path}")
    failed = [finding for finding in result.findings if config.finding_can_fail(finding)]
    if failed:
        print(f"policy: {len(failed)} finding(s) meet fail_on_severity={config.fail_on_severity}"
              " (effective severity)")
        return 1
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    try:
        config = _load(args.config)
        if not config.ledger_path.is_file():
            _error(f"ledger not found: {config.display(config.ledger_path)}; run `run` first")
            return 2
        server = build_server(config.ledger_path, host="127.0.0.1", port=args.port)
    except (ConfigError, OSError, ValueError, LedgerError) as exc:
        _error(str(exc))
        return 2
    print(f"serve: http://127.0.0.1:{args.port} (read-only, loopback only)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        server.server_close()
    return 0


def _resolve_batch_pair(ledger: Ledger, base: str | None, head: str | None) -> tuple[str, str]:
    ids = ledger.batch_ids()
    if not ids:
        raise LedgerError("ledger contains no batches")
    head_id = head or ids[0]
    if base:
        base_id = base
    elif len(ids) >= 2:
        base_id = ids[1]
    else:
        raise LedgerError("need two batches or an explicit --base")
    for batch_id in (base_id, head_id):
        if not ledger.get_batch(batch_id):
            raise LedgerError(f"unknown batch: {batch_id}")
    return base_id, head_id


def cmd_diff(args: argparse.Namespace) -> int:
    try:
        config = _load(args.config)
        if not config.ledger_path.is_file():
            raise LedgerError(f"ledger not found: {config.display(config.ledger_path)}")
        with Ledger(config.ledger_path) as ledger:
            ledger.init_schema()
            base_id, head_id = _resolve_batch_pair(ledger, args.base, args.head)
            summary = diff_batches(
                base_id, head_id,
                ledger.list_clusters(base_id), ledger.list_clusters(head_id),
                ledger.list_findings(base_id), ledger.list_findings(head_id),
            )
            ledger.record_comparison(
                stable_id("cmp", base_id, head_id), base_id, head_id,
                utc_now_iso(), summary,
            )
    except (ConfigError, OSError, ValueError, LedgerError) as exc:
        _error(str(exc))
        return 2
    text = json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8", newline="\n")
    print(text, end="")
    counts = summary["counts"]
    print(
        f"diff: new_clusters={counts['new_clusters']} "
        f"disappeared_clusters={counts['disappeared_clusters']} "
        f"new_high={counts['new_high_findings']} "
        f"disappeared_high={counts['disappeared_high_findings']} "
        f"suppressed={counts.get('suppressed_findings', 0)} "
        f"original_high={counts.get('original_high_findings', 0)} "
        f"effective_high={counts.get('effective_high_findings', 0)}",
        file=sys.stderr,
    )
    should_fail = args.fail_on_new_high or config.diff_fail_on_new_high
    return 1 if should_fail and counts["new_high_findings"] > 0 else 0


def cmd_validate(args: argparse.Namespace) -> int:
    try:
        config = _load(args.config)
        errors = validate_configuration(config)
        if not errors:
            result = build_result(config)
            print(f"VALID {config.config_path}")
            print(
                f"inputs={len(config.inputs)} queries={len(result.queries)} "
                f"clusters={len(result.clusters)} plans={len(result.plans)} "
                f"findings={len(result.findings)} unparsed={len(result.unparsed)}"
            )
            suppressed = sum(1 for finding in result.findings if finding.suppressed)
            if suppressed:
                print(f"baseline: suppressed={suppressed} of {len(result.findings)} findings")
            if result.unparsed:
                for item in result.unparsed[:5]:
                    print(f"note: unparsed {item.file}:{item.line_no}: {item.reason}")
    except (ConfigError, OSError, ValueError) as exc:
        errors = [str(exc)]
    if errors:
        for error in errors:
            _error(error)
        return 2
    return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    try:
        config = _load(args.config)
        if args.baseline_command == "add":
            if not args.rule_id and not args.fingerprint:
                _error("baseline add requires --rule-id and/or --fingerprint")
                return 2
            baseline, affected = register_baseline(
                config,
                rule_id=args.rule_id or "",
                fingerprint=args.fingerprint or "",
                note=args.note or "",
                created_at=utc_now_iso(),
            )
            print(f"baseline {baseline.baseline_id}: registered")
            print(f"rule_id={baseline.rule_id or '—'} fingerprint={baseline.fingerprint or '—'} "
                  f"suppressed={affected}")
            return 0
        if args.baseline_command == "remove":
            if not remove_baseline(config, args.baseline_id):
                _error(f"unknown baseline: {args.baseline_id}")
                return 2
            print(f"baseline {args.baseline_id}: removed")
            return 0
        if args.baseline_command == "list":
            baselines = list_finding_baselines(config)
            if not baselines:
                print("no finding baselines registered")
                return 0
            for baseline in baselines:
                print(
                    f"{baseline.baseline_id}\trule_id={baseline.rule_id or '—'}\t"
                    f"fingerprint={baseline.fingerprint or '—'}\t"
                    f"source={baseline.origin or '—'}"
                )
            return 0
        _error("baseline: expected add, remove or list")
        return 2
    except (ConfigError, OSError, ValueError, LedgerError) as exc:
        _error(str(exc))
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROJECT_SLUG,
        description="Offline slow-query log and execution-plan autopsy.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    default_config = "configs/pipeline.yaml"

    run_parser = sub.add_parser("run", help="run one full analysis batch")
    run_parser.add_argument("--config", default=default_config)
    run_parser.add_argument("--now", help="fixed ISO-8601 timestamp for ledger idempotence testing")
    run_parser.add_argument("--report-batch", metavar="BATCH_ID",
                            help="re-render reports for an already stored batch from the ledger")
    run_parser.set_defaults(func=cmd_run)

    serve_parser = sub.add_parser("serve", help="serve the read-only local report UI")
    serve_parser.add_argument("--config", default=default_config)
    serve_parser.add_argument("--port", type=int, default=5000)
    serve_parser.set_defaults(func=cmd_serve)

    diff_parser = sub.add_parser("diff", help="compare two ledger batches")
    diff_parser.add_argument("--config", default=default_config)
    diff_parser.add_argument("--base", help="base batch id (defaults to second newest)")
    diff_parser.add_argument("--head", help="head batch id (defaults to newest)")
    diff_parser.add_argument("--output", help="optional path for the JSON diff")
    diff_parser.add_argument("--fail-on-new-high", action="store_true",
                             help="return exit code 1 when new high/critical findings appear")
    diff_parser.set_defaults(func=cmd_diff)

    validate_parser = sub.add_parser("validate", help="validate config, fixtures and plans")
    validate_parser.add_argument("--config", default=default_config)
    validate_parser.set_defaults(func=cmd_validate)

    baseline_parser = sub.add_parser(
        "baseline", help="manage finding baselines (rule id / fingerprint exemptions)"
    )
    baseline_parser.add_argument("--config", default=default_config)
    baseline_sub = baseline_parser.add_subparsers(dest="baseline_command", required=True)
    add_parser = baseline_sub.add_parser("add", help="register a finding baseline")
    add_parser.add_argument("--config", default=default_config)
    add_parser.add_argument("--rule-id", help="rule id to exempt, e.g. COST-AMP-001")
    add_parser.add_argument("--fingerprint", help="SQL fingerprint (cluster id) to exempt")
    add_parser.add_argument("--note", help="free-form note stored with the baseline")
    add_parser.set_defaults(func=cmd_baseline)
    remove_parser = baseline_sub.add_parser("remove", help="remove a finding baseline")
    remove_parser.add_argument("--config", default=default_config)
    remove_parser.add_argument("baseline_id")
    remove_parser.set_defaults(func=cmd_baseline)
    list_parser = baseline_sub.add_parser("list", help="list finding baselines")
    list_parser.add_argument("--config", default=default_config)
    list_parser.set_defaults(func=cmd_baseline)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
