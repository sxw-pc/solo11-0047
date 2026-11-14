"""Typed loading and validation of the local YAML configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .util.hashing import canonical_json, sha256_text


class ConfigError(ValueError):
    """Raised when a configuration or referenced file is invalid."""


@dataclass(frozen=True)
class InputSpec:
    path: Path
    display_path: str
    log_format: str
    encoding: str = "auto"


@dataclass
class AppConfig:
    config_path: Path
    root: Path
    raw: dict[str, Any]
    inputs: list[InputSpec]
    formats: dict[str, Any]
    ledger_path: Path
    reports_dir: Path
    fingerprint_rules_path: Path
    fingerprint_rules: dict[str, Any]
    excluded_prefixes: list[str]
    quantile_method: str
    schema_path: Path
    plan_rules_path: Path
    plan_rules: dict[str, Any]
    plan_files: list[Path]
    plan_links: dict[str, str]
    cost_rules: list[dict[str, Any]]
    risk_overrides: dict[str, dict[str, Any]]
    fail_on_severity: list[str]
    diff_fail_on_new_high: bool
    report_options: dict[str, Any]
    source_hashes: dict[str, str] = field(default_factory=dict)

    def resolve(self, value: str) -> Path:
        candidate = Path(value)
        return candidate if candidate.is_absolute() else (self.root / candidate).resolve()

    def display(self, path: Path) -> str:
        try:
            return path.resolve().relative_to(self.root).as_posix()
        except ValueError:
            return path.as_posix()

    def plan_link_for(self, path: Path) -> str:
        display = self.display(path)
        return (
            self.plan_links.get(display)
            or self.plan_links.get(path.name)
            or self.plan_links.get(path.as_posix())
            or ""
        )

    def config_fingerprint(self) -> str:
        rules_part = self.source_hashes.get(self.display(self.fingerprint_rules_path), "")
        audit_part = self.source_hashes.get(self.display(self.plan_rules_path), "")
        payload = {
            "pipeline": self.raw,
            "fingerprint_rules_sha256": rules_part,
            "plan_audit_rules_sha256": audit_part,
        }
        return sha256_text(canonical_json(payload))

    def severity_can_fail(self, severity: str) -> bool:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        if not self.fail_on_severity:
            return False
        threshold = min(order.get(level, 99) for level in self.fail_on_severity)
        return order.get(severity, 99) <= threshold


def _require_mapping(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{where}: expected a mapping")
    return value


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ConfigError(f"{path}: file does not exist")
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            loaded = yaml.safe_load(handle)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ConfigError(f"{path}: cannot read YAML: {exc}") from exc
    if loaded is None:
        return {}
    return _require_mapping(loaded, str(path))


def _as_string_list(value: Any, where: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{where}: expected a list of strings")
    return list(value)


def load_config(path: str | Path) -> AppConfig:
    config_path = Path(path).resolve()
    raw = _read_yaml(config_path)
    if raw.get("version") != 1:
        raise ConfigError(f"{config_path}: unsupported or missing version (expected 1)")
    paths = _require_mapping(raw.get("paths", {}), "paths")
    root_value = paths.get("root", ".")
    root = (config_path.parent / root_value).resolve()
    if not root.is_dir():
        raise ConfigError(f"paths.root: directory does not exist: {root}")

    def rel(value: str, where: str) -> Path:
        if not isinstance(value, str) or not value:
            raise ConfigError(f"{where}: expected a non-empty path")
        resolved = Path(value)
        return resolved if resolved.is_absolute() else (root / resolved).resolve()

    raw_inputs = raw.get("inputs")
    if not isinstance(raw_inputs, list) or not raw_inputs:
        raise ConfigError("inputs: expected a non-empty list")
    inputs: list[InputSpec] = []
    for index, item in enumerate(raw_inputs):
        entry = _require_mapping(item, f"inputs[{index}]")
        input_path = rel(entry.get("path", ""), f"inputs[{index}].path")
        log_format = entry.get("format")
        if not isinstance(log_format, str) or not log_format:
            raise ConfigError(f"inputs[{index}].format: expected a format name")
        encoding = entry.get("encoding", "auto")
        if encoding not in ("auto", "utf-8", "utf-8-sig", "gbk"):
            raise ConfigError(f"inputs[{index}].encoding: unsupported value {encoding!r}")
        inputs.append(InputSpec(input_path, _display_for(root, input_path), log_format, encoding))

    formats = _require_mapping(raw.get("formats", {}), "formats")
    if not formats:
        raise ConfigError("formats: expected at least one format definition")
    for name, definition in formats.items():
        fmt = _require_mapping(definition, f"formats.{name}")
        if fmt.get("type") not in ("mysql_slow", "postgres_csv"):
            raise ConfigError(f"formats.{name}.type: unsupported parser type {fmt.get('type')!r}")
    for spec in inputs:
        if spec.log_format not in formats:
            raise ConfigError(f"input {spec.display_path}: unknown format {spec.log_format!r}")

    fingerprint_cfg = _require_mapping(raw.get("fingerprint", {}), "fingerprint")
    rules_path = rel(fingerprint_cfg.get("rules_file", ""), "fingerprint.rules_file")
    fingerprint_rules = _read_yaml(rules_path)
    if not isinstance(fingerprint_rules.get("rules"), list):
        raise ConfigError(f"{rules_path}: rules must be a list")
    excluded_prefixes = [
        prefix.upper()
        for prefix in _as_string_list(
            fingerprint_cfg.get("excluded_statement_prefixes"), "fingerprint.excluded_statement_prefixes"
        )
    ]
    quantile = fingerprint_cfg.get("quantile", "nearest_rank")
    if quantile != "nearest_rank":
        raise ConfigError("fingerprint.quantile: only nearest_rank is supported")

    cost_cfg = _require_mapping(raw.get("cost", {}), "cost")
    cost_rules = cost_cfg.get("rules", [])
    if not isinstance(cost_rules, list):
        raise ConfigError("cost.rules: expected a list")
    seen_rule_ids: set[str] = set()
    for index, rule in enumerate(cost_rules):
        item = _require_mapping(rule, f"cost.rules[{index}]")
        for key in ("id", "metric", "operator", "threshold", "severity", "title"):
            if key not in item:
                raise ConfigError(f"cost.rules[{index}]: missing {key}")
        if item["id"] in seen_rule_ids:
            raise ConfigError(f"cost.rules[{index}]: duplicate rule id {item['id']}")
        seen_rule_ids.add(item["id"])
        if item["operator"] not in ("gt", "gte", "lt", "lte", "eq"):
            raise ConfigError(f"cost.rules[{index}].operator: unsupported {item['operator']!r}")

    plan_cfg = _require_mapping(raw.get("plan", {}), "plan")
    schema_path = rel(plan_cfg.get("schema_file", ""), "plan.schema_file")
    audit_rules_path = rel(plan_cfg.get("rules_file", ""), "plan.rules_file")
    plan_rules = _read_yaml(audit_rules_path)
    if not isinstance(plan_rules.get("rules"), list):
        raise ConfigError(f"{audit_rules_path}: rules must be a list")
    audit_ids: set[str] = set()
    for index, rule in enumerate(plan_rules["rules"]):
        item = _require_mapping(rule, f"plan_audit_rules.rules[{index}]")
        for key in ("id", "type", "severity", "title"):
            if key not in item:
                raise ConfigError(f"plan rules[{index}]: missing {key}")
        if item["id"] in audit_ids:
            raise ConfigError(f"plan rules[{index}]: duplicate rule id {item['id']}")
        audit_ids.add(item["id"])
    plan_files = [
        rel(value, f"plan.files[{index}]")
        for index, value in enumerate(plan_cfg.get("files", []))
    ]
    links = _require_mapping(plan_cfg.get("links", {}), "plan.links")
    plan_links = {str(key): str(value) for key, value in links.items()}

    risk_cfg = _require_mapping(raw.get("risk", {}), "risk")
    overrides = _require_mapping(risk_cfg.get("overrides", {}), "risk.overrides")
    risk_overrides = {
        str(key): _require_mapping(value, f"risk.overrides.{key}")
        for key, value in overrides.items()
    }
    fail_on = _as_string_list(risk_cfg.get("fail_on_severity", []), "risk.fail_on_severity")
    for level in fail_on:
        if level not in ("critical", "high", "medium", "low", "info"):
            raise ConfigError(f"risk.fail_on_severity: invalid severity {level!r}")

    reports = _require_mapping(raw.get("reports", {}), "reports")
    formats_list = _as_string_list(reports.get("formats", ["markdown", "json", "html"]), "reports.formats")
    for name in formats_list:
        if name not in ("markdown", "json", "html"):
            raise ConfigError(f"reports.formats: unsupported format {name!r}")
    report_options = dict(reports)
    report_options["formats"] = formats_list
    report_options.setdefault("top_clusters", 8)
    report_options.setdefault("unparsed_preview", 10)
    report_options.setdefault("excluded_preview", 10)

    ledger_value = paths.get("ledger", "data/ledger.sqlite3")
    reports_value = paths.get("reports", "reports")
    ledger_path = rel(ledger_value, "paths.ledger")
    reports_dir = rel(reports_value, "paths.reports")
    source_hashes = {}
    for source in (rules_path, audit_rules_path):
        source_hashes[_display_for(root, source)] = sha256_text(source.read_text(encoding="utf-8"))

    return AppConfig(
        config_path=config_path,
        root=root,
        raw=raw,
        inputs=inputs,
        formats=formats,
        ledger_path=ledger_path,
        reports_dir=reports_dir,
        fingerprint_rules_path=rules_path,
        fingerprint_rules=fingerprint_rules,
        excluded_prefixes=excluded_prefixes,
        quantile_method=quantile,
        schema_path=schema_path,
        plan_rules_path=audit_rules_path,
        plan_rules=plan_rules,
        plan_files=plan_files,
        plan_links=plan_links,
        cost_rules=cost_rules,
        risk_overrides=risk_overrides,
        fail_on_severity=fail_on,
        diff_fail_on_new_high=bool(risk_cfg.get("diff_fail_on_new_high", False)),
        report_options=report_options,
        source_hashes=source_hashes,
    )


def _display_for(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()
