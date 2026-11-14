"""Static audit rules for parsed execution-plan trees."""

from __future__ import annotations

import re
from typing import Any, Iterable

from ..ingest.schema_loader import SchemaSnapshot
from ..models import PlanDocument, PlanNode

SEQ_ACCESS = {"all", "seq scan", "sequential scan"}
FUNCTION_RE = re.compile(
    r"(?i)\b(?P<func>lower|upper|date|substr|substring|coalesce|cast)\s*"
    r"\(\s*(?P<column>[A-Za-z_][A-Za-z0-9_$]*(?:\.[A-Za-z_][A-Za-z0-9_$]*)?)"
)
CAST_RE = re.compile(
    r"(?i)\b(?P<column>[A-Za-z_][A-Za-z0-9_$]*(?:\.[A-Za-z_][A-Za-z0-9_$]*)?)"
    r"\s*=\s*'(?P<value>-?[0-9]+(?:\.[0-9]+)?)'"
)
KNOWN_TYPES = {
    "full_scan_large_table", "function_wrapped_index", "implicit_type_cast",
    "nested_loop_inner_missing_index", "sort_temp_large",
}


def _split_column(column: str, node_table: str) -> tuple[str, str]:
    if "." in column:
        table, name = column.rsplit(".", 1)
        return table.strip('"`') or node_table, name.strip('"`')
    return node_table, column.strip('"`')


def _evidence(node: PlanNode, plan: PlanDocument, **extra: Any) -> dict[str, Any]:
    values = {
        "plan_file": plan.source_file,
        "node_path": node.path,
        "operation": node.operation,
        "table": node.table_name,
        "access_type": node.access_type,
        "node_rows": node.rows,
        "key": node.key_name,
        "condition": node.condition,
    }
    values.update(extra)
    return values


def _format(template: str, values: dict[str, Any]) -> str:
    try:
        return str(template).format(**values)
    except (KeyError, ValueError, TypeError):
        return str(template)


def _candidate(plan: PlanDocument, node: PlanNode, rule: dict[str, Any],
               evidence: dict[str, Any]) -> dict[str, Any]:
    values = dict(evidence)
    values.setdefault("actual", evidence.get("node_rows", 0))
    values.setdefault("threshold", rule.get("threshold", rule.get("min_rows", "")))
    return {
        "category": "plan",
        "rule_id": rule["id"],
        "severity": rule["severity"],
        "title": rule["title"],
        "description": _format(
            rule.get("description", "{rule_id} triggered at {node_path}"),
            {**values, "rule_id": rule["id"]},
        ),
        "recommendation": _format(rule.get("recommendation", "Review the execution plan."), values),
        "cluster_id": plan.linked_cluster_id,
        "query_id": "",
        "plan_file": plan.source_file,
        "node_path": node.path,
        "evidence": evidence,
    }


def _full_scan(node: PlanNode, rule: dict[str, Any], schema: SchemaSnapshot) -> dict[str, Any] | None:
    if not node.table_name or node.access_type.lower() not in SEQ_ACCESS:
        return None
    if node.key_name:
        return None
    threshold = int(rule.get("min_table_rows", 100000))
    row_count = schema.row_count(node.table_name)
    if row_count < threshold:
        return None
    return {
        "table": node.table_name,
        "table_rows": row_count,
        "access_type": node.access_type,
        "threshold": threshold,
        "node_path": node.path,
    }


def _function_index(node: PlanNode, rule: dict[str, Any], schema: SchemaSnapshot) -> dict[str, Any] | None:
    if not node.condition:
        return None
    pattern = rule.get("pattern")
    regex = re.compile(pattern, re.I) if pattern else FUNCTION_RE
    for match in regex.finditer(node.condition):
        column = match.groupdict().get("column")
        if not column:
            continue
        table, name = _split_column(column, node.table_name)
        if table and schema.is_indexed_column(table, name):
            return {
                "table": table,
                "column": name,
                "function": match.groupdict().get("func", ""),
                "expression": match.group(0),
                "index_wrapped": True,
                "node_path": node.path,
            }
    return None


def _implicit_cast(node: PlanNode, rule: dict[str, Any], schema: SchemaSnapshot) -> dict[str, Any] | None:
    if not node.condition:
        return None
    pattern = rule.get("pattern")
    regex = re.compile(pattern, re.I) if pattern else CAST_RE
    for match in regex.finditer(node.condition):
        table, name = _split_column(match.group("column"), node.table_name)
        if table and schema.is_numeric_column(table, name):
            table_schema = schema.table(table)
            return {
                "table": table,
                "column": name,
                "column_type": table_schema.column_type(name) if table_schema else "",
                "quoted_literal": match.group("value"),
                "node_path": node.path,
            }
    return None


def _nested_inner(node: PlanNode, rule: dict[str, Any], schema: SchemaSnapshot) -> dict[str, Any] | None:
    if not node.table_name or not node.in_nested_loop or node.nested_loop_position <= 0:
        return None
    if node.access_type.lower() not in SEQ_ACCESS or node.key_name:
        return None
    minimum = int(rule.get("min_inner_rows", 10000))
    row_count = schema.row_count(node.table_name)
    if row_count < minimum:
        return None
    return {
        "table": node.table_name,
        "table_rows": row_count,
        "access_type": node.access_type or "SEQ_SCAN",
        "nested_loop_position": node.nested_loop_position,
        "threshold": minimum,
        "node_path": node.path,
    }


def _sort_temp(node: PlanNode, rule: dict[str, Any], schema: SchemaSnapshot) -> dict[str, Any] | None:
    del schema
    minimum = int(rule.get("min_rows", 50000))
    sort_operator = "sort" in node.operation.lower()
    if not (node.using_filesort or node.using_temporary or sort_operator):
        return None
    if node.rows < minimum:
        return None
    return {
        "rows": node.rows,
        "threshold": minimum,
        "using_filesort": node.using_filesort,
        "using_temporary": node.using_temporary,
        "operation": node.operation,
        "node_path": node.path,
    }


CHECKERS = {
    "full_scan_large_table": _full_scan,
    "function_wrapped_index": _function_index,
    "implicit_type_cast": _implicit_cast,
    "nested_loop_inner_missing_index": _nested_inner,
    "sort_temp_large": _sort_temp,
}


def audit_plans(
    plans: Iterable[PlanDocument],
    rules: list[dict[str, Any]],
    schema: SchemaSnapshot,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for rule in rules:
        rule_type = str(rule.get("type", ""))
        if rule_type not in KNOWN_TYPES:
            raise ValueError(f"unknown plan audit rule type: {rule_type!r}")
        if not rule.get("enabled", True):
            continue
        checker = CHECKERS[rule_type]
        for plan in plans:
            if plan.error:
                continue
            for node in plan.nodes:
                evidence = checker(node, rule, schema)
                if evidence is not None:
                    evidence["rule_type"] = rule_type
                    evidence["plan_format"] = plan.plan_format
                    candidates.append(_candidate(plan, node, rule, evidence))
    candidates.sort(key=lambda item: (item["rule_id"], item["plan_file"], item["node_path"]))
    return candidates
