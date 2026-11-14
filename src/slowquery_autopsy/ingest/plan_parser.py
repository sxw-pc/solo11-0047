"""Parsers for synthetic JSON EXPLAIN and indented text plans."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..config import AppConfig
from ..models import PlanDocument, PlanNode
from ..util.hashing import sha256_file, stable_id

FINGERPRINT_META_RE = re.compile(r"(?:fingerprint|query_fingerprint)\s*[:=]\s*([0-9a-f]{16})", re.I)
TEXT_NODE_RE = re.compile(
    r"^(?P<indent>\s*)(?:->\s+)?(?P<body>.+?)\s+\(cost=[^)]*?rows=(?P<rows>\d+)[^)]*\)\s*$"
)
CONDITION_PREFIXES = (
    "filter:", "index cond:", "recheck cond:", "join filter:", "merge cond:",
    "hash cond:", "rows removed", "sort key:", "group key:",
)
TABLE_ON_RE = re.compile(r"\bon\s+([A-Za-z_][A-Za-z0-9_$]*)", re.I)
INDEX_RE = re.compile(r"\busing\s+([A-Za-z_][A-Za-z0-9_$]*)", re.I)


def _condition_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _table_node(table: dict[str, Any], path: str, depth: int, parent: str,
                in_nested: bool, nested_position: int) -> PlanNode:
    condition = " AND ".join(
        part for part in (
            _condition_text(table.get("attached_condition")),
            _condition_text(table.get("index_condition")),
            _condition_text(table.get("filter")),
        ) if part
    )
    rows = table.get("rows_examined_per_scan", table.get("rows_examined", table.get("rows", 0)))
    try:
        row_count = int(float(rows or 0))
    except (TypeError, ValueError):
        row_count = 0
    return PlanNode(
        path=path,
        operation=str(table.get("operation", "TABLE ACCESS")),
        depth=depth,
        table_name=str(table.get("table_name", table.get("table", ""))),
        access_type=str(table.get("access_type", table.get("type", ""))),
        rows=row_count,
        key_name=str(table.get("key", table.get("key_name", "")) or ""),
        condition=condition,
        parent_path=parent,
        in_nested_loop=in_nested,
        nested_loop_position=nested_position,
        using_filesort=bool(table.get("using_filesort", False)),
        using_temporary=bool(table.get("using_temporary_table", table.get("using_temporary", False))),
        extra={
            "possible_keys": table.get("possible_keys", []),
            "filtered": table.get("filtered"),
            "cost_info": table.get("cost_info", {}),
        },
    )


def _walk_json(obj: Any, path: str, depth: int, parent: str,
               nodes: list[PlanNode], in_nested: bool = False,
               nested_position: int = -1) -> None:
    if not isinstance(obj, dict):
        return
    if "query_block" in obj and isinstance(obj["query_block"], dict):
        _walk_json(obj["query_block"], path, depth, parent, nodes, in_nested, nested_position)
        return
    if "nested_loop" in obj and isinstance(obj["nested_loop"], list):
        nodes.append(PlanNode(
            path=path, operation="NESTED_LOOP", depth=depth,
            parent_path=parent, in_nested_loop=in_nested,
            nested_loop_position=nested_position,
        ))
        for index, item in enumerate(obj["nested_loop"]):
            _walk_json(item, f"{path}.{index}", depth + 1, path, nodes, True, index)
        return
    if "table" in obj and isinstance(obj["table"], dict):
        table = obj["table"]
        nodes.append(_table_node(table, path, depth, parent, in_nested, nested_position))
        if isinstance(table.get("nested_loop"), list):
            _walk_json(table, f"{path}.0", depth + 1, path, nodes, in_nested, nested_position)
        return
    for key in ("query_block", "plan", "result"):
        if key in obj:
            _walk_json(obj[key], path, depth, parent, nodes, in_nested, nested_position)
            return


def parse_json_plan(text: str, display_path: str) -> PlanDocument:
    plan_id = stable_id("plan", display_path, text)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return PlanDocument(plan_id, display_path, "json", error=f"invalid JSON at line {exc.lineno}: {exc.msg}")
    if not isinstance(data, dict):
        return PlanDocument(plan_id, display_path, "json", error="plan root must be a JSON object")
    fingerprint = str(data.get("fingerprint", data.get("query_fingerprint", "")) or "")
    if not fingerprint:
        match = FINGERPRINT_META_RE.search(text)
        fingerprint = match.group(1) if match else ""
    nodes: list[PlanNode] = []
    _walk_json(data, "0", 0, "", nodes)
    nodes.sort(key=lambda node: [int(part) if part.isdigit() else 0 for part in node.path.split(".")])
    return PlanDocument(plan_id, display_path, "json", fingerprint=fingerprint, nodes=nodes)


def _parse_text_node(body: str, path: str, depth: int, parent: str, rows: int,
                     in_nested: bool, nested_position: int) -> PlanNode:
    operation = body
    table_name = ""
    access_type = ""
    key_name = ""
    on_match = TABLE_ON_RE.search(body)
    if on_match:
        table_name = on_match.group(1)
        operation = body[: on_match.start()].strip()
        access_type = operation
    key_match = INDEX_RE.search(body)
    if key_match:
        key_name = key_match.group(1)
    return PlanNode(
        path=path,
        operation=operation,
        depth=depth,
        table_name=table_name,
        access_type=access_type,
        rows=rows,
        key_name=key_name,
        parent_path=parent,
        in_nested_loop=in_nested,
        nested_loop_position=nested_position,
    )


def parse_text_plan(text: str, display_path: str) -> PlanDocument:
    plan_id = stable_id("plan", display_path, text)
    metadata_match = FINGERPRINT_META_RE.search(text)
    fingerprint = metadata_match.group(1) if metadata_match else ""
    nodes: list[PlanNode] = []
    # Each stack frame is (indent, node, next_child_index).  The child counter
    # belongs to the frame instead of a global path -> count map: popping back
    # to an ancestor lets that ancestor resume numbering its own remaining
    # children, while a fresh root starts a new subtree with its own prefix.
    # A global map keyed by path leaks consumed indices between subtrees that
    # reuse a path (for example comment-separated sections that each begin at
    # the outermost indent), which shifts sibling indices and makes deeper
    # nodes appear under the previous sibling's prefix.
    stack: list[tuple[int, PlanNode, int]] = []
    root_index = 0
    last_node: PlanNode | None = None
    for raw_line in text.splitlines():
        if raw_line.lstrip().startswith("--"):
            last_node = None
            continue
        stripped = raw_line.strip()
        if not stripped:
            continue
        node_match = TEXT_NODE_RE.match(raw_line)
        if node_match:
            indent = len(node_match.group("indent"))
            while stack and indent <= stack[-1][0]:
                stack.pop()
            if not stack:
                # Independent top-level subtree: give it its own prefix so
                # repeated roots never collide on path "0", which is also the
                # persistence key for plan nodes.
                path = str(root_index)
                root_index += 1
                depth = 0
                parent_path = ""
                in_nested = False
                nested_position = -1
            else:
                parent_indent, parent, child_index = stack[-1]
                stack[-1] = (parent_indent, parent, child_index + 1)
                parent_path = parent.path
                path = f"{parent.path}.{child_index}"
                depth = parent.depth + 1
                in_nested = parent.in_nested_loop or "NESTED LOOP" in parent.operation.upper()
                nested_position = (
                    child_index if "NESTED LOOP" in parent.operation.upper() else -1
                )
            node = _parse_text_node(
                node_match.group("body"), path, depth, parent_path,
                int(node_match.group("rows")), in_nested, nested_position,
            )
            nodes.append(node)
            stack.append((indent, node, 0))
            last_node = node
            continue
        lower = stripped.lower()
        if last_node is not None and lower.startswith(CONDITION_PREFIXES):
            addition = stripped
            last_node.condition = (
                f"{last_node.condition} AND {addition}" if last_node.condition else addition
            )
    nodes.sort(key=lambda node: [int(part) if part.isdigit() else 0 for part in node.path.split(".")])
    return PlanDocument(plan_id, display_path, "text_indent", fingerprint=fingerprint, nodes=nodes)


def parse_plan_file(path: Path, display_path: str) -> PlanDocument:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError) as exc:
        return PlanDocument(stable_id("plan", display_path), display_path, "unknown", error=str(exc))
    if path.suffix.lower() == ".json":
        return parse_json_plan(text, display_path)
    return parse_text_plan(text, display_path)


def load_plans(config: AppConfig, cluster_ids: set[str]) -> list[PlanDocument]:
    plans: list[PlanDocument] = []
    for path in config.plan_files:
        display = config.display(path)
        if not path.is_file():
            plans.append(PlanDocument(stable_id("plan", display), display, "missing", error="file not found"))
            continue
        document = parse_plan_file(path, display)
        configured_link = config.plan_link_for(path)
        if configured_link:
            document.fingerprint = configured_link
        if document.fingerprint in cluster_ids:
            document.linked_cluster_id = document.fingerprint
        document.plan_id = stable_id("plan", display, sha256_file(path))
        plans.append(document)
    plans.sort(key=lambda plan: plan.source_file)
    return plans
