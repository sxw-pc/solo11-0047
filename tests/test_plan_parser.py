from __future__ import annotations

from pathlib import Path

from slowquery_autopsy.ingest.plan_parser import (
    load_plans,
    parse_json_plan,
    parse_plan_file,
    parse_text_plan,
)


def test_json_plan_fixture(project_root):
    path = project_root / "fixtures/plans/full_scan.json"
    plan = parse_plan_file(path, "fixtures/plans/full_scan.json")
    assert not plan.error and plan.plan_format == "json"
    assert plan.fingerprint == "b6b972a308926333"
    node = plan.nodes[0]
    assert node.path == "0"
    assert node.table_name == "orders"
    assert node.access_type == "ALL"
    assert node.rows == 500000
    assert node.using_filesort is True
    assert "status" in node.condition


def test_json_nested_loop_paths(project_root):
    plan = parse_plan_file(
        project_root / "fixtures/plans/nested_loop.json", "nested.json"
    )
    assert [node.path for node in plan.nodes] == ["0", "0.0", "0.1"]
    assert plan.nodes[0].operation == "NESTED_LOOP"
    inner = plan.nodes[2]
    assert inner.in_nested_loop and inner.nested_loop_position == 1
    assert inner.table_name == "order_items" and inner.rows == 900000


def test_text_plan_parsing():
    text = """-- slowquery fingerprint: deadbeefdeadbeef
Limit  (cost=0.43..15.20 rows=20 width=64)
  ->  Index Scan using idx_orders_customer on orders o  (cost=0.43..14.90 rows=20 width=64)
        Index Cond: (customer_id = 42)
"""
    plan = parse_text_plan(text, "plan.txt")
    assert plan.plan_format == "text_indent"
    assert plan.fingerprint == "deadbeefdeadbeef"
    assert [node.path for node in plan.nodes] == ["0", "0.0"]
    assert plan.nodes[1].table_name == "orders"
    assert plan.nodes[1].key_name == "idx_orders_customer"
    assert "Index Cond" in plan.nodes[1].condition


def test_text_plan_sibling_subtrees_get_independent_child_indices():
    # Two branches under one root: A's deep child must not leak the index that
    # B should use, and B's deep child must hang off B, not off A's subtree.
    text = """Limit  (cost=0.43..15.20 rows=20 width=64)
  ->  Nested Loop  (cost=0.43..15.20 rows=20 width=64)
        ->  Index Scan on alpha  (cost=0.43..14.90 rows=20 width=64)
              ->  Seq Scan on alpha2  (cost=0.43..14.90 rows=20 width=64)
  ->  Hash Join  (cost=0.43..15.20 rows=20 width=64)
        ->  Seq Scan on beta  (cost=0.43..15.20 rows=20 width=64)
              ->  Seq Scan on beta2  (cost=0.43..15.20 rows=20 width=64)
"""
    plan = parse_text_plan(text, "multi.txt")
    triples = [(node.path, node.depth, node.parent_path) for node in plan.nodes]
    assert triples == [
        ("0", 0, ""),
        ("0.0", 1, "0"),
        ("0.0.0", 2, "0.0"),
        ("0.0.0.0", 3, "0.0.0"),
        ("0.1", 1, "0"),
        ("0.1.0", 2, "0.1"),
        ("0.1.0.0", 3, "0.1.0"),
    ]
    assert {node.path for node in plan.nodes} == {triple[0] for triple in triples}
    assert [node.table_name for node in plan.nodes if node.table_name] == [
        "alpha", "alpha2", "beta", "beta2",
    ]
    # depth must track the indentation level monotonically.
    assert [node.depth for node in plan.nodes] == [0, 1, 2, 3, 1, 2, 3]


def test_text_plan_comment_separated_subtrees_are_distinct():
    # Comment-separated sections each carry their own root; the second section
    # must not resume the first section's child indices or reuse its prefix.
    text = """-- section one
Limit  (cost=0.43..15.20 rows=20 width=64)
  ->  Index Scan on alpha  (cost=0.43..14.90 rows=20 width=64)
        ->  Seq Scan on alpha2  (cost=0.43..14.90 rows=20 width=64)
-- section two
Limit  (cost=0.43..15.20 rows=20 width=64)
  ->  Index Scan on beta  (cost=0.43..14.90 rows=20 width=64)
        ->  Seq Scan on beta2  (cost=0.43..14.90 rows=20 width=64)
"""
    plan = parse_text_plan(text, "sections.txt")
    assert [(n.path, n.depth, n.parent_path) for n in plan.nodes] == [
        ("0", 0, ""),
        ("0.0", 1, "0"),
        ("0.0.0", 2, "0.0"),
        ("1", 0, ""),
        ("1.0", 1, "1"),
        ("1.0.0", 2, "1.0"),
    ]
    assert len({node.path for node in plan.nodes}) == len(plan.nodes)
    # Parsing is deterministic across runs.
    again = parse_text_plan(text, "sections.txt")
    assert [(n.path, n.parent_path) for n in again.nodes] == [
        (n.path, n.parent_path) for n in plan.nodes
    ]


def test_text_plan_deep_nodes_fall_back_to_nearest_shallower_ancestor():
    # Indent widths are irregular, so only relative depth matters: each node
    # attaches to the nearest shallower ancestor, not to the previous node.
    text = """Limit  (cost=0.43..15.20 rows=20 width=64)
  ->  Nested Loop  (cost=0.43..15.20 rows=20 width=64)
     ->  Index Scan on alpha  (cost=0.43..14.90 rows=20 width=64)
       ->  Seq Scan on alpha2  (cost=0.43..14.90 rows=20 width=64)
   ->  Seq Scan on beta  (cost=0.43..15.20 rows=20 width=64)
"""
    plan = parse_text_plan(text, "irregular.txt")
    assert [(n.path, n.depth, n.parent_path) for n in plan.nodes] == [
        ("0", 0, ""),
        ("0.0", 1, "0"),
        ("0.0.0", 2, "0.0"),
        ("0.0.0.0", 3, "0.0.0"),
        ("0.0.1", 2, "0.0"),
    ]
    assert plan.nodes[4].table_name == "beta"



def test_invalid_plans_are_reported_not_raised():
    broken = parse_json_plan('{"query_block": ', "broken.json")
    assert broken.error and "invalid JSON" in broken.error
    root = parse_json_plan('["not", "a", "plan"]', "array.json")
    assert root.error and root.nodes == []
    empty = parse_text_plan("garbage without a cost line", "empty.txt")
    assert empty.error == "" and empty.nodes == []


def test_load_plans_and_config_links(config):
    plans = load_plans(config, {"b6b972a308926333", "c34301cef6431f5f", "af4b9db7cdc9c045"})
    assert len(plans) == 5
    linked = [plan for plan in plans if plan.linked_cluster_id]
    unlinked = [plan for plan in plans if not plan.linked_cluster_id]
    assert len(linked) == 4
    assert [Path(plan.source_file).name for plan in unlinked] == ["text_ok_plan.txt"]
    assert all(plan.plan_id.startswith("plan-") for plan in plans)
