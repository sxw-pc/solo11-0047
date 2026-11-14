from __future__ import annotations

from slowquery_autopsy.analysis.plan_audit import audit_plans
from slowquery_autopsy.ingest.plan_parser import load_plans
from slowquery_autopsy.ingest.schema_loader import load_schema
from slowquery_autopsy.models import PlanDocument, PlanNode


def _node(**overrides) -> PlanNode:
    values = {
        "path": "0", "operation": "TABLE ACCESS", "depth": 0, "table_name": "orders",
        "access_type": "ALL", "rows": 500000, "parent_path": "", "in_nested_loop": False,
        "nested_loop_position": -1,
    }
    values.update(overrides)
    return PlanNode(**values)


def _audit(schema, rule_type: str, node: PlanNode, **options):
    rule = {
        "id": f"TEST-{rule_type}", "type": rule_type, "title": "test",
        "severity": "high", "enabled": True,
    }
    rule.update(options)
    plan = PlanDocument("plan-test", "synthetic.json", "json",
                        fingerprint="c", linked_cluster_id="c", nodes=[node])
    return audit_plans([plan], [rule], schema)


def test_fixture_plan_audit_triggers_every_rule(config, project_root):
    schema = load_schema(project_root / "fixtures/schema_snapshot.json")
    plans = load_plans(config, {"b6b972a308926333", "c34301cef6431f5f", "af4b9db7cdc9c045"})
    candidates = audit_plans(plans, config.plan_rules["rules"], schema)
    ids = {item["rule_id"] for item in candidates}
    assert ids == {
        "PLAN-FULLSCAN-001", "PLAN-FUNC-001", "PLAN-CAST-001",
        "PLAN-NL-INNER-001", "PLAN-SORT-001",
    }
    assert all(item["cluster_id"] for item in candidates)
    ok_only = [item for item in candidates if item["plan_file"].endswith("ok_plan.json")]
    assert ok_only == []


def test_full_scan_large_table_positive_negative(project_root):
    schema = load_schema(project_root / "fixtures/schema_snapshot.json")
    assert _audit(schema, "full_scan_large_table", _node())
    assert _audit(schema, "full_scan_large_table",
                 _node(table_name="products", rows=2000)) == []
    assert _audit(schema, "full_scan_large_table",
                 _node(access_type="range", key_name="idx_orders_customer")) == []


def test_function_wrapped_index_positive_negative(project_root):
    schema = load_schema(project_root / "fixtures/schema_snapshot.json")
    positive = _audit(schema, "function_wrapped_index", _node(
        table_name="customers", access_type="ref",
        condition="(lower(customers.region) = 'north')",
    ))
    negative = _audit(schema, "function_wrapped_index", _node(
        table_name="customers", access_type="ref",
        condition="(lower(customers.name) = 'north')",
    ))
    assert positive and positive[0]["evidence"]["column"] == "region"
    assert negative == []


def test_implicit_type_cast_positive_negative(project_root):
    schema = load_schema(project_root / "fixtures/schema_snapshot.json")
    positive = _audit(schema, "implicit_type_cast", _node(
        table_name="customers", condition="(customers.id = '42')"
    ))
    negative = _audit(schema, "implicit_type_cast", _node(
        table_name="customers", condition="(customers.status = '42')"
    ))
    assert positive and positive[0]["evidence"]["column_type"] == "bigint"
    assert negative == []


def test_nested_loop_inner_missing_index_positive_negative(project_root):
    schema = load_schema(project_root / "fixtures/schema_snapshot.json")
    positive = _audit(schema, "nested_loop_inner_missing_index", _node(
        table_name="order_items", in_nested_loop=True, nested_loop_position=1, rows=900000
    ))
    outer = _audit(schema, "nested_loop_inner_missing_index", _node(
        table_name="order_items", in_nested_loop=True, nested_loop_position=0, rows=900000
    ))
    assert positive and positive[0]["evidence"]["table_rows"] == 900000
    assert outer == []


def test_sort_temp_large_positive_negative(project_root):
    schema = load_schema(project_root / "fixtures/schema_snapshot.json")
    positive = _audit(schema, "sort_temp_large", _node(
        operation="TABLE ACCESS", using_filesort=True, rows=500000
    ), min_rows=50000)
    negative = _audit(schema, "sort_temp_large", _node(
        operation="TABLE ACCESS", using_filesort=True, rows=100
    ), min_rows=50000)
    assert positive and positive[0]["evidence"]["using_filesort"] is True
    assert negative == []
