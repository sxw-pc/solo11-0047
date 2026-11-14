#!/usr/bin/env python3
"""Deterministically regenerate synthetic fixtures and print fingerprint ids."""

from __future__ import annotations

import csv
import io
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import yaml  # noqa: E402

from slowquery_autopsy.analysis.fingerprint import fingerprint_id  # noqa: E402
from slowquery_autopsy.analysis.normalize import normalize_sql  # noqa: E402

RULES = yaml.safe_load((ROOT / "configs/fingerprint_rules.yaml").read_text(encoding="utf-8"))
SQL = {
    "A": "SELECT *\nFROM orders\nWHERE customer_id = 42\n  AND status = 'PAID'\nORDER BY created_at DESC\nLIMIT 20;",
    "B": "SELECT c.id, c.name, COUNT(o.id) AS order_count\nFROM customers c\nJOIN orders o ON o.customer_id = c.id\nWHERE lower(c.region) = 'north'\nGROUP BY c.id, c.name\nORDER BY order_count DESC\nLIMIT 100;",
    "C": "SELECT oi.order_id, SUM(oi.quantity) AS qty\nFROM order_items oi\nJOIN orders o ON o.id = oi.order_id\nWHERE o.created_at >= '2026-01-01'\nGROUP BY oi.order_id\nORDER BY qty DESC\nLIMIT 50;",
    "E": "SELECT id, name FROM products WHERE id = 7;",
}
FINGERPRINTS = {
    key: fingerprint_id((n := normalize_sql(sql, RULES)).text, n.tokens) for key, sql in SQL.items()
}


def mysql_block(ts: str, client: str, duration: float, lock: float, sent: int,
                examined: int, sql: str, query_id: int) -> str:
    return (
        f"# Time: {ts}\n# User@Host: svc_app[svc_app] @ {client} [synthetic]  Id: {query_id}\n"
        f"# Schema: shopdemo\n# Query_time: {duration:.6f}  Lock_time: {lock:.6f} "
        f"Rows_sent: {sent}  Rows_examined: {examined}\nSET timestamp=1768039200;\n{sql}\n\n"
    )


def write_mysql() -> None:
    blocks = [
        mysql_block("2026-01-10T10:00:00Z", "node-a", 2.31, 0.01, 20, 200000, SQL["A"], 101),
        mysql_block("2026-01-10T10:01:00Z", "node-a", 2.80, 0.01, 20, 240000,
                    SQL["A"].replace("customer_id = 42", "customer_id = 99").replace("'PAID'", "'SHIPPED'"), 102),
        mysql_block("2026-01-10T10:02:00Z", "node-b", 2.42, 0.01, 20, 210000,
                    SQL["A"].replace("customer_id = 42", "customer_id = 7").replace("'PAID'", "'REFUNDED'"), 103),
        mysql_block("2026-01-10T10:03:00Z", "node-b", 1.80, 0.70, 80, 120000,
                    SQL["B"].replace("'north'", "'south'"), 104),
        mysql_block("2026-01-10T10:04:00Z", "node-a", 0.40, 0.00, 0, 0,
                    "SET SESSION long_query_time = 0.2;", 105),
        mysql_block("2026-01-10T10:05:00Z", "node-a", 0.35, 0.00, 12, 2000,
                    "SHOW INDEX FROM orders;", 106),
    ]
    for index, (duration, lock, sent, examined, customer, status) in enumerate([
        (2.55, 0.01, 20, 220000, 44, "PAID"), (2.66, 0.02, 20, 205000, 12, "NEW"),
        (2.91, 0.01, 20, 250000, 81, "PAID"), (3.05, 0.02, 20, 260000, 33, "CANCELLED"),
        (3.20, 0.01, 20, 230000, 5, "PAID"),
    ]):
        sql = SQL["A"].replace("customer_id = 42", f"customer_id = {customer}").replace("'PAID'", f"'{status}'")
        blocks.append(mysql_block(f"2026-01-10T11:0{index}:00Z", "node-c" if index % 2 else "node-a",
                                  duration, lock, sent, examined, sql, 201 + index))
    blocks.append(mysql_block("2026-01-10T11:06:00Z", "node-b", 2.05, 0.80, 80, 130000,
                              SQL["B"].replace("'north'", "'east'"), 206))
    blocks.append(mysql_block("2026-01-10T11:07:00Z", "node-c", 2.40, 1.00, 80, 140000,
                              SQL["B"].replace("'north'", "'west'"), 207))
    for index, (duration, examined) in enumerate(((4.00, 850000), (4.40, 920000))):
        blocks.append(mysql_block(f"2026-01-10T11:1{index}:00Z", "node-c", duration, 0.02, 50,
                                  examined, SQL["C"].replace("'2026-01-01'", f"'2026-01-0{index + 2}'"),
                                  208 + index))
    (ROOT / "fixtures/logs/mysql_slow_01.log").write_text("".join(blocks[:6]), encoding="utf-8")
    (ROOT / "fixtures/logs/mysql_slow_02.log").write_text("".join(blocks[6:]), encoding="utf-8")


def pg_row(ts: str, duration: float, lock: float, sent: int, examined: int, client: str, sql: str) -> str:
    buffer = io.StringIO()
    csv.writer(buffer, lineterminator="\n").writerow([
        ts, "svc_report", "shopdemo", f"{duration:.3f}", f"{lock:.3f}",
        sent, examined, client, sql.replace("\n", " "),
    ])
    return buffer.getvalue()


def write_logs() -> None:
    write_mysql()
    rows = [
        pg_row("2026-01-10T12:00:00Z", 2.45, 0.01, 20, 215000, "node-d",
               SQL["A"].replace("customer_id = 42", "customer_id = 501")),
        pg_row("2026-01-10T12:01:00Z", 2.70, 0.01, 20, 225000, "node-d",
               SQL["A"].replace("customer_id = 42", "customer_id = 502").replace("'PAID'", "'NEW'")),
        pg_row("2026-01-10T12:02:00Z", 2.20, 0.90, 80, 135000, "node-e",
               SQL["B"].replace("'north'", "'central'")),
        pg_row("2026-01-10T12:03:00Z", 4.80, 0.03, 50, 960000, "node-e",
               SQL["C"].replace("'2026-01-01'", "'2026-01-09'")),
    ]
    rows.append("2026-01-10T12:04:00Z,svc_report,shopdemo\n")
    (ROOT / "fixtures/logs/pg_log_01.log").write_text("".join(rows), encoding="utf-8")
    malformed = (
        "this synthetic line is intentionally outside any slow-log block\n"
        + mysql_block("2026-01-10T13:00:00Z", "node-f", 0.90, 0.01, 1, 100, SQL["E"], 301)
        + "# Time: 2026-01-10T13:01:00Z\n"
        + "# User@Host: svc_app[svc_app] @ node-f [synthetic]  Id: 302\n"
        + "# Query_time: broken\nSELECT missing_metadata FROM ghost_table;\n\n"
    )
    (ROOT / "fixtures/logs/malformed_lines.log").write_text(malformed, encoding="utf-8")


def write_schema() -> None:
    schema = {"database": "shopdemo", "tables": {
        "orders": {"row_count": 500000, "columns": {"id": "bigint", "customer_id": "bigint",
                   "status": "varchar(16)", "created_at": "datetime", "total": "decimal(12,2)"},
                   "indexes": [{"name": "PRIMARY", "columns": ["id"]},
                   {"name": "idx_orders_customer", "columns": ["customer_id"]},
                   {"name": "idx_orders_status", "columns": ["status"]},
                   {"name": "idx_orders_created", "columns": ["created_at"]}]},
        "customers": {"row_count": 50000, "columns": {"id": "bigint", "name": "varchar(80)",
                      "region": "varchar(32)", "status": "varchar(16)", "email": "varchar(120)",
                      "created_at": "datetime"},
                      "indexes": [{"name": "PRIMARY", "columns": ["id"]},
                      {"name": "idx_customers_region", "columns": ["region"]},
                      {"name": "idx_customers_status", "columns": ["status"]}]},
        "order_items": {"row_count": 900000, "columns": {"id": "bigint", "order_id": "bigint",
                        "product_id": "bigint", "quantity": "int"},
                        "indexes": [{"name": "PRIMARY", "columns": ["id"]}]},
        "products": {"row_count": 2000, "columns": {"id": "bigint", "name": "varchar(120)",
                     "price": "decimal(10,2)"}, "indexes": [{"name": "PRIMARY", "columns": ["id"]}]},
    }}
    (ROOT / "fixtures/schema_snapshot.json").write_text(
        json.dumps(schema, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_plans() -> None:
    def table(name: str, access: str, key, rows: int, condition: str, **extra) -> dict:
        node = {"table_name": name, "access_type": access, "key": key,
                "rows_examined_per_scan": rows, "rows_produced_per_join": rows // 2,
                "filtered": "50.00", "attached_condition": condition}
        node.update(extra)
        return node

    plans = {
        "full_scan.json": {"format": "mysql_json_explain", "fingerprint": FINGERPRINTS["A"],
            "query_block": {"select_id": 1, "cost_info": {"query_cost": "125000.00"},
                "table": table("orders", "ALL", None, 500000, "(orders.status = 'PAID')",
                               possible_keys=["idx_orders_customer", "idx_orders_status"],
                               using_filesort=True)}},
        "bad_index.json": {"format": "mysql_json_explain", "fingerprint": FINGERPRINTS["B"],
            "query_block": {"select_id": 1, "cost_info": {"query_cost": "88000.00"},
                "table": table("customers", "ref", "idx_customers_region", 120000,
                    "((lower(customers.region) = 'north') and (customers.id = '42'))",
                    possible_keys=["idx_customers_region", "PRIMARY"])}},
        "nested_loop.json": {"format": "mysql_json_explain", "fingerprint": FINGERPRINTS["C"],
            "query_block": {"select_id": 1, "cost_info": {"query_cost": "640000.00"}, "nested_loop": [
                {"table": table("customers", "ALL", None, 50000, "(customers.region = 'north')")},
                {"table": table("order_items", "ALL", None, 900000,
                                "(order_items.order_id = customers.id)")}]}},
        "ok_plan.json": {"format": "mysql_json_explain", "fingerprint": FINGERPRINTS["A"],
            "query_block": {"select_id": 1, "table": table(
                "orders", "range", "idx_orders_customer", 120, "(orders.customer_id = 42)")}},
    }
    for name, plan in plans.items():
        (ROOT / "fixtures/plans" / name).write_text(
            json.dumps(plan, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    text_plan = (
        "-- slowquery fingerprint: deadbeefdeadbeef\n"
        "Limit  (cost=0.43..15.20 rows=20 width=64)\n"
        "  ->  Index Scan using idx_orders_customer on orders o  (cost=0.43..14.90 rows=20 width=64)\n"
        "        Index Cond: (customer_id = 42)\n"
    )
    (ROOT / "fixtures/plans/text_ok_plan.txt").write_text(text_plan, encoding="utf-8")


def main() -> None:
    write_logs()
    write_schema()
    write_plans()
    print(json.dumps(FINGERPRINTS, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
