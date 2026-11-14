from __future__ import annotations

import copy

from slowquery_autopsy.analysis.normalize import (
    normalize_sql,
    strip_comments,
    tokenize,
)


def test_literal_variants_normalize_identically(config):
    left = normalize_sql(
        "select * from orders where customer_id = 42 and status in ('PAID','NEW') limit 20;",
        config.fingerprint_rules,
    )
    right = normalize_sql(
        "SELECT *\nFROM orders\nWHERE customer_id = 987\n  AND status IN ('X', 'Y')\nLIMIT 10, 30;",
        config.fingerprint_rules,
    )
    assert left.text == right.text
    assert left.tokens == right.tokens
    assert left.text == "SELECT * FROM orders WHERE customer_id = ? AND status IN (?) LIMIT ?;"
    assert left.applied_rules == right.applied_rules


def test_comments_and_string_safety():
    text = "SELECT '--not-a-comment', id /* hidden */ FROM t -- tail\n WHERE id = 1;"
    assert strip_comments(text) == "SELECT '--not-a-comment', id   FROM t  \n WHERE id = 1;"
    assert "not" in tokenize(text)
    normalized = normalize_sql(
        "SELECT /* c */ id FROM t WHERE note = 'a -- b' AND id = 9;",
        {"rules": [
            {"id": "c", "type": "strip_comments"},
            {"id": "s", "type": "replace_string_literals"},
            {"id": "n", "type": "replace_numeric_literals"},
        ]},
    )
    assert "/*" not in normalized.text and "-- b" not in normalized.text
    assert normalized.text == "SELECT id FROM t WHERE note = ? AND id = ?;"


def test_declarative_regex_rule_extension(config):
    rules = copy.deepcopy(config.fingerprint_rules["rules"])
    before = normalize_sql("SELECT id FROM products WHERE id = 7;", rules)
    rules.append({
        "id": "FP-TABLE-ALIAS", "type": "regex_sub",
        "pattern": r"\bproducts\b", "replacement": "items", "enabled": True,
    })
    after = normalize_sql("SELECT id FROM products WHERE id = 7;", rules)
    assert "products" in before.text and "items" in after.text
    assert before.text != after.text


def test_disabled_rule_is_not_applied():
    rules = {"rules": [
        {"id": "s", "type": "replace_string_literals", "enabled": True},
        {"id": "off", "type": "replace_numeric_literals", "enabled": False},
    ]}
    normalized = normalize_sql("SELECT 'x' FROM t WHERE id = 7;", rules)
    assert normalized.text == "SELECT ? FROM t WHERE id = 7;"
    assert normalized.applied_rules == ["s"]


def test_whitespace_and_keywords_are_stable(config):
    one = normalize_sql("select  id,count(*)  from t group by id;", config.fingerprint_rules)
    two = normalize_sql("SELECT id, COUNT(*) FROM t GROUP BY id;", config.fingerprint_rules)
    assert one.text == two.text == "SELECT id,COUNT(*) FROM t GROUP BY id;"
    loose = normalize_sql("SELECT id FROM t WHERE id>=7;", config.fingerprint_rules)
    tight = normalize_sql("select id from t where id >= 7;", config.fingerprint_rules)
    assert loose.text == tight.text == "SELECT id FROM t WHERE id >= ?;"
