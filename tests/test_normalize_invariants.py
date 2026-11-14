"""Invariant tests for the declarative SQL normalization pipeline.

These tests pin the contracts that let us tell a semantic regression apart
from harmless rule tuning: which inputs must collapse to one normalized
text, which inputs must stay distinguishable, how rule order changes the
outcome, and whether re-applying the same rule set is a fixpoint.
"""

from __future__ import annotations

import pytest

from slowquery_autopsy.analysis.normalize import (
    NormalizationError,
    normalize_sql,
    tokenize,
)


def _enabled_rules(config) -> list[dict]:
    """The shipped rule chain, limited to rules that are enabled."""
    return [
        dict(rule)
        for rule in config.fingerprint_rules["rules"]
        if rule.get("enabled", True)
    ]


def _move_rules(rules: list[dict], moved_ids: set[str], before_id: str) -> list[dict]:
    """Copy of ``rules`` with ``moved_ids`` relocated to just before ``before_id``."""
    chain = [rule for rule in rules if rule["id"] in moved_ids]
    rest = [rule for rule in rules if rule["id"] not in moved_ids]
    reordered: list[dict] = []
    for rule in rest:
        if rule["id"] == before_id:
            reordered.extend(chain)
        reordered.append(rule)
    return reordered


# One query shape; only literals, IN-list arity, LIMIT shape, whitespace,
# casing and comments differ. Literal replacement plus collapse_in_list
# must land every form on the same normalized text.
EQUIVALENT_FORMS = [
    "select * from orders where customer_id = 42 and status in ('PAID','NEW') limit 20;",
    "SELECT *\nFROM orders\nWHERE customer_id = 987\n  AND status IN ('X', 'Y')\nLIMIT 10, 30;",
    " SELECT  *  FROM  orders  WHERE  customer_id=7  AND  status  IN  ( 'Q' )  LIMIT 5;",
    "SELECT * FROM orders /* audit */ WHERE customer_id = 123456 -- hot path\n"
    " AND status IN ('A','B','C','D') LIMIT 200 OFFSET 40;",
]

# Diverse shapes used for fixpoint and token-consistency checks.
DIVERSE_CORPUS = [
    *EQUIVALENT_FORMS,
    "SELECT id, COUNT(*) FROM t WHERE a=1 AND b='2' GROUP BY id "
    "HAVING COUNT(*)>5 ORDER BY id DESC LIMIT 100 OFFSET 7;",
    "SELECT '--not-a-comment', id /* hidden */ FROM t2 WHERE note = 'a -- b' "
    "AND x IN(1,2,3) -- tail",
    "UPDATE t SET a = 1.5, b = 'x' WHERE id = 9;",
    "SELECT * FROM t WHERE a BETWEEN 1 AND 5 AND b != 'z' AND c >= 7;",
    "SELECT * FROM t WHERE a = -5 AND b = 1e5 AND c = 0.25;",
    "SELECT * FROM shopdemo.orders WHERE id = 3;",
    "SELECT * FROM t WHERE a IS NULL OR b IS NOT NULL;",
]


def test_literal_and_shape_variants_share_one_normalized_text(config):
    rules = _enabled_rules(config)
    results = [normalize_sql(sql, rules) for sql in EQUIVALENT_FORMS]

    texts = {result.text for result in results}
    assert len(texts) == 1
    text = texts.pop()

    # The four-element IN list and every LIMIT shape collapsed to placeholders.
    assert "IN (?)" in text
    assert "LIMIT ?" in text
    # No literal survives: no digits, no quotes, no comment debris.
    assert not any(char.isdigit() for char in text)
    assert "'" not in text and "/*" not in text and "--" not in text

    first = results[0]
    for result in results[1:]:
        assert result.tokens == first.tokens
        assert result.applied_rules == first.applied_rules


def test_enabled_rules_are_applied_in_file_order(config):
    rules = _enabled_rules(config)
    result = normalize_sql(EQUIVALENT_FORMS[0], rules)
    assert result.applied_rules == [rule["id"] for rule in rules]

    reversed_rules = list(reversed(rules))
    reordered = normalize_sql(EQUIVALENT_FORMS[0], reversed_rules)
    assert reordered.applied_rules == [rule["id"] for rule in reversed_rules]


def test_collapse_in_list_requires_literal_placeholders_first(config):
    rules = _enabled_rules(config)
    sql = "SELECT * FROM t WHERE id IN (1, 2, 3);"

    collapsed = normalize_sql(sql, rules)
    assert "IN (?)" in collapsed.text

    # With collapse running before literal replacement the raw numbers are
    # not placeholders yet, so the list survives in expanded form.
    reordered = _move_rules(rules, {"FP-IN-LIST"}, before_id="FP-STRINGS")
    expanded = normalize_sql(sql, reordered)
    assert expanded.text != collapsed.text
    assert "IN (?,?,?)" in expanded.text
    assert expanded.applied_rules.index("FP-IN-LIST") < expanded.applied_rules.index(
        "FP-NUMBERS"
    )


def test_normalize_limit_requires_numeric_placeholders_first(config):
    rules = _enabled_rules(config)
    sql = "SELECT * FROM t LIMIT 10, 30;"

    collapsed = normalize_sql(sql, rules)
    assert "LIMIT ?" in collapsed.text
    assert "?,?" not in collapsed.text

    reordered = _move_rules(rules, {"FP-LIMIT"}, before_id="FP-NUMBERS")
    expanded = normalize_sql(sql, reordered)
    assert expanded.text != collapsed.text
    assert "LIMIT ?,?" in expanded.text


def test_normalization_is_a_fixpoint(config):
    rules = _enabled_rules(config)
    for sql in DIVERSE_CORPUS:
        once = normalize_sql(sql, rules)
        twice = normalize_sql(once.text, rules)
        assert twice.text == once.text
        assert twice.tokens == once.tokens


def test_normalization_has_no_hidden_state(config):
    rules = _enabled_rules(config)
    for sql in DIVERSE_CORPUS:
        first = normalize_sql(sql, rules)
        second = normalize_sql(sql, rules)
        assert (first.text, first.tokens, first.applied_rules) == (
            second.text,
            second.tokens,
            second.applied_rules,
        )


def test_tokens_always_match_the_normalized_text(config):
    rules = _enabled_rules(config)
    for sql in DIVERSE_CORPUS:
        result = normalize_sql(sql, rules)
        assert result.tokens == tokenize(result.text)
        assert "  " not in result.text  # canonical single-space whitespace


DISTINCT_PAIRS = [
    # Equality filters on different columns must never merge.
    ("SELECT * FROM t WHERE a = 1;", "SELECT * FROM t WHERE b = 1;"),
    # Predicate order is structural: normalization does not commute AND.
    ("SELECT * FROM t WHERE a = 1 AND b = 2;", "SELECT * FROM t WHERE b = 1 AND a = 2;"),
    # The operator is semantics, not a literal.
    ("SELECT * FROM t WHERE a = 1;", "SELECT * FROM t WHERE a > 1;"),
    ("SELECT * FROM t WHERE a >= 1;", "SELECT * FROM t WHERE a > 1;"),
    # IN-lists on different columns collapse independently.
    ("SELECT * FROM t WHERE a IN (1, 2);", "SELECT * FROM t WHERE b IN (1, 2);"),
    # Different tables, projections and null semantics stay apart.
    ("SELECT * FROM orders WHERE a = 1;", "SELECT * FROM customers WHERE a = 1;"),
    ("SELECT id FROM t WHERE a = 1;", "SELECT * FROM t WHERE a = 1;"),
    ("SELECT * FROM t WHERE a IS NULL;", "SELECT * FROM t WHERE a = 1;"),
]


@pytest.mark.parametrize(
    "left,right",
    DISTINCT_PAIRS,
    ids=[
        "different-filter-column",
        "predicate-order-not-commuted",
        "equality-vs-range-operator",
        "gte-vs-gt-operator",
        "in-list-on-different-columns",
        "different-table",
        "different-projection",
        "is-null-vs-equality",
    ],
)
def test_semantically_distinct_inputs_stay_distinct(config, left, right):
    rules = _enabled_rules(config)
    left_result = normalize_sql(left, rules)
    right_result = normalize_sql(right, rules)
    assert left_result.text != right_result.text
    assert left_result.tokens != right_result.tokens


def test_literal_values_do_not_leak_into_structure(config):
    rules = _enabled_rules(config)
    # Same column, different literal values: must merge.
    assert (
        normalize_sql("SELECT * FROM t WHERE customer_id = 42;", rules).text
        == normalize_sql("SELECT * FROM t WHERE customer_id = 987654;", rules).text
    )
    # String and numeric literals share one placeholder shape by design.
    assert (
        normalize_sql("SELECT * FROM t WHERE a = 'x';", rules).text
        == normalize_sql("SELECT * FROM t WHERE a = 9;", rules).text
    )
    # Integer and decimal literals share the placeholder too.
    assert (
        normalize_sql("SELECT * FROM t WHERE price = 9.99;", rules).text
        == normalize_sql("SELECT * FROM t WHERE price = 10;", rules).text
    )


def test_disabled_schema_qualifier_rule_keeps_qualifiers(config):
    # FP-SCHEMA-QUALIFIER ships disabled; while it is, qualified and
    # unqualified names must not merge. Enabling that rule is rule tuning
    # and should update this test deliberately, not silently.
    rules = _enabled_rules(config)
    qualified = normalize_sql("SELECT * FROM shopdemo.orders WHERE id = 3;", rules)
    bare = normalize_sql("SELECT * FROM orders WHERE id = 3;", rules)
    assert qualified.text != bare.text


def test_malformed_rules_raise_normalization_error():
    with pytest.raises(NormalizationError):
        normalize_sql("SELECT 1;", {"rules": "not-a-list"})
    with pytest.raises(NormalizationError):
        # Enabled rule without an id.
        normalize_sql("SELECT 1;", [{"type": "replace_numeric_literals"}])
    with pytest.raises(NormalizationError):
        normalize_sql("SELECT 1;", [{"id": "x", "type": "no-such-rule"}])
    with pytest.raises(NormalizationError):
        # regex_sub without a pattern.
        normalize_sql("SELECT 1;", [{"id": "x", "type": "regex_sub"}])
    with pytest.raises(NormalizationError):
        normalize_sql("SELECT 1;", [{"id": "x", "type": "regex_sub", "pattern": "("}])
