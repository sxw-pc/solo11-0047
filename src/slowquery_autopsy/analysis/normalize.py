"""Declarative SQL normalization for stable fingerprinting."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

DEFAULT_KEYWORDS = {
    "SELECT", "FROM", "WHERE", "AND", "OR", "NOT", "NULL", "IS", "IN", "LIKE",
    "BETWEEN", "EXISTS", "JOIN", "INNER", "LEFT", "RIGHT", "OUTER", "FULL", "CROSS",
    "ON", "AS", "ORDER", "BY", "GROUP", "HAVING", "LIMIT", "OFFSET", "ASC", "DESC",
    "DISTINCT", "UNION", "ALL", "INTERSECT", "EXCEPT", "WITH", "CASE", "WHEN",
    "THEN", "ELSE", "END", "INSERT", "INTO", "VALUES", "UPDATE", "SET", "DELETE",
    "CREATE", "ALTER", "DROP", "TABLE", "INDEX", "VIEW", "EXPLAIN", "ANALYZE",
    "SHOW", "USE", "COUNT", "SUM", "AVG", "MIN", "MAX", "LOWER", "UPPER",
    "COALESCE", "CAST", "DATE", "SUBSTR", "SUBSTRING", "NOW", "CONCAT",
}
TOKEN_RE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_$]*|::|<=|>=|<>|!=|[?(),.;=*+\-/<>%]|\S"
)
STRING_RE = re.compile(r"'(?:''|\\.|[^'\\])*'", re.DOTALL)
NUMBER_RE = re.compile(r"(?<![A-Za-z0-9_$])(?:\d+\.\d+|\d+)(?![A-Za-z0-9_$])")


class NormalizationError(ValueError):
    """Raised for malformed normalization rules."""


@dataclass
class NormalizedSQL:
    text: str
    tokens: list[str]
    applied_rules: list[str] = field(default_factory=list)


def strip_comments(sql: str) -> str:
    """Strip SQL comments while preserving quoted strings."""
    out: list[str] = []
    index = 0
    quote: str | None = None
    while index < len(sql):
        char = sql[index]
        nxt = sql[index + 1] if index + 1 < len(sql) else ""
        if quote:
            out.append(char)
            if char == quote:
                if nxt == quote:
                    out.append(nxt)
                    index += 2
                    continue
                quote = None
            elif char == "\\" and nxt:
                out.append(nxt)
                index += 2
                continue
            index += 1
            continue
        if char in ("'", '"', "`"):
            quote = char
            out.append(char)
            index += 1
            continue
        if char == "-" and nxt == "-":
            while index < len(sql) and sql[index] != "\n":
                index += 1
            out.append(" ")
            continue
        if char == "#":
            while index < len(sql) and sql[index] != "\n":
                index += 1
            out.append(" ")
            continue
        if char == "/" and nxt == "*":
            end = sql.find("*/", index + 2)
            index = len(sql) if end == -1 else end + 2
            out.append(" ")
            continue
        out.append(char)
        index += 1
    return "".join(out)


def canonical_punctuation(sql: str) -> str:
    text = re.sub(r"\s+", " ", sql).strip()
    text = re.sub(r"\s*,\s*", ",", text)
    text = re.sub(r"\s*(<=|>=|<>|!=|=|<|>)\s*", r" \1 ", text)
    text = re.sub(r"\s+([);])", r"\1", text)
    text = re.sub(r"([(])\s+", r"\1", text)
    return re.sub(r"\s+", " ", text).strip()


def tokenize(sql: str) -> list[str]:
    return TOKEN_RE.findall(sql)


def _apply_rule(sql: str, rule: dict[str, Any]) -> str:
    rule_type = rule.get("type")
    if rule_type == "strip_comments":
        return strip_comments(sql)
    if rule_type == "replace_string_literals":
        return STRING_RE.sub("?", sql)
    if rule_type == "replace_numeric_literals":
        return NUMBER_RE.sub("?", sql)
    if rule_type == "collapse_in_list":
        return re.sub(r"\bIN\s*\(\s*\?(?:\s*,\s*\?)*\s*\)", "IN (?)", sql, flags=re.I)
    if rule_type == "normalize_limit":
        return re.sub(r"\bLIMIT\s+\?(?:\s*,\s*\?)?(?:\s+OFFSET\s+\?)?", "LIMIT ?", sql, flags=re.I)
    if rule_type == "collapse_whitespace":
        return canonical_punctuation(sql)
    if rule_type == "uppercase_keywords":
        keywords = {str(word).upper() for word in rule.get("keywords", DEFAULT_KEYWORDS)}
        if not keywords:
            return sql
        pattern = re.compile(
            r"\b(" + "|".join(sorted((re.escape(word) for word in keywords), key=len, reverse=True)) + r")\b",
            re.I,
        )
        return pattern.sub(lambda match: match.group(1).upper(), sql)
    if rule_type == "regex_sub":
        pattern = rule.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            raise NormalizationError(f"rule {rule.get('id')}: regex_sub requires pattern")
        flags = 0
        for flag in str(rule.get("flags", "")):
            flags |= {"i": re.I, "m": re.M, "s": re.S}.get(flag, 0)
        try:
            compiled = re.compile(pattern, flags)
        except re.error as exc:
            raise NormalizationError(f"rule {rule.get('id')}: invalid regex: {exc}") from exc
        return compiled.sub(str(rule.get("replacement", "?")), sql)
    raise NormalizationError(f"unsupported normalization rule type: {rule_type!r}")


def normalize_sql(sql: str, rules: list[dict[str, Any]] | dict[str, Any]) -> NormalizedSQL:
    if isinstance(rules, dict):
        rule_list = rules.get("rules", [])
    else:
        rule_list = rules
    if not isinstance(rule_list, list):
        raise NormalizationError("normalization rules must be a list")
    text = sql.strip()
    applied: list[str] = []
    for index, rule in enumerate(rule_list):
        if not isinstance(rule, dict):
            raise NormalizationError(f"rule[{index}]: expected a mapping")
        if not rule.get("enabled", True):
            continue
        if not rule.get("id"):
            raise NormalizationError(f"rule[{index}]: missing id")
        text = _apply_rule(text, rule)
        applied.append(str(rule["id"]))
    text = canonical_punctuation(text)
    return NormalizedSQL(text=text, tokens=tokenize(text), applied_rules=applied)
