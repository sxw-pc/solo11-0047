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


# ---------------------------------------------------------------------------
# Structural canonicalization for the parent-cluster fingerprint.
#
# This layer is deliberately stricter than the text fingerprint: it absorbs
# aliases, select-list order and CASE writing styles, but it never rewrites the
# filter columns inside WHERE predicates. Queries filtering on different
# columns therefore keep distinct structural fingerprints.
# ---------------------------------------------------------------------------

_CLAUSE_KEYWORDS = (
    "SELECT", "FROM", "WHERE", "GROUP", "HAVING", "ORDER", "BY", "LIMIT",
    "OFFSET", "UNION", "INTERSECT", "EXCEPT",
)


def _is_identifier(token: str) -> bool:
    return bool(token) and (token[0].isalpha() or token[0] == "_")


def _split_top_level(tokens: list[str], separator: str) -> list[list[str]]:
    """Split a token list on a separator that sits at parenthesis depth 0."""
    parts: list[list[str]] = []
    current: list[str] = []
    depth = 0
    for token in tokens:
        if token == "(":
            depth += 1
        elif token == ")" and depth > 0:
            depth -= 1
        if token == separator and depth == 0:
            parts.append(current)
            current = []
        else:
            current.append(token)
    parts.append(current)
    return parts


def _split_conjuncts(tokens: list[str]) -> list[list[str]]:
    """Split WHERE/HAVING content at top-level AND; OR groups stay intact."""
    groups: list[list[str]] = []
    current: list[str] = []
    depth = 0
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "(":
            depth += 1
        elif token == ")":
            depth = max(0, depth - 1)
        if depth == 0 and token == "AND":
            groups.append(current)
            current = []
        else:
            current.append(token)
        index += 1
    groups.append(current)
    return [group for group in groups if group and not all(item == ";" for item in group)]


def _canonicalize_case(tokens: list[str]) -> list[str]:
    """Rewrite simple CASE (CASE x WHEN v1 THEN ... END) into searched CASE.

    Searched CASE is already canonical and passes through untouched. Nested
    CASE expressions are handled via a depth stack.
    """
    out: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token != "CASE":
            out.append(token)
            index += 1
            continue
        if index + 1 < len(tokens) and tokens[index + 1] == "WHEN":
            out.append(token)
            index += 1
            continue
        # Gather the subject expression up to the first depth-1 WHEN.
        cursor = index + 1
        depth = 1
        subject: list[str] = []
        while cursor < len(tokens):
            item = tokens[cursor]
            if depth == 1 and item == "WHEN":
                break
            if item == "CASE":
                depth += 1
            elif item == "END":
                depth -= 1
                if depth == 0:
                    break
            subject.append(item)
            cursor += 1
        if cursor >= len(tokens) or tokens[cursor] != "WHEN" or not subject:
            # Unbalanced input or empty subject: leave the stream unchanged.
            out.append(token)
            index += 1
            continue
        out.append("CASE")
        depth = 1
        while cursor < len(tokens):
            item = tokens[cursor]
            if item == "CASE":
                depth += 1
                out.append(item)
                cursor += 1
                continue
            if item == "END":
                depth -= 1
                if depth == 0:
                    out.append("END")
                    cursor += 1
                    break
                out.append(item)
                cursor += 1
                continue
            if depth == 1 and item == "WHEN":
                # CASE s WHEN v THEN t -> CASE WHEN s = v THEN t
                out.append("WHEN")
                out.extend(subject)
                out.append("=")
                cursor += 1  # consume WHEN; operand tokens follow in stream
                continue
            out.append(item)
            cursor += 1
        index = cursor
    return out


def _table_aliases(tokens: list[str]) -> dict[str, str]:
    """Map table aliases to table names across FROM/JOIN table references.

    Scans the whole scope at parenthesis depth 0 so subquery bodies and
    parenthesised join groups are treated as separate scopes.
    """
    aliases: dict[str, str] = {}
    depth = 0
    index = 0
    join_starts = ("FROM", "JOIN", "INNER", "LEFT", "RIGHT", "FULL",
                   "OUTER", "CROSS")
    while index < len(tokens):
        token = tokens[index]
        if token == "(":
            depth += 1
            index += 1
            continue
        if token == ")":
            depth = max(0, depth - 1)
            index += 1
            continue
        if depth == 0 and token in join_starts:
            while index < len(tokens) and tokens[index] in join_starts:
                index += 1
            if index >= len(tokens) or not _is_identifier(tokens[index]):
                continue
            table_name = tokens[index]
            index += 1
            if index < len(tokens) and tokens[index] == "AS":
                index += 1
            if (
                index < len(tokens)
                and _is_identifier(tokens[index])
                and tokens[index] not in _CLAUSE_KEYWORDS
                and tokens[index] not in ("ON", "USING", "JOIN", "WHERE",
                                          "GROUP", "ORDER", "LIMIT")
            ):
                aliases.setdefault(tokens[index], table_name)
            continue
        index += 1
    return aliases


def _resolve_qualifiers(tokens: list[str], aliases: dict[str, str]) -> list[str]:
    out: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if (
            token in aliases
            and index + 2 < len(tokens)
            and tokens[index + 1] == "."
            and _is_identifier(tokens[index + 2])
        ):
            out.extend((aliases[token], ".", tokens[index + 2]))
            index += 3
            continue
        out.append(token)
        index += 1
    return out


def _drop_table_alias_tokens(tokens: list[str], aliases: dict[str, str]) -> list[str]:
    """Remove alias declarations themselves from FROM/JOIN table refs."""
    out: list[str] = []
    depth = 0
    index = 0
    join_starts = ("FROM", "JOIN", "INNER", "LEFT", "RIGHT", "FULL",
                   "OUTER", "CROSS")
    while index < len(tokens):
        token = tokens[index]
        if token == "(":
            depth += 1
            out.append(token)
            index += 1
            continue
        if token == ")":
            depth = max(0, depth - 1)
            out.append(token)
            index += 1
            continue
        if depth == 0 and token in join_starts:
            chain: list[str] = []
            while index < len(tokens) and tokens[index] in join_starts:
                chain.append(tokens[index])
                index += 1
            out.extend(chain)
            if index < len(tokens) and _is_identifier(tokens[index]):
                out.append(tokens[index])  # table name
                index += 1
                if index < len(tokens) and tokens[index] == "AS":
                    index += 1
                if (
                    index < len(tokens)
                    and tokens[index] in aliases
                ):
                    index += 1  # drop the alias token
            continue
        out.append(token)
        index += 1
    return out


def _drop_explicit_aliases(tokens: list[str]) -> list[str]:
    out: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "AS":
            # Remove AS and its immediately following output alias.
            index += 1
            if index < len(tokens) and _is_identifier(tokens[index]):
                index += 1
            continue
        out.append(token)
        index += 1
    return out


def _split_clauses(tokens: list[str]) -> list[tuple[str, list[str]]]:
    clauses: list[tuple[str, list[str]]] = []
    current_kw = "SELECT"
    current: list[str] = []
    depth = 0
    for token in tokens:
        if token == "(":
            depth += 1
            current.append(token)
            continue
        if token == ")":
            depth = max(0, depth - 1)
            current.append(token)
            continue
        if depth == 0 and token in _CLAUSE_KEYWORDS:
            if token == "BY" and current_kw in ("GROUP", "ORDER"):
                current_kw = f"{current_kw} BY"
                continue
            clauses.append((current_kw, current))
            current_kw = token
            current = []
            continue
        current.append(token)
    clauses.append((current_kw, current))
    return [(kw, body) for kw, body in clauses if body or kw == "WHERE"]


def _strip_terminator(body: list[str]) -> tuple[list[str], list[str]]:
    """Separate a trailing semicolon so it never participates in sorting."""
    if body and body[-1] == ";":
        return body[:-1], [";"]
    return body, []


def _canonical_scope(tokens: list[str]) -> list[str]:
    tokens = _canonicalize_case(tokens)
    from_aliases = _table_aliases(tokens)
    tokens = _drop_table_alias_tokens(tokens, from_aliases)
    clauses = _split_clauses(tokens)

    rendered: list[str] = []
    for kw, raw_body in clauses:
        body, terminator = _strip_terminator(raw_body)
        body = _resolve_qualifiers(body, from_aliases)
        body = _drop_explicit_aliases(body)
        if kw == "SELECT":
            items = sorted(_split_top_level(body, ","), key=lambda part: " ".join(part))
            body = _join_items(items, ",")
        elif kw == "GROUP BY":
            items = sorted(_split_top_level(body, ","), key=lambda part: " ".join(part))
            body = _join_items(items, ",")
        elif kw in ("WHERE", "HAVING"):
            items = sorted(_split_conjuncts(body), key=lambda part: " ".join(part))
            body = _join_items(items, "AND")
        if rendered:
            rendered.append(kw)
        else:
            rendered.append(kw)
        rendered.extend(body)
        rendered.extend(terminator)
    return rendered


def _join_items(items: list[list[str]], separator: str) -> list[str]:
    joined: list[str] = []
    for index, item in enumerate(items):
        if index:
            joined.append(separator)
        joined.extend(item)
    return joined


def structural_tokens(normalized_tokens: list[str]) -> list[str]:
    """Canonical token sequence defining structural equivalence.

    Absorbs table/column aliases, output-alias noise, select-list /
    group-by ordering, top-level AND ordering and simple-vs-searched CASE
    spelling. Filter column identifiers inside WHERE are preserved, so
    queries filtering on different columns never share a structure.
    """
    return _canonical_scope(list(normalized_tokens))


def structural_signature(normalized_tokens: list[str]) -> tuple[str, list[str]]:
    """Return the canonical structural text and its token sequence."""
    tokens = structural_tokens(normalized_tokens)
    return " ".join(tokens), tokens
