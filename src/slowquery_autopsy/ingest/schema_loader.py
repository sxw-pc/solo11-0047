"""Load the synthetic schema snapshot used by plan audit rules."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

NUMERIC_TYPES = (
    "int", "integer", "bigint", "smallint", "tinyint", "decimal", "numeric",
    "float", "double", "real", "serial", "bigserial",
)


@dataclass
class TableSchema:
    name: str
    row_count: int
    columns: dict[str, str] = field(default_factory=dict)
    indexes: list[dict[str, Any]] = field(default_factory=list)

    def column_type(self, column: str) -> str:
        normalized = column.strip('"`').split(".")[-1].lower()
        for name, data_type in self.columns.items():
            if name.lower() == normalized:
                return data_type
        return ""

    def is_indexed(self, column: str) -> bool:
        normalized = column.strip('"`').split(".")[-1].lower()
        for index in self.indexes:
            columns = index.get("columns", [])
            if any(str(item).lower() == normalized for item in columns):
                return True
        return False

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "row_count": self.row_count,
            "columns": self.columns,
            "indexes": self.indexes,
        }


@dataclass
class SchemaSnapshot:
    database: str
    tables: dict[str, TableSchema]

    def table(self, name: str) -> TableSchema | None:
        if not name:
            return None
        normalized = name.strip('"`').split(".")[-1].lower()
        return self.tables.get(normalized)

    def row_count(self, name: str) -> int:
        table = self.table(name)
        return table.row_count if table else 0

    def is_numeric_column(self, table_name: str, column: str) -> bool:
        table = self.table(table_name)
        if not table:
            return False
        return any(table.column_type(column).lower().startswith(kind) for kind in NUMERIC_TYPES)

    def is_indexed_column(self, table_name: str, column: str) -> bool:
        table = self.table(table_name)
        return bool(table and table.is_indexed(column))


def load_schema(path: Path) -> SchemaSnapshot:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path}: cannot load schema snapshot: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("tables"), dict):
        raise ValueError(f"{path}: schema snapshot must contain a tables mapping")
    tables: dict[str, TableSchema] = {}
    for name, raw in data["tables"].items():
        if not isinstance(raw, dict):
            raise ValueError(f"{path}: table {name!r} must be an object")
        try:
            row_count = int(raw.get("row_count", 0))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{path}: table {name!r} has an invalid row_count") from exc
        columns = raw.get("columns", {})
        if not isinstance(columns, dict):
            raise ValueError(f"{path}: table {name!r} columns must be an object")
        indexes = raw.get("indexes", [])
        if not isinstance(indexes, list):
            raise ValueError(f"{path}: table {name!r} indexes must be a list")
        tables[str(name).lower()] = TableSchema(
            name=str(name),
            row_count=row_count,
            columns={str(key): str(value) for key, value in columns.items()},
            indexes=indexes,
        )
    return SchemaSnapshot(database=str(data.get("database", "")), tables=tables)
