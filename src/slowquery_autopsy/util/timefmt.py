"""Timestamp parsing and deterministic run timestamps."""

from __future__ import annotations

from datetime import datetime, timezone


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_timestamp(value: str) -> str:
    """Return an ISO-8601 UTC timestamp when parseable, otherwise the input."""
    raw = (value or "").strip()
    if not raw:
        return ""
    candidates = [raw]
    if raw.endswith("Z"):
        candidates.append(raw[:-1] + "+00:00")
    if " " in raw and "T" not in raw:
        candidates.append(raw.replace(" ", "T"))
    for candidate in candidates:
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
            "+00:00", "Z"
        )
    return raw


def mysql_timestamp_to_iso(value: str) -> str:
    """MySQL slow logs use ``YYMMDD HH:MM:SS`` (or ISO in synthetic files)."""
    raw = (value or "").strip()
    if len(raw) == 15 and raw[6] == " ":
        try:
            parsed = datetime.strptime(raw, "%y%m%d %H:%M:%S")
            return parsed.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        except ValueError:
            pass
    return normalize_timestamp(raw)


def sort_iso(values: list[str]) -> list[str]:
    return sorted(values, key=lambda item: (item == "", item))


def iso_to_epoch_seconds(value: str) -> float | None:
    """Return UTC epoch seconds for a normalizable timestamp, else ``None``."""
    raw = (value or "").strip()
    if not raw:
        return None
    candidates = [raw]
    if raw.endswith("Z"):
        candidates.append(raw[:-1] + "+00:00")
    if " " in raw and "T" not in raw:
        candidates.append(raw.replace(" ", "T"))
    for candidate in candidates:
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).timestamp()
    return None


def timestamp_distance_seconds(left: str, right: str) -> float | None:
    """Absolute distance between two timestamps, or ``None`` when unparseable."""
    left_epoch = iso_to_epoch_seconds(left)
    right_epoch = iso_to_epoch_seconds(right)
    if left_epoch is None or right_epoch is None:
        return None
    return abs(left_epoch - right_epoch)
