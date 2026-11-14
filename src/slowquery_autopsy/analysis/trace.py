"""Cross-batch fingerprint persistence tracing.

``finding_id`` is intentionally not used as the identity of a recurring
finding: its payload includes evidence values, so a query-count or P95 change
yields a new id.  Findings are grouped by ``rule_id + plan_file + node_path``
instead, while per-batch finding ids are kept as provenance.

Identity is the fingerprint (the cluster id).  For every fingerprint and every
requested batch the trace distinguishes three states:

``observed``
    The fingerprint has a cluster in that batch.
``absent``
    The batch collected every known source file where this fingerprint has
    been seen before, but produced no cluster for it.  This is a genuine
    disappearance.
``not_collected``
    The batch did not collect every known source of this fingerprint, or the
    ledger cannot prove what it collected (a batch written before per-source
    coverage existed).  A gap here says nothing about the fingerprint and must
    not be read as "it disappeared"; the entry records ``missing_sources`` and
    ``coverage_known`` so the reason is auditable.

Coverage is *fingerprint-scoped*: the sources are the files where this
fingerprint was ever seen, and a source counts as collected when the batch
lists it in ``log_files`` (it was an input, even if it happened to yield zero
slow queries).  Partial coverage is deliberately reported as
``not_collected`` rather than ``absent``.

Persistence status uses only ``observed``/``absent`` batches, so a
``not_collected`` gap never fabricates a disappearance.

Only fingerprints observed in at least one selected batch are traced; other
batches are never consulted for their state, so non-adjacent selections work.
"""

from __future__ import annotations

from typing import Any

from . import trace_records as records
from .trace_records import (
    ABSENT,
    HIGH_SEVERITIES,
    NOT_COLLECTED,
    OBSERVED,
    STATUS_LEGEND,
    TRACE_SCHEMA_VERSION,
)

__all__ = [
    "ABSENT",
    "NOT_COLLECTED",
    "OBSERVED",
    "STATUS_CONTINUOUS",
    "STATUS_DISAPPEARED",
    "STATUS_NEW",
    "STATUS_REAPPEARED",
    "STATUS_SINGLE",
    "TRACE_SCHEMA_VERSION",
    "trace_batches_from_ledger",
    "trace_fingerprints",
]

STATUS_CONTINUOUS = records.STATUS_CONTINUOUS
STATUS_DISAPPEARED = records.STATUS_DISAPPEARED
STATUS_NEW = records.STATUS_NEW
STATUS_REAPPEARED = records.STATUS_REAPPEARED
STATUS_SINGLE = records.STATUS_SINGLE


def _dedupe(batch_ids: list[str]) -> list[str]:
    ordered: list[str] = []
    for batch_id in batch_ids:
        if batch_id not in ordered:
            ordered.append(batch_id)
    return ordered


def trace_fingerprints(
    batch_ids: list[str],
    clusters: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    log_files: list[dict[str, Any]],
    sources: list[dict[str, Any]],
    sources_known: set[str] | None = None,
    batch_metadata: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a deterministic cross-batch persistence trace.

    ``batch_ids`` is the ordered batch sequence (oldest first).  ``sources``
    contains ``batch_id/fingerprint/source_file`` rows for analyzed queries.
    Rows for batch ids outside ``batch_ids`` are ignored, so callers cannot
    leak data from batches they did not ask for.

    ``sources_known`` lists the batches whose per-fingerprint source coverage
    row exists.  It is ``None`` for callers that always supply complete
    coverage.  A batch not in the set is treated as ``not_collected`` for every
    fingerprint instead of risking a false ``absent``: a ledger written before
    the ``fingerprint_sources`` table cannot prove non-collection.
    """
    ordered_ids = _dedupe(batch_ids)
    order = {batch_id: index for index, batch_id in enumerate(ordered_ids)}
    valid = set(ordered_ids)

    clusters = [row for row in clusters if str(row.get("batch_id")) in valid]
    findings = [
        row for row in findings
        if str(row.get("batch_id")) in valid
        and str(row.get("severity", "")) in HIGH_SEVERITIES
    ]
    log_files = [row for row in log_files if str(row.get("batch_id")) in valid]
    sources = [row for row in sources if str(row.get("batch_id")) in valid]

    cluster_map: dict[tuple[str, str], dict[str, Any]] = {}
    first_cluster: dict[str, dict[str, Any]] = {}
    clusters_per_batch: dict[str, int] = {}
    for row in clusters:
        fingerprint = records.cluster_fingerprint(row)
        if not fingerprint:
            continue
        batch_id = str(row["batch_id"])
        cluster_map[(batch_id, fingerprint)] = row
        clusters_per_batch[batch_id] = clusters_per_batch.get(batch_id, 0) + 1
        current = first_cluster.get(fingerprint)
        if current is None or order[batch_id] < order[str(current["batch_id"])]:
            first_cluster[fingerprint] = row

    sources_by_fingerprint: dict[str, set[str]] = {}
    for row in sources:
        fingerprint = str(row.get("fingerprint", ""))
        if fingerprint:
            sources_by_fingerprint.setdefault(fingerprint, set()).add(
                str(row.get("source_file", ""))
            )
    files_by_batch: dict[str, set[str]] = {}
    for row in log_files:
        files_by_batch.setdefault(str(row["batch_id"]), set()).add(
            str(row.get("path", ""))
        )
    findings_by_target: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in findings:
        findings_by_target.setdefault(
            (str(row["batch_id"]), str(row.get("cluster_id", ""))), []
        ).append(row)

    entries = [
        _trace_fingerprint(
            fingerprint, first_cluster[fingerprint], ordered_ids, order,
            cluster_map, findings_by_target, files_by_batch,
            sources_by_fingerprint.get(fingerprint, set()), sources_known,
        )
        for fingerprint in sorted(
            first_cluster,
            key=lambda value: (order[str(first_cluster[value]["batch_id"])], value),
        )
    ]
    return _document(entries, findings, first_cluster, ordered_ids, order,
                     clusters_per_batch, files_by_batch, batch_metadata)


def _trace_fingerprint(
    fingerprint: str,
    first: dict[str, Any],
    ordered_ids: list[str],
    order: dict[str, int],
    cluster_map: dict[tuple[str, str], dict[str, Any]],
    findings_by_target: dict[tuple[str, str], list[dict[str, Any]]],
    files_by_batch: dict[str, set[str]],
    known_sources: set[str],
    sources_known: set[str] | None,
) -> dict[str, Any]:
    def coverage(batch_id: str) -> tuple[bool, bool, list[str]]:
        """Return (fully_covered, coverage_known, missing_sources).

        A source is collected when the batch lists the file in ``log_files``.
        ``parsed_count == 0`` still means the batch looked at that file and
        found no slow query, which is exactly the evidence needed for
        ``absent``.
        """
        if sources_known is not None and batch_id not in sources_known:
            return False, False, []
        if not known_sources:
            # No provenance for this fingerprint at all (legacy ledger):
            # coverage cannot be proven, so absence cannot be asserted.
            return False, False, []
        missing = sorted(known_sources - files_by_batch.get(batch_id, set()))
        return not missing, True, missing

    records_out: list[dict[str, Any]] = []
    observed_flags: list[bool] = []
    for batch_id in ordered_ids:
        cluster = cluster_map.get((batch_id, fingerprint))
        target_findings = findings_by_target.get((batch_id, fingerprint), [])
        if cluster is not None:
            state, coverage_known, missing = OBSERVED, True, []
        else:
            covered, coverage_known, missing = coverage(batch_id)
            state = ABSENT if covered else NOT_COLLECTED
        records_out.append(records.batch_record(
            batch_id, state, cluster, target_findings, missing, coverage_known,
        ))
        if state != NOT_COLLECTED:
            observed_flags.append(state == OBSERVED)

    observed = [item["batch_id"] for item in records_out if item["state"] == OBSERVED]
    fingerprint_findings = [
        row for rows in findings_by_target.values() for row in rows
        if str(row.get("cluster_id", "")) == fingerprint
    ]
    return {
        "fingerprint": fingerprint,
        "sample_sql": str(first.get("sample_sql", "")),
        "normalized_sql": str(first.get("normalized_sql", "")),
        "first_seen_batch": observed[0],
        "last_seen_batch": observed[-1],
        "latest_batch_state": records_out[-1]["state"],
        "status": records.status_from_flags(observed_flags),
        "observations": len(observed),
        "observed_batches": observed,
        "absent_batches": [item["batch_id"] for item in records_out
                           if item["state"] == ABSENT],
        "not_collected_batches": [item["batch_id"] for item in records_out
                                  if item["state"] == NOT_COLLECTED],
        "batches": records_out,
        "high_findings": records.finding_summary(fingerprint_findings, order),
    }


def _document(entries, findings, first_cluster, ordered_ids, order,
              clusters_per_batch, files_by_batch, batch_metadata):
    unattributed = [row for row in findings
                    if str(row.get("cluster_id", "")) not in first_cluster]
    by_status: dict[str, int] = {}
    for entry in entries:
        by_status[entry["status"]] = by_status.get(entry["status"], 0) + 1
    return {
        "trace_type": "slowquery-autopsy-fingerprint-trace",
        "schema_version": TRACE_SCHEMA_VERSION,
        "status_basis": "observed_and_absent_batches",
        "status_legend": {key: STATUS_LEGEND[key] for key in sorted(STATUS_LEGEND)},
        "batches": [
            records.batch_metadata(
                batch_id, (batch_metadata or {}).get(batch_id),
                clusters_per_batch.get(batch_id, 0),
                sorted(files_by_batch.get(batch_id, set())),
            )
            for batch_id in ordered_ids
        ],
        "fingerprints": entries,
        "counts": {
            "batches": len(ordered_ids),
            "fingerprints": len(entries),
            "observations": sum(entry["observations"] for entry in entries),
            "absent": sum(len(entry["absent_batches"]) for entry in entries),
            "not_collected": sum(len(entry["not_collected_batches"])
                                 for entry in entries),
            "fingerprints_with_high_findings": sum(
                1 for entry in entries if entry["high_findings"]["count"]
            ),
            "high_findings": len(findings),
            "unattributed_high_findings": len(unattributed),
            "by_status": {key: by_status[key] for key in sorted(by_status)},
        },
    }


def trace_batches_from_ledger(ledger: Any, batch_ids: list[str]) -> dict[str, Any]:
    """Load the rows for ``batch_ids`` from a :class:`Ledger` and trace them."""
    batches: list[str] = []
    batch_metadata: dict[str, dict[str, Any]] = {}
    clusters: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    log_files: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    sources_known: set[str] = set()
    coverage = getattr(ledger, "has_fingerprint_sources", None)
    table_exists = coverage is None or coverage()
    for batch_id in batch_ids:
        batch = ledger.get_batch(batch_id)
        if not batch:
            raise KeyError(batch_id)
        batches.append(batch_id)
        summary = batch.get("summary") or {}
        batch_metadata[batch_id] = {
            "query_count": int((summary.get("counts") or {}).get("queries", 0)),
        }
        clusters.extend(ledger.list_clusters(batch_id))
        findings.extend(ledger.list_findings(batch_id))
        log_files.extend(ledger.list_log_files(batch_id))
        batch_sources = ledger.list_fingerprint_sources(batch_id)
        sources.extend(batch_sources)
        # Only batches that actually carry provenance may claim ``absent``; an
        # un-backfilled legacy batch stays ``not_collected``.
        if table_exists and batch_sources:
            sources_known.add(batch_id)
    return trace_fingerprints(
        batches, clusters, findings, log_files, sources,
        sources_known=sources_known, batch_metadata=batch_metadata,
    )
