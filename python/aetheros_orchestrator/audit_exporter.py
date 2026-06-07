"""Structured audit-log export for SIEM ingestion — Phase 19.

Why structured audit export
────────────────────────────
The AetherOS evidence ledger already records a tamper-evident, hash-chained account
of every governance event: intent submissions, lease issuance, policy decisions,
tool invocations, approvals, budget charges, collaboration admissions, marketplace
installs, and run completions. Phase 7 exposed this as a compliance rollup; Phases
8–9 exposed it as RFC 6962 transparency proofs.

What was missing: an event-level export feed for SIEM tools (Splunk, Datadog,
Elastic, Azure Sentinel). SIEM ingestion requires per-event granularity, stable
field names, ISO-8601 timestamps, and a filterable, paginated HTTP interface. A
SIEM operator cannot consume a compliance summary — they need the raw events.

Design (atom of thoughts — Phase 19)
──────────────────────────────────────
The smallest independently verifiable properties:

1. ``AuditEvent`` is a stable, OCSF-aligned dataclass with ``time_iso``,
   ``event_type``, ``actor``, ``tenant_id``, ``run_id``, ``seq``,
   ``entry_hash``, ``prev_hash``, and ``payload``.
2. ``AuditExporter.export(runs, ...)`` collects events from one or more run
   ledgers, normalises them into ``AuditEvent`` instances, applies filters
   (``event_type``, ``since``, ``until``), sorts by ``(time_iso, seq)``,
   and paginates with ``offset`` + ``limit``.
3. Filtering is purely additive — no filter parameter = all events returned.
4. Pagination is deterministic: stable sort + offset/limit always yields the
   same page for the same ledger state.
5. ``AuditExporter.to_ndjson(events)`` serialises a list of events as one
   JSON object per line (NDJSON, application/x-ndjson), suitable for Splunk
   HEC, Datadog Logs API, and Elastic Bulk API.
6. The exporter is stateless — it holds no references between calls, so it
   can be constructed once and reused safely across requests.
7. Disabled mode: when ``audit.enabled = False`` (the default) the endpoint
   returns HTTP 403, identical to the key_rotation pattern.

Standards / research net
────────────────────────
* OCSF (Open Cybersecurity Schema Framework) v1.0 — CISA / AWS / Splunk / IBM,
  2022. Core fields: ``time`` (epoch ms), ``class_uid``, ``category_uid``,
  ``activity_id``, ``actor``, ``resources``, ``status``, ``severity_id``,
  ``message``. AetherOS maps its native ledger fields to OCSF-compatible names;
  full OCSF UIDs are outside scope (they require a fixed taxonomy) but the
  field names align.
* NDJSON (ndjson.org): one JSON object per line, ``\\n`` separated. Standard
  format for Elastic Bulk API, Splunk HEC stream, Datadog Logs API.
* Splunk HTTP Event Collector (HEC): POST with JSON body
  ``{"time": <epoch>, "event": {...}}``. The exporter's NDJSON output maps
  directly; operators wrap it in an HEC envelope or use a Splunk-certified
  forwarder.
* NIST SP 800-92 (Log Management, 2006): §3.2 defines what must be logged —
  who, what, when, where, outcome. The AetherOS ledger captures all of these
  in its ``actor``, ``event_type``, ``timestamp``, ``entry_hash``, and
  ``payload`` fields.
* ISO 8601 — timestamps in ``YYYY-MM-DDTHH:MM:SS.ffffff+HH:MM`` form for
  human readability and SIEM compatibility.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


# ── stable AuditEvent schema ──────────────────────────────────────────────────

@dataclass
class AuditEvent:
    """A single normalised audit event, derived from one evidence ledger entry.

    Field alignment with OCSF v1.0 (CISA 2022):
      time_iso   → ``time`` (ISO-8601; OCSF uses epoch ms, we use ISO for readability)
      event_type → ``class_name`` / ``activity_name``
      actor      → ``actor.user.name``
      tenant_id  → ``actor.session.uid`` (tenant scope)
      run_id     → ``resources[0].uid``
      seq        → ``metadata.sequence``
      entry_hash → ``metadata.uid`` (tamper-evidence anchor)
      prev_hash  → ``metadata.original_uid`` (chain linkage)
      payload    → ``unmapped`` (raw governance payload, preserved as-is)
    """

    time_iso: str          # ISO-8601 UTC timestamp from the ledger entry
    event_type: str        # e.g. "tool.invoked", "policy.denied", "run.completed"
    actor: str             # agent_id or "control-plane"
    tenant_id: str         # tenant scope
    run_id: str            # which run this event belongs to
    seq: int               # position in the ledger (0-based)
    entry_hash: str        # SHA-256 hash of this entry (tamper evidence)
    prev_hash: str         # hash of the preceding entry (chain linkage)
    payload: dict          # raw governance payload from the ledger

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable dict, suitable for SIEM ingestion."""
        d = asdict(self)
        # Add a convenience epoch_ms field for SIEM tools that want numeric time.
        try:
            dt = datetime.fromisoformat(self.time_iso)
            d["epoch_ms"] = int(dt.timestamp() * 1000)
        except ValueError:
            d["epoch_ms"] = None
        return d

    def to_splunk_hec(self) -> dict[str, Any]:
        """Splunk HTTP Event Collector envelope: {\"time\": <epoch_s>, \"event\": {...}}."""
        try:
            dt = datetime.fromisoformat(self.time_iso)
            epoch_s = dt.timestamp()
        except ValueError:
            epoch_s = 0.0
        return {"time": epoch_s, "event": self.to_dict()}


# ── exporter ──────────────────────────────────────────────────────────────────

@dataclass
class AuditPage:
    """A paginated slice of audit events."""

    events: list[AuditEvent]
    total: int            # total matching events across all pages
    offset: int
    limit: int
    has_more: bool        # True when offset + len(events) < total

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "offset": self.offset,
            "limit": self.limit,
            "has_more": self.has_more,
            "events": [e.to_dict() for e in self.events],
        }


class AuditExporter:
    """Stateless exporter: collects, normalises, filters, and paginates audit events.

    Designed to be constructed once (per application) and called per-request.
    All state is derived from the ledger entries passed to ``export``; no internal
    caches or mutable state.
    """

    def export(
        self,
        runs: list[tuple[str, str, Any]],  # [(run_id, tenant_id, ledger), ...]
        event_type: str | None = None,
        since: str | None = None,   # ISO-8601 or epoch seconds as string
        until: str | None = None,   # ISO-8601 or epoch seconds as string
        actor: str | None = None,
        offset: int = 0,
        limit: int = 100,
        max_limit: int = 1000,
    ) -> AuditPage:
        """Export a filtered, paginated page of audit events from one or more run ledgers.

        Parameters
        ----------
        runs:
            List of ``(run_id, tenant_id, ledger)`` tuples. Each ledger must
            expose a ``.entries()`` method returning objects with ``seq``,
            ``event_type``, ``actor``, ``timestamp``, ``payload``,
            ``entry_hash``, ``prev_hash`` attributes.
        event_type:
            Optional exact match filter on ``event_type``.
        since:
            Optional lower bound on event timestamp (inclusive). Accepts ISO-8601
            or Unix epoch as a string.
        until:
            Optional upper bound on event timestamp (exclusive). Same formats.
        actor:
            Optional exact match filter on ``actor``.
        offset:
            Zero-based starting position in the filtered + sorted event list.
        limit:
            Maximum events to return. Capped at ``max_limit``.
        max_limit:
            Server-side cap on ``limit`` (config-driven, typically 1000).
        """
        limit = min(limit, max_limit)
        since_dt = _parse_dt(since)
        until_dt = _parse_dt(until)

        all_events: list[AuditEvent] = []
        for run_id, tenant_id, ledger in runs:
            for e in ledger.entries():
                evt = AuditEvent(
                    time_iso=e.timestamp,
                    event_type=e.event_type,
                    actor=e.actor,
                    tenant_id=tenant_id,
                    run_id=run_id,
                    seq=e.seq,
                    entry_hash=e.entry_hash,
                    prev_hash=e.prev_hash,
                    payload=dict(e.payload) if isinstance(e.payload, dict) else {},
                )
                # Apply filters.
                if event_type is not None and evt.event_type != event_type:
                    continue
                if actor is not None and evt.actor != actor:
                    continue
                if since_dt is not None:
                    try:
                        evt_dt = datetime.fromisoformat(evt.time_iso)
                        if evt_dt.tzinfo is None:
                            evt_dt = evt_dt.replace(tzinfo=timezone.utc)
                        if evt_dt < since_dt:
                            continue
                    except ValueError:
                        pass
                if until_dt is not None:
                    try:
                        evt_dt = datetime.fromisoformat(evt.time_iso)
                        if evt_dt.tzinfo is None:
                            evt_dt = evt_dt.replace(tzinfo=timezone.utc)
                        if evt_dt >= until_dt:
                            continue
                    except ValueError:
                        pass
                all_events.append(evt)

        # Stable sort: primary = ISO timestamp (lexicographic = chronological for UTC),
        # secondary = seq (stable within the same timestamp).
        all_events.sort(key=lambda ev: (ev.time_iso, ev.seq))

        total = len(all_events)
        page = all_events[offset: offset + limit]
        return AuditPage(
            events=page,
            total=total,
            offset=offset,
            limit=limit,
            has_more=(offset + len(page)) < total,
        )

    @staticmethod
    def to_ndjson(events: list[AuditEvent]) -> str:
        """Serialise events as NDJSON (one JSON object per line).

        Standard format for Elastic Bulk API, Splunk HEC stream, Datadog Logs API.
        Each line is a self-contained JSON object. Lines are separated by ``\\n``.
        """
        lines = [json.dumps(e.to_dict(), separators=(",", ":")) for e in events]
        return "\n".join(lines) + ("\n" if lines else "")

    @staticmethod
    def summary(
        runs: list[tuple[str, str, Any]],
    ) -> dict[str, Any]:
        """Return a lightweight event-count summary across all provided run ledgers.

        Suitable for a dashboard overview without the cost of a full export page.
        Groups events by type, counts by actor, lists distinct event types, and
        reports the time range of the audit window.

        This is the Phase 19 replacement / supplement for the Phase 7 ``GET /compliance``
        aggregate (which remains unchanged for backward-compatibility).
        """
        by_type: dict[str, int] = {}
        by_actor: dict[str, int] = {}
        timestamps: list[str] = []
        total = 0

        for run_id, tenant_id, ledger in runs:
            for e in ledger.entries():
                total += 1
                by_type[e.event_type] = by_type.get(e.event_type, 0) + 1
                by_actor[e.actor] = by_actor.get(e.actor, 0) + 1
                if e.timestamp:
                    timestamps.append(e.timestamp)

        timestamps.sort()
        return {
            "total_events": total,
            "run_count": len(runs),
            "earliest": timestamps[0] if timestamps else None,
            "latest": timestamps[-1] if timestamps else None,
            "event_types": by_type,
            "actors": by_actor,
        }


# ── helpers ───────────────────────────────────────────────────────────────────

def _parse_dt(value: str | None) -> datetime | None:
    """Parse an ISO-8601 or Unix epoch string into a timezone-aware datetime, or None."""
    if value is None:
        return None
    # Try epoch (float or int as string).
    try:
        epoch = float(value)
        return datetime.fromtimestamp(epoch, tz=timezone.utc)
    except (ValueError, OverflowError):
        pass
    # Try ISO-8601.
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None
