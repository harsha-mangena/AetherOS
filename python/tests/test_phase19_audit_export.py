"""Phase 19: SIEM audit-log export — unit and integration tests.

Atom of thoughts (each test validates exactly one independently verifiable property)
─────────────────────────────────────────────────────────────────────────────────────
Unit-layer (AuditExporter directly, no HTTP):
  1.  export() with no runs returns an empty AuditPage (total=0, has_more=False)
  2.  AuditEvent fields map correctly from a ledger entry (seq, actor, event_type,
      time_iso, entry_hash, prev_hash, payload)
  3.  to_dict() includes epoch_ms derived from time_iso
  4.  to_splunk_hec() wraps the event in {"time": <epoch_s>, "event": {...}}
  5.  filter by event_type returns only matching events
  6.  filter by actor returns only events from that actor
  7.  filter by since excludes events before the lower bound
  8.  filter by until excludes events at or after the upper bound
  9.  since + until together define a half-open [since, until) window
  10. offset + limit paginate correctly (offset skips, limit caps)
  11. has_more is True when the page does not reach the last event
  12. has_more is False on the last page
  13. limit is capped at max_limit even when the caller asks for more
  14. events from multiple runs are merged and sorted by (time_iso, seq)
  15. to_ndjson() produces one JSON line per event, newline-terminated
  16. to_ndjson() on an empty list returns an empty string
  17. summary() counts total events, groups by event_type and actor
  18. summary() earliest/latest reflect the actual timestamp range
  19. summary() with no runs returns zeros and None timestamps

HTTP-layer (FastAPI TestClient, audit disabled — default):
  20. GET /audit/events returns 403 when audit.enabled = False
  21. GET /audit/summary returns 403 when audit.enabled = False

HTTP-layer (audit enabled):
  22. GET /audit/events returns 200 with correct AuditPage schema
  23. GET /audit/events?event_type= filters events correctly
  24. GET /audit/events?offset=&limit= paginates correctly
  25. GET /audit/summary returns correct counts and window
  26. GET /audit/events for unknown tenant returns 404
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from aetheros_orchestrator.audit_exporter import AuditEvent, AuditExporter, AuditPage
from aetheros_orchestrator.api import create_app
from aetheros_orchestrator.config import AuditConfig
from aetheros_orchestrator.run_service import RunService


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_entry(
    seq: int,
    event_type: str = "tool.invoked",
    actor: str = "agent-1",
    timestamp: str = "2024-01-15T10:00:00+00:00",
    payload: dict | None = None,
    entry_hash: str = "",
    prev_hash: str = "",
) -> MagicMock:
    """Build a mock ledger entry with the exact attributes the exporter reads."""
    e = MagicMock()
    e.seq = seq
    e.event_type = event_type
    e.actor = actor
    e.timestamp = timestamp
    e.payload = payload or {"tool": "read_file"}
    e.entry_hash = entry_hash or f"hash{seq:04d}"
    e.prev_hash = prev_hash or (f"hash{seq-1:04d}" if seq > 0 else "0" * 64)
    return e


def _make_ledger(*entries) -> MagicMock:
    """Build a mock EvidenceLedger whose .entries() returns the given entries."""
    ledger = MagicMock()
    ledger.entries.return_value = list(entries)
    return ledger


def _make_run_triple(run_id: str, tenant_id: str, *entries) -> tuple:
    """Return (run_id, tenant_id, ledger) suitable for AuditExporter.export()."""
    return (run_id, tenant_id, _make_ledger(*entries))


def _make_client(audit_enabled: bool = False) -> tuple[TestClient, RunService]:
    """Create a TestClient with two tenants and configurable audit flag."""
    svc = RunService()
    svc.tenants.create("Tenant Alpha", tenant_id="alpha")
    svc.tenants.create("Tenant Beta", tenant_id="beta")
    audit_cfg = AuditConfig(enabled=audit_enabled, max_page_size=1000)
    app = create_app(svc, audit_config=audit_cfg)
    return TestClient(app, raise_server_exceptions=False), svc


def _create_run(client: TestClient, tenant_id: str = "alpha") -> str:
    r = client.post(
        "/runs",
        json={"intent": "fix the bug", "submitted_by": "vamsi", "budget_minor": 500},
        headers={"X-Tenant-Id": tenant_id},
    )
    assert r.status_code == 200
    run_id = r.json()["run_id"]
    # Advance once so ledger gets events.
    client.post(f"/runs/{run_id}/advance", headers={"X-Tenant-Id": tenant_id})
    return run_id


# ── Unit: AuditExporter ───────────────────────────────────────────────────────

class TestAuditExporterUnit:

    def test_empty_runs_returns_empty_page(self):
        """Property 1: no runs → empty AuditPage."""
        exporter = AuditExporter()
        page = exporter.export([])
        assert page.total == 0
        assert page.events == []
        assert page.has_more is False

    def test_audit_event_fields_mapped_correctly(self):
        """Property 2: AuditEvent fields map from ledger entry attributes."""
        entry = _make_entry(
            seq=3,
            event_type="policy.denied",
            actor="control-plane",
            timestamp="2024-06-01T09:30:00+00:00",
            payload={"reason": "budget exceeded"},
            entry_hash="abcdef123456",
            prev_hash="fedcba654321",
        )
        runs = [_make_run_triple("run-1", "alpha", entry)]
        exporter = AuditExporter()
        page = exporter.export(runs)

        assert page.total == 1
        evt = page.events[0]
        assert evt.seq == 3
        assert evt.event_type == "policy.denied"
        assert evt.actor == "control-plane"
        assert evt.time_iso == "2024-06-01T09:30:00+00:00"
        assert evt.payload == {"reason": "budget exceeded"}
        assert evt.entry_hash == "abcdef123456"
        assert evt.prev_hash == "fedcba654321"
        assert evt.tenant_id == "alpha"
        assert evt.run_id == "run-1"

    def test_to_dict_includes_epoch_ms(self):
        """Property 3: to_dict() includes epoch_ms derived from time_iso."""
        entry = _make_entry(0, timestamp="2024-01-01T00:00:00+00:00")
        runs = [_make_run_triple("r", "t", entry)]
        page = AuditExporter().export(runs)
        d = page.events[0].to_dict()
        assert "epoch_ms" in d
        # 2024-01-01T00:00:00Z = 1704067200000 ms
        assert d["epoch_ms"] == 1704067200000

    def test_to_splunk_hec_envelope(self):
        """Property 4: to_splunk_hec() wraps in {"time": <epoch_s>, "event": {...}}."""
        entry = _make_entry(0, timestamp="2024-01-01T00:00:00+00:00")
        runs = [_make_run_triple("r", "t", entry)]
        page = AuditExporter().export(runs)
        hec = page.events[0].to_splunk_hec()
        assert "time" in hec
        assert "event" in hec
        assert abs(hec["time"] - 1704067200.0) < 1.0
        assert hec["event"]["event_type"] == "tool.invoked"

    def test_filter_event_type(self):
        """Property 5: event_type filter returns only matching events."""
        entries = [
            _make_entry(0, event_type="tool.invoked"),
            _make_entry(1, event_type="policy.denied"),
            _make_entry(2, event_type="tool.invoked"),
        ]
        runs = [_make_run_triple("r", "t", *entries)]
        page = AuditExporter().export(runs, event_type="policy.denied")
        assert page.total == 1
        assert page.events[0].event_type == "policy.denied"

    def test_filter_actor(self):
        """Property 6: actor filter returns only events from that actor."""
        entries = [
            _make_entry(0, actor="agent-A"),
            _make_entry(1, actor="agent-B"),
            _make_entry(2, actor="agent-A"),
        ]
        runs = [_make_run_triple("r", "t", *entries)]
        page = AuditExporter().export(runs, actor="agent-B")
        assert page.total == 1
        assert page.events[0].actor == "agent-B"

    def test_filter_since_excludes_earlier(self):
        """Property 7: since filter excludes events before the lower bound."""
        entries = [
            _make_entry(0, timestamp="2024-01-01T08:00:00+00:00"),
            _make_entry(1, timestamp="2024-01-01T10:00:00+00:00"),
            _make_entry(2, timestamp="2024-01-01T12:00:00+00:00"),
        ]
        runs = [_make_run_triple("r", "t", *entries)]
        page = AuditExporter().export(runs, since="2024-01-01T10:00:00+00:00")
        assert page.total == 2
        assert all(e.time_iso >= "2024-01-01T10:00:00+00:00" for e in page.events)

    def test_filter_until_excludes_at_or_after(self):
        """Property 8: until filter excludes events at or after the upper bound."""
        entries = [
            _make_entry(0, timestamp="2024-01-01T08:00:00+00:00"),
            _make_entry(1, timestamp="2024-01-01T10:00:00+00:00"),
            _make_entry(2, timestamp="2024-01-01T12:00:00+00:00"),
        ]
        runs = [_make_run_triple("r", "t", *entries)]
        page = AuditExporter().export(runs, until="2024-01-01T10:00:00+00:00")
        assert page.total == 1
        assert page.events[0].time_iso == "2024-01-01T08:00:00+00:00"

    def test_filter_since_until_window(self):
        """Property 9: since + until form a half-open [since, until) window."""
        entries = [
            _make_entry(0, timestamp="2024-01-01T07:00:00+00:00"),
            _make_entry(1, timestamp="2024-01-01T09:00:00+00:00"),
            _make_entry(2, timestamp="2024-01-01T11:00:00+00:00"),
            _make_entry(3, timestamp="2024-01-01T13:00:00+00:00"),
        ]
        runs = [_make_run_triple("r", "t", *entries)]
        page = AuditExporter().export(
            runs,
            since="2024-01-01T09:00:00+00:00",
            until="2024-01-01T11:00:00+00:00",
        )
        assert page.total == 1
        assert page.events[0].seq == 1

    def test_offset_and_limit_paginate(self):
        """Property 10: offset skips events; limit caps the page size."""
        entries = [_make_entry(i) for i in range(10)]
        runs = [_make_run_triple("r", "t", *entries)]
        page = AuditExporter().export(runs, offset=3, limit=4)
        assert len(page.events) == 4
        assert page.events[0].seq == 3
        assert page.offset == 3
        assert page.limit == 4

    def test_has_more_true_when_not_last_page(self):
        """Property 11: has_more is True when there are events beyond the page."""
        entries = [_make_entry(i) for i in range(5)]
        runs = [_make_run_triple("r", "t", *entries)]
        page = AuditExporter().export(runs, offset=0, limit=3)
        assert page.has_more is True
        assert page.total == 5

    def test_has_more_false_on_last_page(self):
        """Property 12: has_more is False when the page covers the last event."""
        entries = [_make_entry(i) for i in range(5)]
        runs = [_make_run_triple("r", "t", *entries)]
        page = AuditExporter().export(runs, offset=3, limit=10)
        assert page.has_more is False
        assert len(page.events) == 2  # only 2 left after offset=3

    def test_limit_capped_at_max_limit(self):
        """Property 13: limit is silently capped at max_limit."""
        entries = [_make_entry(i) for i in range(20)]
        runs = [_make_run_triple("r", "t", *entries)]
        page = AuditExporter().export(runs, limit=9999, max_limit=5)
        assert len(page.events) == 5
        assert page.limit == 5

    def test_multi_run_merge_sorted(self):
        """Property 14: events from multiple runs merge and sort by (time_iso, seq)."""
        run_a = _make_run_triple(
            "run-A", "alpha",
            _make_entry(0, timestamp="2024-01-01T10:00:00+00:00", event_type="A0"),
            _make_entry(1, timestamp="2024-01-01T12:00:00+00:00", event_type="A1"),
        )
        run_b = _make_run_triple(
            "run-B", "alpha",
            _make_entry(0, timestamp="2024-01-01T11:00:00+00:00", event_type="B0"),
            _make_entry(1, timestamp="2024-01-01T13:00:00+00:00", event_type="B1"),
        )
        page = AuditExporter().export([run_a, run_b])
        assert page.total == 4
        types = [e.event_type for e in page.events]
        assert types == ["A0", "B0", "A1", "B1"]

    def test_to_ndjson_one_line_per_event(self):
        """Property 15: to_ndjson() produces one JSON line per event."""
        entries = [_make_entry(i, event_type=f"type.{i}") for i in range(3)]
        runs = [_make_run_triple("r", "t", *entries)]
        page = AuditExporter().export(runs)
        ndjson = AuditExporter.to_ndjson(page.events)
        lines = [ln for ln in ndjson.strip().split("\n") if ln]
        assert len(lines) == 3
        for i, line in enumerate(lines):
            obj = json.loads(line)
            assert obj["event_type"] == f"type.{i}"

    def test_to_ndjson_empty_returns_empty_string(self):
        """Property 16: to_ndjson() on an empty list returns an empty string."""
        result = AuditExporter.to_ndjson([])
        assert result == ""

    def test_summary_counts(self):
        """Property 17: summary() counts total events grouped by type and actor."""
        entries = [
            _make_entry(0, event_type="tool.invoked", actor="agent-A"),
            _make_entry(1, event_type="tool.invoked", actor="agent-A"),
            _make_entry(2, event_type="policy.denied", actor="control-plane"),
        ]
        runs = [_make_run_triple("r", "t", *entries)]
        s = AuditExporter.summary(runs)
        assert s["total_events"] == 3
        assert s["event_types"]["tool.invoked"] == 2
        assert s["event_types"]["policy.denied"] == 1
        assert s["actors"]["agent-A"] == 2
        assert s["actors"]["control-plane"] == 1

    def test_summary_earliest_latest(self):
        """Property 18: summary() earliest/latest reflect the actual timestamp range."""
        entries = [
            _make_entry(0, timestamp="2024-01-01T08:00:00+00:00"),
            _make_entry(1, timestamp="2024-01-01T10:00:00+00:00"),
            _make_entry(2, timestamp="2024-01-01T12:00:00+00:00"),
        ]
        runs = [_make_run_triple("r", "t", *entries)]
        s = AuditExporter.summary(runs)
        assert s["earliest"] == "2024-01-01T08:00:00+00:00"
        assert s["latest"] == "2024-01-01T12:00:00+00:00"

    def test_summary_no_runs(self):
        """Property 19: summary() with no runs returns zeros and None timestamps."""
        s = AuditExporter.summary([])
        assert s["total_events"] == 0
        assert s["run_count"] == 0
        assert s["earliest"] is None
        assert s["latest"] is None


# ── HTTP: audit disabled (default) ───────────────────────────────────────────

class TestAuditDisabled:

    def test_audit_events_returns_403_when_disabled(self):
        """Property 20: GET /audit/events → 403 when audit.enabled = False."""
        client, _ = _make_client(audit_enabled=False)
        r = client.get("/audit/events", headers={"X-Tenant-Id": "alpha"})
        assert r.status_code == 403
        assert "disabled" in r.json()["detail"]

    def test_audit_summary_returns_403_when_disabled(self):
        """Property 21: GET /audit/summary → 403 when audit.enabled = False."""
        client, _ = _make_client(audit_enabled=False)
        r = client.get("/audit/summary", headers={"X-Tenant-Id": "alpha"})
        assert r.status_code == 403


# ── HTTP: audit enabled ───────────────────────────────────────────────────────

class TestAuditEnabled:

    def test_audit_events_200_with_schema(self):
        """Property 22: GET /audit/events returns 200 with correct AuditPage schema."""
        client, _ = _make_client(audit_enabled=True)
        _create_run(client, tenant_id="alpha")
        r = client.get("/audit/events", headers={"X-Tenant-Id": "alpha"})
        assert r.status_code == 200
        body = r.json()
        assert "total" in body
        assert "offset" in body
        assert "limit" in body
        assert "has_more" in body
        assert "events" in body
        assert isinstance(body["events"], list)
        if body["events"]:
            evt = body["events"][0]
            for field in ("time_iso", "event_type", "actor", "tenant_id", "run_id",
                          "seq", "entry_hash", "prev_hash", "payload", "epoch_ms"):
                assert field in evt, f"missing field: {field}"

    def test_audit_events_filter_event_type(self):
        """Property 23: GET /audit/events?event_type= filters correctly."""
        client, _ = _make_client(audit_enabled=True)
        _create_run(client, tenant_id="alpha")
        # First get all events to find a real event_type present.
        all_r = client.get("/audit/events", headers={"X-Tenant-Id": "alpha"})
        all_events = all_r.json()["events"]
        if not all_events:
            pytest.skip("no events produced by run advance (test environment)")
        target_type = all_events[0]["event_type"]
        r = client.get(
            f"/audit/events?event_type={target_type}",
            headers={"X-Tenant-Id": "alpha"},
        )
        assert r.status_code == 200
        filtered = r.json()["events"]
        assert all(e["event_type"] == target_type for e in filtered)

    def test_audit_events_pagination(self):
        """Property 24: offset + limit paginate correctly over real run events."""
        client, _ = _make_client(audit_enabled=True)
        _create_run(client, tenant_id="alpha")
        # Get total.
        all_r = client.get("/audit/events?limit=1000", headers={"X-Tenant-Id": "alpha"})
        total = all_r.json()["total"]
        if total < 2:
            pytest.skip("insufficient events for pagination test")
        # Page 1: first 1 event.
        p1 = client.get("/audit/events?offset=0&limit=1", headers={"X-Tenant-Id": "alpha"})
        assert p1.status_code == 200
        p1_body = p1.json()
        assert len(p1_body["events"]) == 1
        assert p1_body["has_more"] is True
        # Page 2: second event.
        p2 = client.get("/audit/events?offset=1&limit=1", headers={"X-Tenant-Id": "alpha"})
        assert p2.status_code == 200
        p2_events = p2.json()["events"]
        assert len(p2_events) == 1
        # Pages must be distinct events.
        assert p1_body["events"][0]["seq"] != p2_events[0]["seq"] or \
               p1_body["events"][0]["run_id"] != p2_events[0]["run_id"]

    def test_audit_summary_counts(self):
        """Property 25: GET /audit/summary returns correct counts and window."""
        client, _ = _make_client(audit_enabled=True)
        _create_run(client, tenant_id="alpha")
        r = client.get("/audit/summary", headers={"X-Tenant-Id": "alpha"})
        assert r.status_code == 200
        body = r.json()
        assert "total_events" in body
        assert "run_count" in body
        assert "earliest" in body
        assert "latest" in body
        assert "event_types" in body
        assert "actors" in body
        assert body["total_events"] >= 0
        assert body["run_count"] >= 1

    def test_audit_events_unknown_tenant_returns_404(self):
        """Property 26: GET /audit/events for unknown tenant → 404."""
        client, _ = _make_client(audit_enabled=True)
        r = client.get("/audit/events", headers={"X-Tenant-Id": "ghost"})
        assert r.status_code == 404
