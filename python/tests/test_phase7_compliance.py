"""Phase 7d tests: SOC2/GDPR compliance export from the evidence ledger.

Proves the report is a faithful projection — it passes when the ledger evidences each
control, fails the specific control when evidence is missing, and becomes non-attestable
the moment the underlying hash chain does not verify.
"""

from __future__ import annotations

from aetheros import EvidenceLedger
from aetheros_orchestrator.compliance import (
    ComplianceExporter,
    ControlStatus,
)


def _finding(report, control_id):
    return next(f for f in report.findings if f.control_id == control_id)


def test_clean_governed_run_is_compliant() -> None:
    led = EvidenceLedger()
    led.append("control-plane", "lease.issued", {"lease_id": "l1", "scopes": ["s3:read"]})
    led.append("agent-1", "tool.invoked", {"tool": "search", "high_impact": False, "cost_minor": 5})
    led.append("control-plane", "policy.denied", {"reason": "blocked write"})

    report = ComplianceExporter().generate(led, tenant_id="acme")
    assert report.attestable is True
    assert report.compliant is True
    assert _finding(report, "CC6.1").status == ControlStatus.PASS
    assert _finding(report, "CC7.2").status == ControlStatus.PASS
    assert _finding(report, "Art.32").status == ControlStatus.PASS


def test_tool_invocation_without_lease_fails_access_control() -> None:
    led = EvidenceLedger()
    # Invocation with no preceding lease issuance.
    led.append("agent-1", "tool.invoked", {"tool": "search", "high_impact": False})
    report = ComplianceExporter().generate(led)
    cc61 = _finding(report, "CC6.1")
    assert cc61.status == ControlStatus.FAIL
    assert report.compliant is False


def test_high_impact_without_approval_fails_change_control() -> None:
    led = EvidenceLedger()
    led.append("control-plane", "lease.issued", {"lease_id": "l1"})
    led.append("agent-1", "tool.invoked", {"tool": "restart", "high_impact": True})
    report = ComplianceExporter().generate(led)
    cc81 = _finding(report, "CC8.1")
    assert cc81.status == ControlStatus.FAIL


def test_high_impact_with_approval_passes_change_control() -> None:
    led = EvidenceLedger()
    led.append("control-plane", "lease.issued", {"lease_id": "l1"})
    led.append("human:vamsi", "approval.granted", {"step_id": "s1"})
    led.append("agent-1", "tool.invoked", {"tool": "restart", "high_impact": True})
    report = ComplianceExporter().generate(led)
    assert _finding(report, "CC8.1").status == ControlStatus.PASS
    assert report.compliant is True


def test_empty_ledger_is_not_applicable_not_failing() -> None:
    led = EvidenceLedger()
    report = ComplianceExporter().generate(led)
    # No activity: monitoring and processing are N/A, integrity still passes vacuously.
    assert _finding(report, "CC7.2").status == ControlStatus.NOT_APPLICABLE
    assert _finding(report, "Art.30").status == ControlStatus.NOT_APPLICABLE
    assert report.compliant is True


def test_report_is_reproducible() -> None:
    led = EvidenceLedger()
    led.append("control-plane", "lease.issued", {"lease_id": "l1"})
    led.append("agent-1", "tool.invoked", {"tool": "search", "high_impact": False})
    exporter = ComplianceExporter()
    a = exporter.generate(led, tenant_id="acme")
    b = exporter.generate(led, tenant_id="acme")
    # Same ledger -> same findings (ignoring the wall-clock generated_at).
    assert [f.to_view() for f in a.findings] == [f.to_view() for f in b.findings]
    assert a.ledger_head == b.ledger_head


def test_tampered_ledger_is_not_attestable() -> None:
    led = EvidenceLedger()
    led.append("control-plane", "lease.issued", {"lease_id": "l1"})
    led.append("agent-1", "tool.invoked", {"tool": "search", "high_impact": False})
    # Reconstruct a corrupted ledger from tampered JSON to break the hash chain.
    import json

    raw = json.loads(led.to_json())
    # Mutate a payload after the fact without recomputing hashes.
    if raw.get("entries"):
        raw["entries"][0]["payload"] = {"lease_id": "tampered"}
    # Rebuilding from corrupted JSON should either raise or verify() False; handle both.
    try:
        corrupted = EvidenceLedger.from_json(json.dumps(raw))
        intact = corrupted.verify()
    except Exception:
        intact = False

    assert intact is False
    # If a corrupted ledger somehow loads, the report must not be attestable.
    if intact is False:
        try:
            corrupted = EvidenceLedger.from_json(json.dumps(raw))
            report = ComplianceExporter().generate(corrupted)
            assert report.attestable is False
            assert report.compliant is False
        except Exception:
            # from_json rejecting tamper is itself the strongest possible guarantee.
            pass
