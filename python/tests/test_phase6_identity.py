"""Phase 6b tests: enterprise IdP-mapped agent onboarding.

Proves the verify -> map -> onboard flow is deterministic and default-deny: tampered
tokens are rejected, claims that match no rule onboard nothing, and a successful
onboarding provisions the tenant and records replayable evidence.
"""

from __future__ import annotations

import pytest
from aetheros import EvidenceLedger

from aetheros_orchestrator.identity_provider import (
    ClaimMappingRule,
    MockOIDCProvider,
    OnboardingDenied,
    OnboardingService,
    TokenVerificationError,
)
from aetheros_orchestrator.tenancy import TenantRegistry

ISSUER = "https://acme.okta.com"


def _service() -> tuple[OnboardingService, MockOIDCProvider, TenantRegistry]:
    provider = MockOIDCProvider(issuer=ISSUER, secret="s3cret")
    rules = [
        ClaimMappingRule(
            id="sre-admins",
            tenant_id="acme",
            match_issuer="https://acme.okta.com",
            match_groups=("sre-*", "platform-admins"),
            grant_scopes=("infra:read", "infra:restart"),
            max_autonomy_tier=2,
            priority=10,
        ),
        ClaimMappingRule(
            id="acme-readonly",
            tenant_id="acme",
            match_issuer="https://acme.okta.com",
            match_groups=(),  # any verified acme user
            grant_scopes=("infra:read",),
            max_autonomy_tier=0,
            priority=1,
        ),
    ]
    tenants = TenantRegistry()
    return OnboardingService(provider, rules, tenants), provider, tenants


def test_verify_rejects_tampered_token():
    _, provider, _ = _service()
    tok = provider.mint("agent-1", groups=("sre-oncall",))
    tampered = tok[:-2] + ("AA" if not tok.endswith("AA") else "BB")
    with pytest.raises(TokenVerificationError):
        provider.verify(tampered)


def test_verify_rejects_wrong_issuer():
    other = MockOIDCProvider(issuer="https://evil.example", secret="s3cret")
    real = MockOIDCProvider(issuer=ISSUER, secret="s3cret")
    tok = other.mint("agent-x")
    with pytest.raises(TokenVerificationError):
        real.verify(tok)


def test_high_priority_rule_wins():
    svc, provider, _ = _service()
    tok = provider.mint("agent-1", email="a@acme.com", groups=("sre-oncall",))
    result = svc.onboard(tok)
    assert result.rule_id == "sre-admins"
    assert result.tenant_id == "acme"
    assert "infra:restart" in result.scopes
    assert result.max_autonomy_tier == 2
    assert result.agent_ref == f"{ISSUER}#agent-1"


def test_fallback_rule_for_plain_user():
    svc, provider, _ = _service()
    tok = provider.mint("agent-2", email="b@acme.com", groups=("finance",))
    result = svc.onboard(tok)
    assert result.rule_id == "acme-readonly"
    assert result.scopes == ("infra:read",)
    assert result.max_autonomy_tier == 0


def test_default_deny_when_no_rule_matches():
    provider = MockOIDCProvider(issuer=ISSUER, secret="s3cret")
    # Only a rule for a *different* issuer.
    rules = [ClaimMappingRule(id="other", tenant_id="x", match_issuer="https://other.example")]
    svc = OnboardingService(provider, rules, TenantRegistry())
    tok = provider.mint("agent-3")
    with pytest.raises(OnboardingDenied):
        svc.onboard(tok)


def test_onboarding_provisions_tenant_on_demand():
    svc, provider, tenants = _service()
    assert not tenants.exists("acme")
    tok = provider.mint("agent-1", groups=("sre-oncall",))
    svc.onboard(tok)
    assert tenants.exists("acme")


def test_onboarding_emits_evidence():
    svc, provider, _ = _service()
    ledger = EvidenceLedger()
    tok = provider.mint("agent-1", email="a@acme.com", groups=("platform-admins",))
    result = svc.onboard(tok, ledger=ledger)
    assert ledger.verify()
    events = [e.event_type for e in ledger.entries()]
    assert "agent.onboarded" in events
    entry = next(e for e in ledger.entries() if e.event_type == "agent.onboarded")
    assert entry.payload["agent_ref"] == result.agent_ref
    assert entry.payload["tenant_id"] == "acme"
