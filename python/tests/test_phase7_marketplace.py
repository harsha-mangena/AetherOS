"""Phase 7e tests: governed-skill marketplace.

Proves a skill must prove its origin (publisher signature), stay within the installing
tenant's delegated scopes, and never request a constitutionally forbidden capability —
and that every rejection is recorded as tamper-evident evidence.
"""

from __future__ import annotations

import pytest

from aetheros import AgentIdentity
from aetheros_orchestrator.config import ArticleConfig, ConstitutionConfig
from aetheros_orchestrator.constitution import ConstitutionEngine
from aetheros_orchestrator.marketplace import (
    ConstitutionallyForbidden,
    ScopeNotPermitted,
    SignatureInvalid,
    SkillManifest,
    SkillMarketplace,
    sign_skill,
)


def _publisher() -> AgentIdentity:
    return AgentIdentity.generate("acme-skills-inc")


def _manifest(pub: AgentIdentity, scopes=("s3:read:logs",), skill_id="log-triage") -> SkillManifest:
    return SkillManifest(
        skill_id=skill_id,
        version="1.0.0",
        publisher_agent_id=pub.agent_id,
        publisher_public_key=pub.public_key,
        required_scopes=tuple(scopes),
        declared_tools=("log_search",),
        description="Triage logs.",
    )


def _permissive_constitution() -> ConstitutionEngine:
    return ConstitutionEngine(ConstitutionConfig(version="v0", articles=[]))


def _forbidding_constitution() -> ConstitutionEngine:
    return ConstitutionEngine(
        ConstitutionConfig(
            version="v1",
            articles=[
                ArticleConfig(
                    id="no-prod-delete",
                    principle="Never delete production data.",
                    verdict="forbid",
                    scope="db:delete:prod*",
                )
            ],
        )
    )


def test_sign_and_verify_roundtrip() -> None:
    pub = _publisher()
    signed = sign_skill(_manifest(pub), pub)
    assert signed.verify() is True


def test_tampered_manifest_fails_verification() -> None:
    pub = _publisher()
    signed = sign_skill(_manifest(pub), pub)
    # Tamper: swap the manifest for one with an extra scope, keep the old signature.
    tampered = signed.__class__(
        manifest=_manifest(pub, scopes=("s3:read:logs", "secrets:read")),
        signature=signed.signature,
    )
    assert tampered.verify() is False


def test_publish_rejects_invalid_signature() -> None:
    pub = _publisher()
    mkt = SkillMarketplace(constitution=_permissive_constitution())
    bad = sign_skill(_manifest(pub), pub).__class__(
        manifest=_manifest(pub), signature="00" * 64
    )
    with pytest.raises(SignatureInvalid):
        mkt.publish(bad)


def test_install_happy_path_records_evidence() -> None:
    pub = _publisher()
    mkt = SkillMarketplace(constitution=_permissive_constitution())
    signed = sign_skill(_manifest(pub), pub)
    mkt.publish(signed)
    installed = mkt.install(signed, tenant_id="acme", permitted_scopes={"s3:read:logs"})
    assert mkt.is_installed("acme", "log-triage")
    assert installed.installed_at_seq >= 0
    events = [e.event_type for e in mkt.ledger.entries()]
    assert "marketplace.skill_installed" in events
    assert mkt.ledger.verify() is True


def test_install_denied_when_scope_not_permitted() -> None:
    pub = _publisher()
    mkt = SkillMarketplace(constitution=_permissive_constitution())
    signed = sign_skill(_manifest(pub, scopes=("s3:read:logs", "db:write:prod")), pub)
    with pytest.raises(ScopeNotPermitted):
        mkt.install(signed, tenant_id="acme", permitted_scopes={"s3:read:logs"})
    # Rejection recorded.
    events = [e.event_type for e in mkt.ledger.entries()]
    assert "marketplace.install_rejected" in events
    assert not mkt.is_installed("acme", "log-triage")


def test_install_refused_for_constitutionally_forbidden_scope() -> None:
    pub = _publisher()
    mkt = SkillMarketplace(constitution=_forbidding_constitution())
    signed = sign_skill(
        _manifest(pub, scopes=("db:delete:prod",), skill_id="prod-cleaner"), pub
    )
    # Even if the tenant would permit the scope, the constitution forbids it.
    with pytest.raises(ConstitutionallyForbidden):
        mkt.install(signed, tenant_id="acme", permitted_scopes={"db:delete:prod"})
    events = [e.event_type for e in mkt.ledger.entries()]
    assert "marketplace.install_rejected" in events


def test_install_forged_signature_is_rejected_at_gate() -> None:
    pub = _publisher()
    mkt = SkillMarketplace(constitution=_permissive_constitution())
    forged = sign_skill(_manifest(pub), pub).__class__(
        manifest=_manifest(pub), signature="11" * 64
    )
    with pytest.raises(SignatureInvalid):
        mkt.install(forged, tenant_id="acme", permitted_scopes={"s3:read:logs"})
