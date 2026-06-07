"""Governed-skill marketplace (Phase 7e).

A marketplace where skills are *installed under governance*, not merely downloaded. The
whole point of AetherOS is that capability is granted deliberately and provably — so a
third-party skill must prove its origin and stay within the installing tenant's authority
before it can ever run.

Design (atom of thoughts): a marketplace skill =
  - a manifest: id + version + publisher (agent id + public key) + required scopes +
    declared tools + description,
  - an Ed25519 signature by the publisher over the *canonical* manifest bytes,
  - an install-time governance gate.

Install gate (chain of thoughts, default-deny):
  1. Canonicalize the manifest deterministically and verify the publisher signature over
     those exact bytes — origin and integrity. A tampered manifest fails here.
  2. Check every required scope is permitted by the installing tenant's scope allowlist —
     least privilege; a skill cannot acquire authority the tenant has not delegated.
  3. Ask the constitution to judge each requested scope. If any is constitutionally
     forbidden, installation is refused outright — supreme law applies to supply chain,
     not just runtime.
  4. Record the install (or rejection) as tamper-evident evidence.

Reflection: this reuses the existing trust primitives rather than inventing new ones —
Ed25519 identity for signing, the Rust constitution for supremacy, the evidence ledger for
auditability. The marketplace is governance applied to the supply chain.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field

from aetheros import EvidenceLedger, verify_signature

from .constitution import ConstitutionEngine


class MarketplaceError(Exception):
    """Base class for marketplace errors."""


class SignatureInvalid(MarketplaceError):
    """The publisher signature does not verify over the manifest."""


class ScopeNotPermitted(MarketplaceError):
    """A required scope is outside the installing tenant's allowlist."""


class ConstitutionallyForbidden(MarketplaceError):
    """A required scope is forbidden by the constitution; install is refused."""


@dataclass(frozen=True)
class SkillManifest:
    """A publishable, signable description of a governed skill."""

    skill_id: str
    version: str
    publisher_agent_id: str
    publisher_public_key: str
    required_scopes: tuple[str, ...]
    declared_tools: tuple[str, ...]
    description: str = ""

    def canonical_bytes(self) -> bytes:
        """Deterministic byte serialization for signing/verification.

        Sorted keys + sorted scope/tool lists so the same logical manifest always yields
        identical bytes regardless of construction order.
        """
        doc = {
            "skill_id": self.skill_id,
            "version": self.version,
            "publisher_agent_id": self.publisher_agent_id,
            "publisher_public_key": self.publisher_public_key,
            "required_scopes": sorted(self.required_scopes),
            "declared_tools": sorted(self.declared_tools),
            "description": self.description,
        }
        return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_view(self) -> dict:
        return {
            "skill_id": self.skill_id,
            "version": self.version,
            "publisher_agent_id": self.publisher_agent_id,
            "required_scopes": sorted(self.required_scopes),
            "declared_tools": sorted(self.declared_tools),
            "description": self.description,
        }


@dataclass(frozen=True)
class SignedSkill:
    """A manifest plus the publisher's Ed25519 signature over its canonical bytes."""

    manifest: SkillManifest
    signature: str  # hex

    def verify(self) -> bool:
        return verify_signature(
            self.manifest.publisher_public_key,
            self.manifest.canonical_bytes(),
            self.signature,
        )


def sign_skill(manifest: SkillManifest, publisher) -> SignedSkill:
    """Publisher signs a manifest. `publisher` is an AgentIdentity.

    Binds the signing identity into the manifest so verification is self-contained.
    """
    if publisher.agent_id != manifest.publisher_agent_id:
        raise MarketplaceError("publisher identity does not match manifest publisher_agent_id")
    if publisher.public_key != manifest.publisher_public_key:
        raise MarketplaceError("publisher public key does not match manifest")
    signature = publisher.sign(manifest.canonical_bytes())
    return SignedSkill(manifest=manifest, signature=signature)


@dataclass
class InstalledSkill:
    """An admitted skill, recorded with the evidence seq of its governed install."""

    manifest: SkillManifest
    installed_at_seq: int


@dataclass
class SkillMarketplace:
    """A governed marketplace: publish signed skills, install under the install gate."""

    constitution: ConstitutionEngine
    ledger: EvidenceLedger = field(default_factory=EvidenceLedger)
    # Per-tenant scope allowlists (glob-free exact prefixes handled by the caller policy).
    _catalog: dict[str, SignedSkill] = field(default_factory=dict)
    _installed: dict[tuple[str, str], InstalledSkill] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    # ── publishing ───────────────────────────────────────────────────────────

    def publish(self, signed: SignedSkill) -> None:
        """List a signed skill. Rejected if the signature does not verify."""
        if not signed.verify():
            raise SignatureInvalid(
                f"skill {signed.manifest.skill_id}: publisher signature invalid"
            )
        with self._lock:
            key = f"{signed.manifest.skill_id}@{signed.manifest.version}"
            self._catalog[key] = signed

    def catalog(self) -> list[SkillManifest]:
        with self._lock:
            return [s.manifest for s in self._catalog.values()]

    # ── governed install ─────────────────────────────────────────────────────

    def install(
        self,
        signed: SignedSkill,
        tenant_id: str,
        permitted_scopes: set[str],
    ) -> InstalledSkill:
        """Install a skill under the full governance gate (default-deny).

        `permitted_scopes` is the set of scopes the installing tenant is willing to
        delegate. Every check that fails records a rejection in the ledger and raises.
        """
        manifest = signed.manifest

        # 1. Origin + integrity.
        if not signed.verify():
            self._record_rejection(tenant_id, manifest, "signature_invalid")
            raise SignatureInvalid(f"skill {manifest.skill_id}: publisher signature invalid")

        # 2. Least privilege: every required scope must be tenant-permitted.
        missing = [s for s in manifest.required_scopes if s not in permitted_scopes]
        if missing:
            self._record_rejection(tenant_id, manifest, f"scope_not_permitted:{missing}")
            raise ScopeNotPermitted(
                f"skill {manifest.skill_id} requires scopes not permitted by tenant "
                f"{tenant_id}: {missing}"
            )

        # 3. Constitutional supremacy over the supply chain.
        for scope in manifest.required_scopes:
            verdict = self.constitution.judge(
                scope=scope, tool="install", autonomy_tier=0, cost_minor=0, high_impact=True
            )
            if not verdict.permitted:
                self._record_rejection(
                    tenant_id, manifest, f"constitutionally_forbidden:{scope}:{verdict.article_id}"
                )
                raise ConstitutionallyForbidden(
                    f"skill {manifest.skill_id} requests constitutionally forbidden scope "
                    f"{scope!r} (article {verdict.article_id})"
                )

        # 4. Admit + record.
        with self._lock:
            seq, _hash = self.ledger.append(
                "control-plane",
                "marketplace.skill_installed",
                {
                    "tenant_id": tenant_id,
                    "skill_id": manifest.skill_id,
                    "version": manifest.version,
                    "publisher": manifest.publisher_agent_id,
                    "scopes": sorted(manifest.required_scopes),
                },
            )
            installed = InstalledSkill(manifest=manifest, installed_at_seq=seq)
            self._installed[(tenant_id, manifest.skill_id)] = installed
            return installed

    def is_installed(self, tenant_id: str, skill_id: str) -> bool:
        with self._lock:
            return (tenant_id, skill_id) in self._installed

    def installed(self, tenant_id: str) -> list[InstalledSkill]:
        with self._lock:
            return [v for (t, _s), v in self._installed.items() if t == tenant_id]

    # ── helpers ──────────────────────────────────────────────────────────────

    def _record_rejection(self, tenant_id: str, manifest: SkillManifest, reason: str) -> None:
        with self._lock:
            self.ledger.append(
                "control-plane",
                "marketplace.install_rejected",
                {
                    "tenant_id": tenant_id,
                    "skill_id": manifest.skill_id,
                    "version": manifest.version,
                    "reason": reason,
                },
            )
