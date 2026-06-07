"""Enterprise identity: IdP-mapped agent onboarding (Phase 6).

Enterprises onboard agents from their existing identity provider (Okta, Azure AD, any
OIDC issuer) rather than minting ad-hoc credentials. This module turns a *verified* set
of OIDC claims into a governed AetherOS onboarding decision: which tenant the agent joins,
which capability scopes it may request, and its starting autonomy ceiling.

Design (atom of thoughts). An onboarding =
    verified claims (iss, sub, email, groups, ...)
      -> a deterministic, config-driven ClaimMapping (claim/group -> tenant + scopes + tier)
      -> a provisioned agent bound to that tenant
      -> an evidence entry recording the decision (auditable, replayable).

The security-critical parts are (1) claim verification and (2) the claim->privilege
mapping. Both are deterministic and testable. Live network token verification (JWKS
fetch, signature/exp/aud checks against an issuer's discovery document) is intentionally
behind the `IdentityProvider` protocol so a real Okta/Azure provider drops in without
touching the mapping or onboarding logic. The bundled MockOIDCProvider verifies against
an in-memory signing secret so the whole flow is provable hermetically.

Default-deny: claims that match no mapping rule onboard nothing — onboarding raises
OnboardingDenied rather than silently granting default access.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol

from aetheros import EvidenceLedger

from .tenancy import TenantRegistry


class IdentityError(Exception):
    """Base class for identity / onboarding errors."""


class TokenVerificationError(IdentityError):
    """The presented token/assertion failed verification."""


class OnboardingDenied(IdentityError):
    """Verified claims matched no mapping rule (default-deny)."""


@dataclass(frozen=True)
class VerifiedClaims:
    """The subset of OIDC claims AetherOS maps to privileges.

    Produced only by an IdentityProvider after verification — never constructed from
    untrusted input directly in the onboarding path.
    """

    issuer: str
    subject: str
    email: str | None = None
    groups: tuple[str, ...] = ()
    name: str | None = None

    def to_view(self) -> dict:
        return {
            "issuer": self.issuer,
            "subject": self.subject,
            "email": self.email,
            "groups": list(self.groups),
            "name": self.name,
        }


class IdentityProvider(Protocol):
    """Verifies an external assertion and returns trusted claims.

    Real providers (Okta, Azure AD) implement this by validating a JWT against the
    issuer's JWKS (signature, exp, aud, iss). The onboarding logic depends only on this
    protocol, so swapping providers never touches the privilege-mapping code.
    """

    def verify(self, token: str) -> VerifiedClaims: ...


@dataclass
class ClaimMappingRule:
    """One config-driven rule mapping claims to a tenant + privileges.

    A rule matches when the issuer matches (glob) AND at least one of the agent's groups
    matches one of `match_groups` (glob), or `match_groups` is empty (issuer-only match).
    Higher `priority` wins; the first highest-priority match applies.
    """

    id: str
    tenant_id: str
    match_issuer: str = "*"
    match_groups: tuple[str, ...] = ()
    grant_scopes: tuple[str, ...] = ()
    max_autonomy_tier: int = 0
    priority: int = 0

    def matches(self, claims: VerifiedClaims) -> bool:
        if not fnmatch.fnmatch(claims.issuer, self.match_issuer):
            return False
        if not self.match_groups:
            return True
        return any(
            fnmatch.fnmatch(g, pat) for g in claims.groups for pat in self.match_groups
        )


@dataclass(frozen=True)
class OnboardingResult:
    """The governed outcome of onboarding an external identity."""

    agent_ref: str  # stable AetherOS reference: "<issuer>#<subject>"
    tenant_id: str
    scopes: tuple[str, ...]
    max_autonomy_tier: int
    rule_id: str
    claims: VerifiedClaims
    onboarded_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_view(self) -> dict:
        return {
            "agent_ref": self.agent_ref,
            "tenant_id": self.tenant_id,
            "scopes": list(self.scopes),
            "max_autonomy_tier": self.max_autonomy_tier,
            "rule_id": self.rule_id,
            "claims": self.claims.to_view(),
            "onboarded_at": self.onboarded_at,
        }


class OnboardingService:
    """Maps verified IdP claims to a governed onboarding decision, with evidence.

    Pure decision logic over an injected provider + mapping rules + tenant registry. It
    provisions the tenant on demand (so an IdP can drive tenant creation) and records an
    `agent.onboarded` evidence entry for every successful onboarding.
    """

    def __init__(
        self,
        provider: IdentityProvider,
        rules: list[ClaimMappingRule],
        tenants: TenantRegistry,
    ) -> None:
        self._provider = provider
        self._rules = sorted(rules, key=lambda r: r.priority, reverse=True)
        self._tenants = tenants

    def onboard(self, token: str, ledger: EvidenceLedger | None = None) -> OnboardingResult:
        claims = self._provider.verify(token)  # raises TokenVerificationError on failure
        rule = self._first_match(claims)
        if rule is None:
            raise OnboardingDenied(
                f"no mapping rule for issuer={claims.issuer} groups={list(claims.groups)}"
            )
        # Provision the tenant on demand so an IdP can onboard into a fresh workspace.
        self._tenants.ensure(rule.tenant_id, rule.tenant_id)
        result = OnboardingResult(
            agent_ref=f"{claims.issuer}#{claims.subject}",
            tenant_id=rule.tenant_id,
            scopes=rule.grant_scopes,
            max_autonomy_tier=rule.max_autonomy_tier,
            rule_id=rule.id,
            claims=claims,
        )
        if ledger is not None:
            ledger.append(
                "identity-provider",
                "agent.onboarded",
                {
                    "agent_ref": result.agent_ref,
                    "tenant_id": result.tenant_id,
                    "scopes": list(result.scopes),
                    "max_autonomy_tier": result.max_autonomy_tier,
                    "rule_id": result.rule_id,
                    "issuer": claims.issuer,
                },
            )
        return result

    def _first_match(self, claims: VerifiedClaims) -> ClaimMappingRule | None:
        for rule in self._rules:  # already sorted by priority desc
            if rule.matches(claims):
                return rule
        return None


# ── mock provider (deterministic, hermetic) ──────────────────────────────────


class MockOIDCProvider:
    """A deterministic OIDC provider for tests and local demos.

    Tokens are signed with an in-memory HMAC secret over canonical JSON claims, so the
    full verify -> map -> onboard flow is provable without any network. A real provider
    swaps in behind the same `verify` signature.
    """

    def __init__(self, issuer: str, secret: str = "dev-secret") -> None:
        self._issuer = issuer
        self._secret = secret.encode()

    def mint(
        self,
        subject: str,
        email: str | None = None,
        groups: tuple[str, ...] = (),
        name: str | None = None,
    ) -> str:
        import base64
        import hmac
        import json
        from hashlib import sha256

        payload = {
            "iss": self._issuer,
            "sub": subject,
            "email": email,
            "groups": list(groups),
            "name": name,
        }
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        sig = hmac.new(self._secret, body, sha256).digest()
        return base64.urlsafe_b64encode(body).decode() + "." + base64.urlsafe_b64encode(sig).decode()

    def verify(self, token: str) -> VerifiedClaims:
        import base64
        import hmac
        import json
        from hashlib import sha256

        try:
            body_b64, sig_b64 = token.split(".", 1)
            body = base64.urlsafe_b64decode(body_b64)
            sig = base64.urlsafe_b64decode(sig_b64)
        except Exception as exc:
            raise TokenVerificationError("malformed token") from exc

        expected = hmac.new(self._secret, body, sha256).digest()
        if not hmac.compare_digest(sig, expected):
            raise TokenVerificationError("bad signature")

        claims = json.loads(body)
        if claims.get("iss") != self._issuer:
            raise TokenVerificationError("issuer mismatch")
        return VerifiedClaims(
            issuer=claims["iss"],
            subject=claims["sub"],
            email=claims.get("email"),
            groups=tuple(claims.get("groups") or ()),
            name=claims.get("name"),
        )
