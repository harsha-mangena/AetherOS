"""Phase 14 tests: per-tenant Ed25519 (EdDSA) control-plane tokens.

Phase 12 signed every tenant's JWT with one shared HMAC secret — the same value
both signs and verifies for all tenants. Phase 14 adds an asymmetric path: each
tenant has its own Ed25519 keypair (RFC 8032/8037). A token for tenant T is signed
with T's private key and carries ``kid = T``; verification selects T's public key
by ``kid`` and additionally requires ``sub == kid``.

The properties under test (atom of thoughts — smallest verifiable units):

  Unit (AuthService / TenantKeyStore):
    1.  EdDSA issue produces a JWT whose JOSE header is alg=EdDSA, kid=tenant_id.
    2.  A valid EdDSA token validates and yields sub == tenant_id.
    3.  Per-tenant isolation: alpha and beta get different keypairs.
    4.  Cross-tenant forgery is rejected — a token signed by alpha's key cannot be
        validated as beta even if sub is rewritten (kid drives key selection, and
        sub==kid is enforced).
    5.  An unknown tenant (no key yet) fails verification closed (UnknownTenantKey).
    6.  Expired EdDSA token is rejected (InvalidToken).
    7.  Revocation works for EdDSA tokens (jti revocation set).
    8.  An HS256-signed token is rejected by an EdDSA service (algorithm confusion).
    9.  Keystore persists keys to disk → a brand-new AuthService over the same dir
        still validates a previously issued token (survives restart).
    10. Ephemeral keystore (empty dir) regenerates keys → old token no longer valid.
    11. JWKS exports OKP/Ed25519 public JWKs with kid == tenant_id and no private
        material; HS256 service exports an empty key set.

  HTTP (control plane, auth ENABLED + EdDSA):
    12. A protected route accepts a valid EdDSA Bearer token; tenant derives from sub.
    13. Cross-tenant: a token issued for alpha cannot read beta's run (tenant scoping).
    14. /auth/jwks is unprotected and returns the tenant's published key.
    15. Unknown-tenant / forged token → 401 with WWW-Authenticate.

  Backward-compatibility:
    16. Default algorithm is HS256; an HS256 service behaves exactly as Phase 12
        (JWKS empty, tokens validate, no keystore created).
    17. An unsupported algorithm value is rejected at construction.
"""

from __future__ import annotations

import jwt as _jwt
import pytest
from fastapi.testclient import TestClient

from aetheros_orchestrator.api import create_app
from aetheros_orchestrator.auth import (
    AuthConfig,
    AuthService,
    InvalidToken,
    RevokedToken,
    UnknownTenantKey,
)
from aetheros_orchestrator.run_service import RunService
from aetheros_orchestrator.token_keystore import TenantKeyStore

_ADMIN_SECRET = "test-admin-secret"
_SIGNING_SECRET = "test-signing-secret-must-be-32-chars-long!!"
_TTL = 3600


def _eddsa_cfg(
    *,
    enabled: bool = True,
    ttl: int = _TTL,
    keystore_dir: str = "",
) -> AuthConfig:
    return AuthConfig(
        enabled=enabled,
        algorithm="EdDSA",
        secret=_SIGNING_SECRET,  # ignored under EdDSA but kept for shape parity
        admin_secret=_ADMIN_SECRET,
        token_ttl_seconds=ttl,
        token_keystore_dir=keystore_dir,
    )


def _hs256_cfg(*, enabled: bool = True, ttl: int = _TTL) -> AuthConfig:
    return AuthConfig(
        enabled=enabled,
        algorithm="HS256",
        secret=_SIGNING_SECRET,
        admin_secret=_ADMIN_SECRET,
        token_ttl_seconds=ttl,
    )


def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _make_client(auth_svc: AuthService) -> tuple[TestClient, RunService]:
    svc = RunService()
    svc.tenants.create("Tenant Alpha", tenant_id="alpha")
    svc.tenants.create("Tenant Beta", tenant_id="beta")
    app = create_app(svc, auth_service=auth_svc)
    return TestClient(app, raise_server_exceptions=False), svc


# ── 1. header shape ────────────────────────────────────────────────────────────


def test_eddsa_token_header_has_alg_and_kid():
    svc = AuthService(_eddsa_cfg())
    token = svc.issue_token("alpha", _ADMIN_SECRET)
    header = _jwt.get_unverified_header(token)
    assert header["alg"] == "EdDSA"
    # Phase 18: kid is versioned ("{tenant_id}#v{N}"); v1 on first issuance.
    assert header["kid"] == "alpha#v1"


# ── 2. round-trip ──────────────────────────────────────────────────────────────


def test_eddsa_token_validates_and_yields_sub():
    svc = AuthService(_eddsa_cfg())
    token = svc.issue_token("alpha", _ADMIN_SECRET)
    claims = svc.validate_token(token)
    assert claims["sub"] == "alpha"


# ── 3. per-tenant isolation ────────────────────────────────────────────────────


def test_each_tenant_gets_a_distinct_keypair():
    ks = TenantKeyStore("")
    # Force key creation, then read both public keys.
    ks.private_pem("alpha")
    ks.private_pem("beta")
    assert ks.public_pem("alpha") != ks.public_pem("beta")


# ── 4. cross-tenant forgery rejection (the core security property) ──────────────


def test_token_signed_by_one_tenant_cannot_be_validated_as_another():
    svc = AuthService(_eddsa_cfg())
    # Issue legitimately for alpha and beta so both keys exist.
    svc.issue_token("beta", _ADMIN_SECRET)
    ks = svc.keystore
    assert ks is not None

    # Craft a token signed with ALPHA's private key but claiming sub=beta, kid=beta.
    alpha_priv = ks.private_pem("alpha")
    forged = _jwt.encode(
        {"sub": "beta", "iat": 0, "exp": 9_999_999_999, "jti": "forged"},
        alpha_priv,
        algorithm="EdDSA",
        headers={"kid": "beta"},  # claim to be beta so beta's pubkey is selected
    )
    # beta's real public key cannot verify a signature made with alpha's private key.
    with pytest.raises(InvalidToken):
        svc.validate_token(forged)


def test_sub_must_equal_kid():
    svc = AuthService(_eddsa_cfg())
    ks = svc.keystore
    assert ks is not None
    alpha_priv = ks.private_pem("alpha")
    # Signed correctly with alpha's key (kid=alpha) but sub claims beta.
    mismatched = _jwt.encode(
        {"sub": "beta", "iat": 0, "exp": 9_999_999_999, "jti": "x"},
        alpha_priv,
        algorithm="EdDSA",
        headers={"kid": "alpha"},
    )
    with pytest.raises(InvalidToken):
        svc.validate_token(mismatched)


# ── 5. unknown tenant fails closed ─────────────────────────────────────────────


def test_unknown_tenant_key_rejected():
    svc = AuthService(_eddsa_cfg())
    # Hand-craft a token with a kid for which no key was ever generated.
    bogus = _jwt.encode(
        {"sub": "ghost", "iat": 0, "exp": 9_999_999_999, "jti": "x"},
        TenantKeyStore("").private_pem("ghost"),
        algorithm="EdDSA",
        headers={"kid": "ghost"},
    )
    with pytest.raises(UnknownTenantKey):
        svc.validate_token(bogus)


# ── 6. expiry ──────────────────────────────────────────────────────────────────


def test_expired_eddsa_token_rejected():
    svc = AuthService(_eddsa_cfg(ttl=-1))
    token = svc.issue_token("alpha", _ADMIN_SECRET)
    with pytest.raises(InvalidToken):
        svc.validate_token(token)


# ── 7. revocation ──────────────────────────────────────────────────────────────


def test_revoked_eddsa_token_rejected():
    svc = AuthService(_eddsa_cfg())
    token = svc.issue_token("alpha", _ADMIN_SECRET)
    svc.revoke_token(token)
    with pytest.raises(RevokedToken):
        svc.validate_token(token)


# ── 8. algorithm confusion ─────────────────────────────────────────────────────


def test_hs256_token_rejected_by_eddsa_service():
    hs = AuthService(_hs256_cfg())
    hs_token = hs.issue_token("alpha", _ADMIN_SECRET)
    eddsa = AuthService(_eddsa_cfg())
    # The HS256 token has no kid header → rejected before any signature check.
    with pytest.raises(InvalidToken):
        eddsa.validate_token(hs_token)


# ── 9 & 10. keystore persistence vs. ephemerality ──────────────────────────────


def test_persisted_keys_survive_a_restart(tmp_path):
    cfg = _eddsa_cfg(keystore_dir=str(tmp_path))
    svc1 = AuthService(cfg)
    token = svc1.issue_token("alpha", _ADMIN_SECRET)
    # Brand-new service over the same keystore dir = simulated restart.
    svc2 = AuthService(_eddsa_cfg(keystore_dir=str(tmp_path)))
    claims = svc2.validate_token(token)
    assert claims["sub"] == "alpha"


def test_ephemeral_keystore_invalidates_old_tokens_on_restart():
    svc1 = AuthService(_eddsa_cfg(keystore_dir=""))
    token = svc1.issue_token("alpha", _ADMIN_SECRET)
    # New in-memory keystore. Issue a fresh alpha token on svc2 first, so svc2 now
    # holds its OWN regenerated alpha key. The old token (signed by svc1's alpha key)
    # must then fail signature verification against svc2's different alpha key.
    svc2 = AuthService(_eddsa_cfg(keystore_dir=""))
    svc2.issue_token("alpha", _ADMIN_SECRET)  # regenerate a distinct alpha key
    with pytest.raises(InvalidToken):
        svc2.validate_token(token)


# ── 11. JWKS export ────────────────────────────────────────────────────────────


def test_jwks_exports_public_okp_keys():
    svc = AuthService(_eddsa_cfg())
    svc.issue_token("alpha", _ADMIN_SECRET)
    svc.issue_token("beta", _ADMIN_SECRET)
    jwks = svc.jwks()
    kids = {k["kid"] for k in jwks["keys"]}
    # Phase 18: kids are versioned ("{tenant_id}#v{N}"); v1 on first issuance.
    assert kids == {"alpha#v1", "beta#v1"}
    for k in jwks["keys"]:
        assert k["kty"] == "OKP"
        assert k["crv"] == "Ed25519"
        assert k["alg"] == "EdDSA"
        assert "x" in k and k["x"]  # public coordinate present
        assert "d" not in k  # NEVER export the private scalar


def test_hs256_jwks_is_empty():
    svc = AuthService(_hs256_cfg())
    assert svc.jwks() == {"keys": []}


# ── 12-15. HTTP control plane (auth enabled, EdDSA) ────────────────────────────


def test_http_eddsa_token_accepted_on_protected_route():
    svc = AuthService(_eddsa_cfg(enabled=True))
    client, _ = _make_client(svc)
    token = svc.issue_token("alpha", _ADMIN_SECRET)
    r = client.post(
        "/runs",
        headers=_auth_header(token),
        json={"intent": "eddsa run", "submitted_by": "human:test", "budget_minor": 50000},
    )
    assert r.status_code == 200, r.text


def test_http_cross_tenant_token_cannot_read_other_tenant_run():
    svc = AuthService(_eddsa_cfg(enabled=True))
    client, _ = _make_client(svc)
    beta_token = svc.issue_token("beta", _ADMIN_SECRET)
    # Create a run as beta.
    r = client.post(
        "/runs",
        headers=_auth_header(beta_token),
        json={"intent": "beta run", "submitted_by": "human:test", "budget_minor": 50000},
    )
    assert r.status_code == 200, r.text
    run_id = r.json()["run_id"]
    # alpha's token must not see beta's run.
    alpha_token = svc.issue_token("alpha", _ADMIN_SECRET)
    r2 = client.get(f"/runs/{run_id}", headers=_auth_header(alpha_token))
    assert r2.status_code == 404, r2.text


def test_http_jwks_endpoint_is_public_and_lists_tenant_key():
    svc = AuthService(_eddsa_cfg(enabled=True))
    client, _ = _make_client(svc)
    svc.issue_token("alpha", _ADMIN_SECRET)
    r = client.get("/auth/jwks")  # no Authorization header
    assert r.status_code == 200, r.text
    kids = {k["kid"] for k in r.json()["keys"]}
    # Phase 18: kid is versioned; v1 on first issuance.
    assert "alpha#v1" in kids


def test_http_forged_token_returns_401():
    svc = AuthService(_eddsa_cfg(enabled=True))
    client, _ = _make_client(svc)
    bogus = _jwt.encode(
        {"sub": "ghost", "iat": 0, "exp": 9_999_999_999, "jti": "x"},
        TenantKeyStore("").private_pem("ghost"),
        algorithm="EdDSA",
        headers={"kid": "ghost"},
    )
    r = client.get("/runs", headers=_auth_header(bogus))
    assert r.status_code == 401, r.text
    assert "WWW-Authenticate" in r.headers


# ── 16-17. backward-compatibility ──────────────────────────────────────────────


def test_default_algorithm_is_hs256():
    cfg = AuthConfig()
    assert cfg.algorithm == "HS256"
    svc = AuthService(cfg)
    assert svc.algorithm == "HS256"
    assert svc.keystore is None


def test_unsupported_algorithm_rejected():
    with pytest.raises(ValueError):
        AuthService(
            AuthConfig(enabled=True, algorithm="RS256", admin_secret=_ADMIN_SECRET)
        )
