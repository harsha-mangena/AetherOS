"""Phase 12 integration tests — JWT authentication layer.

Atom of thoughts (each test validates exactly one independently verifiable property):

Unit-layer (AuthService directly):
  1.  issue_token returns a compact JWT string
  2.  issued token decodes with correct sub, iat, exp, jti fields
  3.  validate_token accepts a freshly issued token
  4.  validate_token returns claims dict with sub == tenant_id
  5.  wrong admin_secret raises AdminSecretMismatch
  6.  expired token raises InvalidToken
  7.  tampered payload raises InvalidToken (wrong signature)
  8.  revoke_token marks jti revoked, subsequent validate raises RevokedToken
  9.  revoke already-expired token still extracts jti without re-raising expiry
  10. two tokens for same tenant have distinct jti values
  11. validate rejects a token signed with a different secret

HTTP-layer (disabled auth — backward-compat):
  12. POST /auth/token works even when auth.enabled = False
  13. protected routes accept requests with no Authorization header when disabled
  14. X-Tenant-Id header is trusted when auth is disabled
  15. wrong admin_secret at POST /auth/token returns 401 regardless of enabled flag

HTTP-layer (enabled auth):
  16. missing Authorization header returns 401 with WWW-Authenticate
  17. malformed Bearer token returns 401
  18. valid token grants access and tenant_id is derived from token sub, not header
  19. token for tenant A cannot access tenant B's run (tenant derivation isolation)
  20. expired token returns 401
  21. revoked token returns 401
  22. POST /health is unprotected even when auth is enabled
  23. POST /auth/token is unprotected (issues token without requiring one)
  24. issued token carries correct expires_in in the response envelope
  25. POST /auth/revoke revokes a valid token and subsequent use returns 401
  26. POST /auth/revoke with a garbage string returns 400
  27. full round-trip: issue token → hit protected run endpoint → cancel run → revoke token → 401
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from fastapi.testclient import TestClient

from aetheros_orchestrator.api import create_app
from aetheros_orchestrator.auth import (
    AdminSecretMismatch,
    AuthConfig,
    AuthService,
    InvalidToken,
    RevokedToken,
)
from aetheros_orchestrator.run_service import RunService

# ── helpers ──────────────────────────────────────────────────────────────────

_ADMIN_SECRET = "test-admin-secret"
_SIGNING_SECRET = "test-signing-secret-must-be-32-chars-long!!"
_TTL = 3600


def _auth_cfg(enabled: bool = True, ttl: int = _TTL) -> AuthConfig:
    return AuthConfig(
        enabled=enabled,
        secret=_SIGNING_SECRET,
        admin_secret=_ADMIN_SECRET,
        token_ttl_seconds=ttl,
    )


def _make_client(
    enabled: bool = False,
    ttl: int = _TTL,
) -> tuple[TestClient, RunService, AuthService]:
    """Create a TestClient with two tenants ('alpha', 'beta') pre-created."""
    svc = RunService()
    svc.tenants.create("Tenant Alpha", tenant_id="alpha")
    svc.tenants.create("Tenant Beta", tenant_id="beta")
    auth_svc = AuthService(_auth_cfg(enabled=enabled, ttl=ttl))
    app = create_app(svc, auth_service=auth_svc)
    client = TestClient(app, raise_server_exceptions=False)
    return client, svc, auth_svc


def _token(auth_svc: AuthService, tenant_id: str = "alpha") -> str:
    return auth_svc.issue_token(tenant_id, _ADMIN_SECRET)


def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _create_run(
    client: TestClient,
    tenant_id: str = "alpha",
    token: str | None = None,
) -> dict[str, Any]:
    headers = {"x-tenant-id": tenant_id}
    if token:
        headers = _auth_header(token)
    r = client.post(
        "/runs",
        headers=headers,
        json={"intent": "auth test run", "submitted_by": "human:test", "budget_minor": 50000},
    )
    assert r.status_code == 200, r.text
    return r.json()


# ── Unit: AuthService ─────────────────────────────────────────────────────────

def test_issue_token_returns_string():
    auth_svc = AuthService(_auth_cfg())
    token = auth_svc.issue_token("alpha", _ADMIN_SECRET)
    assert isinstance(token, str)
    # compact JWT: three base64url segments separated by dots
    assert token.count(".") == 2


def test_issued_token_claims_are_correct():
    import jwt as _jwt
    auth_svc = AuthService(_auth_cfg())
    before = int(datetime.now(timezone.utc).timestamp())
    token = auth_svc.issue_token("alpha", _ADMIN_SECRET)
    claims = _jwt.decode(token, _SIGNING_SECRET, algorithms=["HS256"])
    assert claims["sub"] == "alpha"
    assert claims["iat"] >= before
    assert claims["exp"] == claims["iat"] + _TTL
    assert len(claims["jti"]) == 32  # uuid4().hex


def test_validate_token_accepts_fresh_token():
    auth_svc = AuthService(_auth_cfg())
    token = auth_svc.issue_token("alpha", _ADMIN_SECRET)
    claims = auth_svc.validate_token(token)
    assert claims["sub"] == "alpha"


def test_validate_token_returns_claims_with_correct_sub():
    auth_svc = AuthService(_auth_cfg())
    token = auth_svc.issue_token("beta", _ADMIN_SECRET)
    claims = auth_svc.validate_token(token)
    assert claims["sub"] == "beta"


def test_wrong_admin_secret_raises_admin_secret_mismatch():
    auth_svc = AuthService(_auth_cfg())
    with pytest.raises(AdminSecretMismatch):
        auth_svc.issue_token("alpha", "wrong-secret")


def test_expired_token_raises_invalid_token():
    # Issue with TTL=-1 so it is already expired at issuance time.
    auth_svc = AuthService(_auth_cfg(ttl=-1))
    token = auth_svc.issue_token("alpha", _ADMIN_SECRET)
    with pytest.raises(InvalidToken, match="expired"):
        auth_svc.validate_token(token)


def test_tampered_payload_raises_invalid_token():
    """Flip one character in the payload segment → signature mismatch."""
    auth_svc = AuthService(_auth_cfg())
    token = auth_svc.issue_token("alpha", _ADMIN_SECRET)
    header, payload, sig = token.split(".")
    # Flip last char of payload
    mangled_payload = payload[:-1] + ("A" if payload[-1] != "A" else "B")
    bad_token = f"{header}.{mangled_payload}.{sig}"
    with pytest.raises(InvalidToken):
        auth_svc.validate_token(bad_token)


def test_revoke_token_causes_subsequent_validate_to_raise():
    auth_svc = AuthService(_auth_cfg())
    token = auth_svc.issue_token("alpha", _ADMIN_SECRET)
    auth_svc.revoke_token(token)
    with pytest.raises(RevokedToken):
        auth_svc.validate_token(token)


def test_revoke_expired_token_extracts_jti_without_raising_expiry():
    """revoke_token skips expiry check — should not raise even on expired tokens."""
    auth_svc = AuthService(_auth_cfg(ttl=-1))
    token = auth_svc.issue_token("alpha", _ADMIN_SECRET)
    jti = auth_svc.revoke_token(token)
    assert isinstance(jti, str) and len(jti) == 32


def test_two_tokens_for_same_tenant_have_distinct_jtis():
    auth_svc = AuthService(_auth_cfg())
    t1 = auth_svc.issue_token("alpha", _ADMIN_SECRET)
    t2 = auth_svc.issue_token("alpha", _ADMIN_SECRET)
    import jwt as _jwt
    c1 = _jwt.decode(t1, _SIGNING_SECRET, algorithms=["HS256"])
    c2 = _jwt.decode(t2, _SIGNING_SECRET, algorithms=["HS256"])
    assert c1["jti"] != c2["jti"]


def test_token_signed_with_different_secret_is_rejected():
    auth_svc_a = AuthService(AuthConfig(
        enabled=True,
        secret=_SIGNING_SECRET,
        admin_secret=_ADMIN_SECRET,
        token_ttl_seconds=_TTL,
    ))
    auth_svc_b = AuthService(AuthConfig(
        enabled=True,
        secret="completely-different-secret-32chars!!!!!",
        admin_secret=_ADMIN_SECRET,
        token_ttl_seconds=_TTL,
    ))
    token_from_b = auth_svc_b.issue_token("alpha", _ADMIN_SECRET)
    with pytest.raises(InvalidToken):
        auth_svc_a.validate_token(token_from_b)


# ── HTTP: disabled auth (backward-compat) ────────────────────────────────────

def test_post_auth_token_works_when_auth_disabled():
    client, _, _ = _make_client(enabled=False)
    r = client.post("/auth/token", json={"tenant_id": "alpha", "admin_secret": _ADMIN_SECRET})
    assert r.status_code == 200
    data = r.json()
    assert "token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == _TTL


def test_protected_routes_work_without_auth_header_when_disabled():
    client, _, _ = _make_client(enabled=False)
    r = client.get("/runs", headers={"x-tenant-id": "alpha"})
    assert r.status_code == 200


def test_x_tenant_id_header_is_trusted_when_auth_disabled():
    client, _, _ = _make_client(enabled=False)
    run = _create_run(client, "alpha")
    r = client.get(f"/runs/{run['run_id']}", headers={"x-tenant-id": "alpha"})
    assert r.status_code == 200
    assert r.json()["tenant_id"] == "alpha"


def test_wrong_admin_secret_at_token_endpoint_returns_401():
    client, _, _ = _make_client(enabled=False)
    r = client.post("/auth/token", json={"tenant_id": "alpha", "admin_secret": "bad"})
    assert r.status_code == 401


# ── HTTP: enabled auth ────────────────────────────────────────────────────────

def test_missing_auth_header_returns_401_when_enabled():
    client, _, _ = _make_client(enabled=True)
    r = client.get("/runs", headers={"x-tenant-id": "alpha"})
    assert r.status_code == 401
    assert "WWW-Authenticate" in r.headers


def test_malformed_bearer_token_returns_401():
    client, _, _ = _make_client(enabled=True)
    r = client.get("/runs", headers={"Authorization": "Bearer not.a.jwt"})
    assert r.status_code == 401


def test_valid_token_grants_access_and_derives_tenant_from_sub():
    client, _, auth_svc = _make_client(enabled=True)
    token = _token(auth_svc, "alpha")
    # Even if we send a forged x-tenant-id header, the resolved tenant must come from token.
    r = client.get(
        "/runs",
        headers={**_auth_header(token), "x-tenant-id": "beta"},  # forged header
    )
    assert r.status_code == 200
    assert r.json()["tenant_id"] == "alpha"  # derived from token, not header


def test_token_for_tenant_a_cannot_access_tenant_b_run():
    client, _, auth_svc = _make_client(enabled=True)
    # Create a run under alpha using alpha's token.
    alpha_token = _token(auth_svc, "alpha")
    run = _create_run(client, token=alpha_token)
    run_id = run["run_id"]
    # Access with beta's token — must 404 (cross-tenant boundary).
    beta_token = _token(auth_svc, "beta")
    r = client.get(f"/runs/{run_id}", headers=_auth_header(beta_token))
    assert r.status_code == 404


def test_expired_token_returns_401_when_enabled():
    client, _, auth_svc = _make_client(enabled=True, ttl=-1)
    token = auth_svc.issue_token("alpha", _ADMIN_SECRET)
    r = client.get("/runs", headers=_auth_header(token))
    assert r.status_code == 401


def test_revoked_token_returns_401_when_enabled():
    client, _, auth_svc = _make_client(enabled=True)
    token = _token(auth_svc, "alpha")
    auth_svc.revoke_token(token)
    r = client.get("/runs", headers=_auth_header(token))
    assert r.status_code == 401


def test_health_endpoint_is_unprotected_when_auth_enabled():
    client, _, _ = _make_client(enabled=True)
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_auth_token_endpoint_is_unprotected():
    """POST /auth/token must itself be unprotected — it is the bootstrap endpoint."""
    client, _, _ = _make_client(enabled=True)
    r = client.post("/auth/token", json={"tenant_id": "alpha", "admin_secret": _ADMIN_SECRET})
    assert r.status_code == 200


def test_token_response_carries_correct_expires_in():
    client, _, _ = _make_client(enabled=True, ttl=7200)
    r = client.post("/auth/token", json={"tenant_id": "alpha", "admin_secret": _ADMIN_SECRET})
    assert r.status_code == 200
    assert r.json()["expires_in"] == 7200


def test_post_auth_revoke_invalidates_token():
    client, _, auth_svc = _make_client(enabled=True)
    token = _token(auth_svc, "alpha")
    # Token works before revocation.
    assert client.get("/runs", headers=_auth_header(token)).status_code == 200
    # Revoke via HTTP endpoint.
    rv = client.post("/auth/revoke", json={"token": token})
    assert rv.status_code == 200
    assert "revoked_jti" in rv.json()
    # Now the same token is rejected.
    assert client.get("/runs", headers=_auth_header(token)).status_code == 401


def test_post_auth_revoke_with_garbage_returns_400():
    client, _, _ = _make_client(enabled=True)
    r = client.post("/auth/revoke", json={"token": "garbage.garbage.garbage"})
    assert r.status_code == 400


def test_full_round_trip_issue_use_cancel_revoke():
    """Full flow: issue token → create run → cancel run → revoke token → 401."""
    client, _, auth_svc = _make_client(enabled=True)
    token = _token(auth_svc, "alpha")

    # Create run.
    run = _create_run(client, token=token)
    run_id = run["run_id"]
    assert run["status"] == "planned"

    # Cancel run.
    r_cancel = client.post(f"/runs/{run_id}/cancel", headers=_auth_header(token))
    assert r_cancel.status_code == 200
    assert r_cancel.json()["status"] == "halted"

    # Revoke token.
    auth_svc.revoke_token(token)

    # Any further request with same token is now rejected.
    r_after = client.get("/runs", headers=_auth_header(token))
    assert r_after.status_code == 401
