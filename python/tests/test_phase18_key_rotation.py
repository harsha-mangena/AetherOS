"""Phase 18: Ed25519 key rotation — unit and integration tests.

Design (atom of thoughts)
──────────────────────────
The smallest independently verifiable properties of the key rotation system:

1. After rotate(), there is exactly one ACTIVE key and at least one RETIRING key.
2. Tokens signed with the RETIRING key are still verifiable during the overlap window.
3. Tokens signed with the new ACTIVE key are verifiable immediately.
4. public_pem(retiring_kid) returns a non-None PEM during the overlap window.
5. public_pem(retiring_kid) returns None after the overlap window closes (key EXPIRED).
6. The JWKS endpoint publishes both ACTIVE and RETIRING keys during the overlap window.
7. The JWKS endpoint omits EXPIRED keys.
8. retire_all() immediately expires all RETIRING keys; ACTIVE key is unaffected.
9. prune() advances RETIRING → EXPIRED based on the injectable clock.
10. key_info() returns the correct state for each version.
11. Versioned kid format is "tenant#v{N}" and increments by 1 on each rotation.
12. Phase 14 unversioned kids (kid = tenant_id) are resolved to v1 transparently.
13. Cross-tenant isolation: rotating tenant A does not affect tenant B.
14. Disk persistence: rotating a durable keystore survives reconstruction from disk.
15. sub == tenant_id (not versioned kid) after rotation — the claim binding is preserved.
16. The API endpoint POST /auth/keys/{tenant_id}/rotate returns the correct payload.
17. The API endpoint GET /auth/keys/{tenant_id} returns key registry state.
18. The API endpoint DELETE /auth/keys/{tenant_id}/retire returns count of expired keys.
19. All three API endpoints return HTTP 403 when key_rotation.enabled = False.
20. Multiple rotations accumulate the correct version chain.

All time-dependent tests use injectable ``now`` parameters — no real time.sleep().
"""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

import pytest

from aetheros_orchestrator.token_keystore import KeyState, TenantKeyStore
from aetheros_orchestrator.auth import AuthService, AuthConfig, InvalidToken, UnknownTenantKey
from aetheros_orchestrator.config import AuthConfig as PydanticAuthConfig


# ── helpers ───────────────────────────────────────────────────────────────────

def make_ks(tmp_path=None, passphrase="", overlap=3600) -> TenantKeyStore:
    """Create a TenantKeyStore, optionally with durable disk storage."""
    return TenantKeyStore(
        db_dir=tmp_path or "",
        passphrase=passphrase,
        default_overlap_ttl_seconds=overlap,
    )


def make_edsa_auth(tmp_path=None, passphrase="") -> AuthService:
    """Create an EdDSA AuthService pointing at a fresh TenantKeyStore."""
    cfg = PydanticAuthConfig(
        enabled=True,
        algorithm="EdDSA",
        admin_secret="test-secret",
        token_keystore_dir=str(tmp_path) if tmp_path else "",
        token_ttl_seconds=3600,
        keystore_passphrase=passphrase,
    )
    return AuthService(cfg)


# ═════════════════════════════════════════════════════════════════════════════
# 1 — TenantKeyStore unit tests
# ═════════════════════════════════════════════════════════════════════════════

class TestKeyRotationStateTransitions:
    def test_initial_key_is_active_v1(self):
        """First private_pem() creates an ACTIVE v1 key."""
        ks = make_ks()
        ks.private_pem("alpha")
        info = ks.key_info("alpha")
        assert len(info["keys"]) == 1
        k = info["keys"][0]
        assert k["kid"] == "alpha#v1"
        assert k["version"] == 1
        assert k["state"] == KeyState.ACTIVE.value
        assert k["rotated_at"] is None

    def test_rotate_increments_version(self):
        """rotate() creates v2 as ACTIVE; v1 becomes RETIRING."""
        ks = make_ks()
        ks.private_pem("alpha")
        new_kid = ks.rotate("alpha")
        assert new_kid == "alpha#v2"
        info = ks.key_info("alpha")
        states = {k["kid"]: k["state"] for k in info["keys"]}
        assert states["alpha#v1"] == KeyState.RETIRING.value
        assert states["alpha#v2"] == KeyState.ACTIVE.value

    def test_multiple_rotations_accumulate_versions(self):
        """Three rotations give v1=RETIRING, v2=RETIRING, v3=ACTIVE."""
        ks = make_ks(overlap=9999)  # large overlap so nothing prunes yet
        ks.private_pem("beta")
        ks.rotate("beta")   # → v2
        ks.rotate("beta")   # → v3
        info = ks.key_info("beta")
        assert len(info["keys"]) == 3
        states = {k["kid"]: k["state"] for k in info["keys"]}
        assert states["beta#v1"] == KeyState.RETIRING.value
        assert states["beta#v2"] == KeyState.RETIRING.value
        assert states["beta#v3"] == KeyState.ACTIVE.value

    def test_rotate_returns_correct_kids(self):
        ks = make_ks()
        ks.private_pem("gamma")
        old_kid = ks.active_kid("gamma")
        assert old_kid == "gamma#v1"
        new_kid = ks.rotate("gamma")
        assert new_kid == "gamma#v2"
        assert ks.active_kid("gamma") == "gamma#v2"

    def test_exactly_one_active_key_per_tenant(self):
        ks = make_ks(overlap=9999)
        ks.private_pem("delta")
        for _ in range(5):
            ks.rotate("delta")
        info = ks.key_info("delta")
        active_keys = [k for k in info["keys"] if k["state"] == KeyState.ACTIVE.value]
        assert len(active_keys) == 1


class TestPublicPemResolution:
    def test_public_pem_versioned_kid_active(self):
        """public_pem(versioned_kid) works for ACTIVE key."""
        ks = make_ks()
        ks.private_pem("alpha")
        pem = ks.public_pem("alpha#v1")
        assert pem is not None
        assert "PUBLIC KEY" in pem

    def test_public_pem_versioned_kid_retiring(self):
        """public_pem(retiring_kid) returns non-None during overlap window."""
        ks = make_ks(overlap=3600)
        ks.private_pem("alpha")
        ks.rotate("alpha")
        pem = ks.public_pem("alpha#v1")  # still retiring
        assert pem is not None

    def test_public_pem_unversioned_kid_backward_compat(self):
        """public_pem(tenant_id) resolves to v1 for Phase 14 backward compat."""
        ks = make_ks()
        ks.private_pem("alpha")
        # unversioned (Phase 14 style) should resolve to alpha#v1
        pem = ks.public_pem("alpha")
        assert pem is not None
        # must equal the explicit versioned form
        pem_v1 = ks.public_pem("alpha#v1")
        assert pem == pem_v1

    def test_public_pem_unknown_kid_returns_none(self):
        """public_pem for an unknown kid returns None (fail closed)."""
        ks = make_ks()
        ks.private_pem("alpha")
        assert ks.public_pem("nobody#v99") is None
        assert ks.public_pem("nobody") is None

    def test_public_pem_expired_kid_returns_none(self):
        """After retire_all, RETIRING keys return None from public_pem."""
        ks = make_ks()
        ks.private_pem("alpha")
        ks.rotate("alpha")
        ks.retire_all("alpha")
        # v1 is now EXPIRED
        assert ks.public_pem("alpha#v1") is None
        # v2 (ACTIVE) still works
        assert ks.public_pem("alpha#v2") is not None


class TestPruning:
    def test_prune_retires_after_overlap(self):
        """prune() moves RETIRING → EXPIRED after the overlap window closes."""
        ks = make_ks(overlap=60)
        t0 = 1_000_000.0
        ks.private_pem("alpha")
        ks.rotate("alpha", overlap_ttl_seconds=60, now=t0)
        # 30 s later — still within window
        pruned = ks.prune("alpha", now=t0 + 30, overlap_ttl_seconds=60)
        assert pruned == 0
        info = ks.key_info("alpha")
        states = {k["kid"]: k["state"] for k in info["keys"]}
        assert states["alpha#v1"] == KeyState.RETIRING.value

    def test_prune_expires_after_overlap(self):
        """prune() transitions RETIRING → EXPIRED once the overlap window closes."""
        ks = make_ks(overlap=60)
        t0 = 1_000_000.0
        ks.private_pem("alpha")
        ks.rotate("alpha", overlap_ttl_seconds=60, now=t0)
        # 61 s later — overlap closed
        pruned = ks.prune("alpha", now=t0 + 61, overlap_ttl_seconds=60)
        assert pruned == 1
        info = ks.key_info("alpha")
        states = {k["kid"]: k["state"] for k in info["keys"]}
        assert states["alpha#v1"] == KeyState.EXPIRED.value

    def test_prune_on_rotate_expires_old_retiring_keys(self):
        """rotate() itself prunes keys whose overlap has passed."""
        ks = make_ks(overlap=60)
        t0 = 1_000_000.0
        ks.private_pem("alpha")
        ks.rotate("alpha", overlap_ttl_seconds=60, now=t0)        # v1→RETIRING, v2→ACTIVE
        ks.rotate("alpha", overlap_ttl_seconds=60, now=t0 + 61)   # v1 should prune, v2→RETIRING, v3→ACTIVE
        info = ks.key_info("alpha")
        states = {k["kid"]: k["state"] for k in info["keys"]}
        assert states["alpha#v1"] == KeyState.EXPIRED.value
        assert states["alpha#v2"] == KeyState.RETIRING.value
        assert states["alpha#v3"] == KeyState.ACTIVE.value


class TestRetireAll:
    def test_retire_all_expires_retiring_keys(self):
        """retire_all() immediately moves RETIRING → EXPIRED."""
        ks = make_ks(overlap=9999)
        ks.private_pem("alpha")
        ks.rotate("alpha")
        count = ks.retire_all("alpha")
        assert count == 1
        info = ks.key_info("alpha")
        states = {k["kid"]: k["state"] for k in info["keys"]}
        assert states["alpha#v1"] == KeyState.EXPIRED.value
        assert states["alpha#v2"] == KeyState.ACTIVE.value

    def test_retire_all_does_not_touch_active(self):
        """retire_all() never touches the ACTIVE key."""
        ks = make_ks(overlap=9999)
        ks.private_pem("alpha")
        ks.rotate("alpha")
        ks.retire_all("alpha")
        assert ks.active_kid("alpha") == "alpha#v2"
        assert ks.public_pem("alpha#v2") is not None

    def test_retire_all_returns_zero_when_nothing_retiring(self):
        """retire_all() returns 0 when there are no RETIRING keys."""
        ks = make_ks()
        ks.private_pem("alpha")
        count = ks.retire_all("alpha")
        assert count == 0


class TestCrossTenantIsolation:
    def test_rotate_does_not_affect_other_tenants(self):
        """Rotating tenant A leaves tenant B's registry untouched."""
        ks = make_ks(overlap=9999)
        ks.private_pem("alpha")
        ks.private_pem("beta")
        ks.rotate("alpha")
        # beta should still have exactly one ACTIVE v1
        info_b = ks.key_info("beta")
        assert len(info_b["keys"]) == 1
        assert info_b["keys"][0]["state"] == KeyState.ACTIVE.value

    def test_different_tenants_get_distinct_keys(self):
        """Two tenants produce distinct key material."""
        ks = make_ks()
        pem_a = ks.public_pem("alpha#v1")
        # Trigger creation for both
        ks.private_pem("alpha")
        ks.private_pem("beta")
        pem_a = ks.public_pem("alpha#v1")
        pem_b = ks.public_pem("beta#v1")
        assert pem_a != pem_b


class TestJWKSWithRotation:
    def test_jwks_includes_active_and_retiring(self):
        """JWKS publishes both ACTIVE (v2) and RETIRING (v1) keys during overlap."""
        ks = make_ks(overlap=9999)
        ks.private_pem("alpha")
        ks.rotate("alpha")
        jwks = ks.jwks()
        kids = {k["kid"] for k in jwks["keys"]}
        assert "alpha#v1" in kids  # RETIRING — still in JWKS
        assert "alpha#v2" in kids  # ACTIVE

    def test_jwks_excludes_expired_keys(self):
        """After retire_all, EXPIRED keys do not appear in JWKS."""
        ks = make_ks(overlap=9999)
        ks.private_pem("alpha")
        ks.rotate("alpha")
        ks.retire_all("alpha")
        jwks = ks.jwks()
        kids = {k["kid"] for k in jwks["keys"]}
        assert "alpha#v1" not in kids
        assert "alpha#v2" in kids

    def test_jwks_multi_rotation_shows_all_retiring(self):
        """JWKS shows all RETIRING keys across multiple rotations."""
        ks = make_ks(overlap=9999)
        ks.private_pem("alpha")
        ks.rotate("alpha")
        ks.rotate("alpha")
        jwks = ks.jwks()
        kids = {k["kid"] for k in jwks["keys"]}
        assert "alpha#v1" in kids
        assert "alpha#v2" in kids
        assert "alpha#v3" in kids


class TestDiskPersistence:
    def test_rotated_registry_survives_reconstruction(self, tmp_path):
        """A rotated keystore reconstructed from disk has the correct registry."""
        ks1 = make_ks(tmp_path=tmp_path, overlap=9999)
        ks1.private_pem("alpha")
        ks1.rotate("alpha")

        # Reconstruct from the same directory
        ks2 = make_ks(tmp_path=tmp_path, overlap=9999)
        info = ks2.key_info("alpha")
        states = {k["kid"]: k["state"] for k in info["keys"]}
        assert states["alpha#v1"] == KeyState.RETIRING.value
        assert states["alpha#v2"] == KeyState.ACTIVE.value

    def test_tokens_verifiable_after_reconstruction(self, tmp_path):
        """Tokens issued before restart remain verifiable after keystore reconstruction."""
        ks1 = make_ks(tmp_path=tmp_path, overlap=9999)
        ks1.private_pem("alpha")

        # Issue a token with the v1 key
        import jwt as _jwt
        priv_pem = ks1.private_pem("alpha")
        token = _jwt.encode(
            {"sub": "alpha", "iat": 1, "exp": 9_999_999_999, "jti": "test-jti"},
            priv_pem,
            algorithm="EdDSA",
            headers={"kid": ks1.active_kid("alpha")},
        )

        # Rotate to v2
        ks1.rotate("alpha", overlap_ttl_seconds=9999)

        # Reconstruct
        ks2 = make_ks(tmp_path=tmp_path, overlap=9999)
        # v1 key should still be retrievable (RETIRING)
        pub_pem = ks2.public_pem("alpha#v1")
        assert pub_pem is not None
        decoded = _jwt.decode(token, pub_pem, algorithms=["EdDSA"])
        assert decoded["sub"] == "alpha"


# ═════════════════════════════════════════════════════════════════════════════
# 2 — AuthService integration: tokens signed with versioned kid
# ═════════════════════════════════════════════════════════════════════════════

class TestAuthServiceWithRotation:
    def test_issued_token_carries_versioned_kid(self):
        """After first issuance, the token JOSE header contains kid=tenant#v1."""
        import jwt as _jwt
        svc = make_edsa_auth()
        token = svc.issue_token("alpha", "test-secret")
        header = _jwt.get_unverified_header(token)
        assert header["kid"] == "alpha#v1"

    def test_token_after_rotation_carries_new_kid(self):
        """After rotate(), newly issued tokens carry kid=tenant#v2."""
        import jwt as _jwt
        svc = make_edsa_auth()
        svc.issue_token("alpha", "test-secret")  # ensure v1 created
        ks = svc.keystore
        assert ks is not None
        ks.rotate("alpha")
        token2 = svc.issue_token("alpha", "test-secret")
        header = _jwt.get_unverified_header(token2)
        assert header["kid"] == "alpha#v2"

    def test_old_token_still_validates_during_overlap(self):
        """Tokens signed with the old (RETIRING) key validate during overlap window."""
        svc = make_edsa_auth()
        old_token = svc.issue_token("alpha", "test-secret")
        ks = svc.keystore
        assert ks is not None
        ks.rotate("alpha", overlap_ttl_seconds=9999)
        # old_token was signed with v1 (now RETIRING) — should still validate
        claims = svc.validate_token(old_token)
        assert claims["sub"] == "alpha"

    def test_new_token_validates_immediately_after_rotation(self):
        """Tokens signed with the new ACTIVE key validate immediately."""
        svc = make_edsa_auth()
        svc.issue_token("alpha", "test-secret")  # ensure v1 created
        ks = svc.keystore
        assert ks is not None
        ks.rotate("alpha", overlap_ttl_seconds=9999)
        new_token = svc.issue_token("alpha", "test-secret")
        claims = svc.validate_token(new_token)
        assert claims["sub"] == "alpha"

    def test_old_token_rejected_after_retire_all(self):
        """Tokens signed with a retired (EXPIRED) key raise UnknownTenantKey."""
        svc = make_edsa_auth()
        old_token = svc.issue_token("alpha", "test-secret")
        ks = svc.keystore
        assert ks is not None
        ks.rotate("alpha", overlap_ttl_seconds=9999)
        ks.retire_all("alpha")
        with pytest.raises((UnknownTenantKey, InvalidToken)):
            svc.validate_token(old_token)

    def test_sub_claim_is_tenant_id_not_versioned_kid(self):
        """The 'sub' claim is always the tenant_id, not the versioned kid."""
        import jwt as _jwt
        svc = make_edsa_auth()
        ks = svc.keystore
        assert ks is not None
        ks.private_pem("alpha")
        ks.rotate("alpha")
        token = svc.issue_token("alpha", "test-secret")  # signed with v2
        header = _jwt.get_unverified_header(token)
        assert header["kid"] == "alpha#v2"
        claims = svc.validate_token(token)
        assert claims["sub"] == "alpha"  # tenant_id, not "alpha#v2"


# ═════════════════════════════════════════════════════════════════════════════
# 3 — API endpoint integration tests
# ═════════════════════════════════════════════════════════════════════════════

def _make_eddsa_app(tmp_path=None):
    """Build a FastAPI test app with EdDSA auth and key_rotation enabled."""
    from fastapi.testclient import TestClient
    from aetheros_orchestrator.api import create_app
    from aetheros_orchestrator.config import KeyRotationConfig

    svc_auth = make_edsa_auth(tmp_path=tmp_path)
    app = create_app(auth_service=svc_auth)

    # Monkey-patch kr_cfg onto app state so the endpoint closure sees enabled=True.
    # (The create_app closure captures kr_cfg from load_config(); we override here.)
    # We do this by re-creating the app with a patched config loader.
    # Easier: patch the app state after construction since the endpoints are closures.
    # The cleanest approach for testing: use the config injection path.
    # For this test we will instead create the app properly via a config override.
    return None  # marker — see below


class TestKeyRotationAPIEndpoints:
    """Tests for Phase 18 HTTP endpoints via FastAPI TestClient."""

    @pytest.fixture
    def eddsa_app_enabled(self, tmp_path):
        """FastAPI test app with EdDSA auth and key_rotation.enabled = True."""
        import os
        from fastapi.testclient import TestClient
        from aetheros_orchestrator.api import create_app

        # Inject config via environment variables — the cleanest path without
        # modifying create_app's signature.
        os.environ["AETHER__AUTH__ALGORITHM"] = "EdDSA"
        os.environ["AETHER__AUTH__ENABLED"] = "false"  # no bearer auth on routes
        os.environ["AETHER__AUTH__ADMIN_SECRET"] = "test-secret"
        os.environ["AETHER__AUTH__TOKEN_KEYSTORE_DIR"] = str(tmp_path)
        os.environ["AETHER__KEY_ROTATION__ENABLED"] = "true"
        os.environ["AETHER__KEY_ROTATION__OVERLAP_TTL_SECONDS"] = "3600"

        app = create_app()
        client = TestClient(app)
        yield client

        # Cleanup env
        for k in [
            "AETHER__AUTH__ALGORITHM",
            "AETHER__AUTH__ENABLED",
            "AETHER__AUTH__ADMIN_SECRET",
            "AETHER__AUTH__TOKEN_KEYSTORE_DIR",
            "AETHER__KEY_ROTATION__ENABLED",
            "AETHER__KEY_ROTATION__OVERLAP_TTL_SECONDS",
        ]:
            os.environ.pop(k, None)

    @pytest.fixture
    def eddsa_app_disabled(self):
        """FastAPI test app with EdDSA auth and key_rotation.enabled = False (default)."""
        import os
        from fastapi.testclient import TestClient
        from aetheros_orchestrator.api import create_app

        os.environ["AETHER__AUTH__ALGORITHM"] = "EdDSA"
        os.environ["AETHER__AUTH__ENABLED"] = "false"
        os.environ["AETHER__AUTH__ADMIN_SECRET"] = "test-secret"
        # key_rotation.enabled is False by default

        app = create_app()
        client = TestClient(app)
        yield client

        for k in [
            "AETHER__AUTH__ALGORITHM",
            "AETHER__AUTH__ENABLED",
            "AETHER__AUTH__ADMIN_SECRET",
        ]:
            os.environ.pop(k, None)

    def test_rotate_key_returns_200(self, eddsa_app_enabled):
        """POST /auth/keys/{tenant}/rotate returns 200 with new_kid and retiring_kid."""
        client = eddsa_app_enabled
        # Ensure key exists first
        client.post("/auth/token", json={"tenant_id": "alpha", "admin_secret": "test-secret"})
        resp = client.post("/auth/keys/alpha/rotate", json={})
        assert resp.status_code == 200
        body = resp.json()
        assert body["new_kid"] == "alpha#v2"
        assert body["retiring_kid"] == "alpha#v1"
        assert body["overlap_ttl_seconds"] == 3600

    def test_rotate_key_disabled_returns_403(self, eddsa_app_disabled):
        """POST /auth/keys/{tenant}/rotate returns 403 when key_rotation.enabled=False."""
        client = eddsa_app_disabled
        resp = client.post("/auth/keys/alpha/rotate", json={})
        assert resp.status_code == 403

    def test_get_key_info_returns_200(self, eddsa_app_enabled):
        """GET /auth/keys/{tenant} returns the key registry state."""
        client = eddsa_app_enabled
        # Ensure v1 created
        client.post("/auth/token", json={"tenant_id": "alpha", "admin_secret": "test-secret"})
        resp = client.get("/auth/keys/alpha")
        assert resp.status_code == 200
        body = resp.json()
        assert body["tenant_id"] == "alpha"
        assert len(body["keys"]) >= 1
        assert body["active_kid"] == "alpha#v1"

    def test_get_key_info_after_rotation(self, eddsa_app_enabled):
        """GET /auth/keys/{tenant} after rotation shows ACTIVE and RETIRING."""
        client = eddsa_app_enabled
        client.post("/auth/token", json={"tenant_id": "alpha", "admin_secret": "test-secret"})
        client.post("/auth/keys/alpha/rotate", json={})
        resp = client.get("/auth/keys/alpha")
        assert resp.status_code == 200
        body = resp.json()
        states = {k["kid"]: k["state"] for k in body["keys"]}
        assert states.get("alpha#v1") == "RETIRING"
        assert states.get("alpha#v2") == "ACTIVE"

    def test_get_key_info_disabled_returns_403(self, eddsa_app_disabled):
        """GET /auth/keys/{tenant} returns 403 when key_rotation.enabled=False."""
        client = eddsa_app_disabled
        resp = client.get("/auth/keys/alpha")
        assert resp.status_code == 403

    def test_emergency_retire_returns_200(self, eddsa_app_enabled):
        """DELETE /auth/keys/{tenant}/retire returns count of expired keys."""
        client = eddsa_app_enabled
        # Create v1, rotate to v2
        client.post("/auth/token", json={"tenant_id": "alpha", "admin_secret": "test-secret"})
        client.post("/auth/keys/alpha/rotate", json={})
        resp = client.delete("/auth/keys/alpha/retire")
        assert resp.status_code == 200
        body = resp.json()
        assert body["tenant_id"] == "alpha"
        assert body["keys_expired"] == 1

    def test_emergency_retire_disabled_returns_403(self, eddsa_app_disabled):
        """DELETE /auth/keys/{tenant}/retire returns 403 when key_rotation disabled."""
        client = eddsa_app_disabled
        resp = client.delete("/auth/keys/alpha/retire")
        assert resp.status_code == 403

    def test_custom_overlap_ttl_in_rotate_request(self, eddsa_app_enabled):
        """POST /auth/keys/{tenant}/rotate with custom overlap_ttl_seconds."""
        client = eddsa_app_enabled
        client.post("/auth/token", json={"tenant_id": "alpha", "admin_secret": "test-secret"})
        resp = client.post("/auth/keys/alpha/rotate", json={"overlap_ttl_seconds": 7200})
        assert resp.status_code == 200
        assert resp.json()["overlap_ttl_seconds"] == 7200

    def test_jwks_includes_retiring_key_during_overlap(self, eddsa_app_enabled):
        """After rotation, JWKS includes both ACTIVE (v2) and RETIRING (v1) keys."""
        client = eddsa_app_enabled
        client.post("/auth/token", json={"tenant_id": "alpha", "admin_secret": "test-secret"})
        client.post("/auth/keys/alpha/rotate", json={})
        resp = client.get("/auth/jwks")
        assert resp.status_code == 200
        kids = {k["kid"] for k in resp.json()["keys"]}
        assert "alpha#v1" in kids
        assert "alpha#v2" in kids
