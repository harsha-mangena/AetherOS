"""API authentication layer (Phase 12).

Provides JWT Bearer-token issuance and validation for the AetherOS control-plane API.

Design (atom of thoughts):
  The smallest independently verifiable security properties:
  1. A token is issued only to a caller who supplies the correct admin_secret.
  2. A token carries sub = tenant_id, iat, exp, and a unique jti (token ID).
  3. Token validation rejects: bad signature, expired token, revoked jti, wrong algorithm.
  4. When auth.enabled = False the dependency returns the X-Tenant-Id header value
     unchanged — identical to all pre-Phase-12 behavior. No test modification required.
  5. When auth.enabled = True the dependency ignores X-Tenant-Id entirely; tenant_id
     is derived from the validated token claims. A forged or missing header is irrelevant.

Chain of thoughts:
  AuthConfig (config.py) → TokenStore (in-memory, thread-safe, revocation set) →
  issue_token (HS256 JWT, jti=uuid4) → validate_token (decode + revocation check) →
  FastAPI Depends(get_tenant_id) → api.py protected routes.

Research net / standards:
  RFC 7519 — JSON Web Token (JWT). Claims used: sub, iat, exp, jti.
  RFC 7518 — JWA. Algorithm: HS256 (HMAC with SHA-256).
  RFC 6750 — Bearer Token Usage. Authorization: Bearer <token>.
  OWASP: secrets >= 256 bits (32 bytes) for HMAC-SHA256.

  PyJWT 2.x API:
    jwt.encode(payload, secret, algorithm="HS256") -> str
    jwt.decode(token, secret, algorithms=["HS256"]) -> dict
    Raises jwt.ExpiredSignatureError, jwt.InvalidTokenError on failure.
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

try:
    import jwt as _jwt
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "PyJWT is required for the auth layer. Install with: pip install PyJWT"
    ) from exc

try:
    from fastapi import Depends, Header, HTTPException
    from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "FastAPI is required. Install with: pip install fastapi"
    ) from exc

from .config import AuthConfig

if TYPE_CHECKING:
    pass


class AuthError(Exception):
    """Base class for authentication errors."""


class InvalidToken(AuthError):
    """The token is missing, malformed, expired, or has an invalid signature."""


class RevokedToken(AuthError):
    """The token's jti has been explicitly revoked (e.g. via logout)."""


class AdminSecretMismatch(AuthError):
    """The admin_secret presented at the token endpoint is incorrect."""


# FastAPI's HTTPBearer returns 403 by default on missing credentials; we override
# auto_error=False so we can return our own 401 with a WWW-Authenticate header.
_bearer_scheme = HTTPBearer(auto_error=False)


class TokenStore:
    """Thread-safe in-memory store for revoked JWT IDs (jti).

    A revoked token is one that was explicitly invalidated before its natural
    expiry — for example after a tenant rotation or a detected compromise.
    Revocation is stored as a set of ``jti`` strings. Tokens that were never
    issued are silently accepted by this store (revocation is an opt-in deny,
    not an allow-list); the cryptographic signature check is the real gate.

    Limitation: the revocation set lives in memory and is lost on restart.
    Phase 13 can persist it to SQLite alongside the ledger store.
    """

    def __init__(self) -> None:
        self._revoked: set[str] = set()
        self._lock = threading.Lock()

    def revoke(self, jti: str) -> None:
        """Mark a token ID as revoked. Idempotent."""
        with self._lock:
            self._revoked.add(jti)

    def is_revoked(self, jti: str) -> bool:
        with self._lock:
            return jti in self._revoked


class AuthService:
    """Encapsulates token issuance and validation for the control-plane API.

    Constructed once from the server's ``AuthConfig`` and reused across requests.
    The ``TokenStore`` is owned by this service and survives across token operations
    within a single process lifetime.
    """

    def __init__(self, config: AuthConfig) -> None:
        self._config = config
        self._store = TokenStore()

    @property
    def enabled(self) -> bool:
        return self._config.enabled

    # ── token issuance ────────────────────────────────────────────────────────

    def issue_token(self, tenant_id: str, admin_secret: str) -> str:
        """Issue a signed JWT for ``tenant_id``.

        Raises ``AdminSecretMismatch`` if ``admin_secret`` does not equal the
        configured ``admin_secret``. In a constant-time comparison to avoid
        timing side-channels.

        Returns a compact JWT string (header.payload.signature).
        """
        import hmac as _hmac
        # Constant-time comparison prevents timing oracle attacks on the secret.
        provided = admin_secret.encode("utf-8")
        expected = self._config.admin_secret.encode("utf-8")
        if not _hmac.compare_digest(provided, expected):
            raise AdminSecretMismatch("invalid admin_secret")

        now = int(datetime.now(timezone.utc).timestamp())
        payload = {
            "sub": tenant_id,
            "iat": now,
            "exp": now + self._config.token_ttl_seconds,
            "jti": uuid.uuid4().hex,
        }
        token: str = _jwt.encode(
            payload,
            self._config.secret,
            algorithm="HS256",
        )
        return token

    # ── token validation ─────────────────────────────────────────────────────

    def validate_token(self, token: str) -> dict:
        """Validate a JWT and return its decoded claims.

        Raises:
          InvalidToken  — bad signature, expired, wrong algorithm, malformed.
          RevokedToken  — jti found in the revocation set.
        """
        try:
            claims: dict = _jwt.decode(
                token,
                self._config.secret,
                algorithms=["HS256"],
                options={"require": ["sub", "iat", "exp", "jti"]},
            )
        except _jwt.ExpiredSignatureError as exc:
            raise InvalidToken("token has expired") from exc
        except _jwt.InvalidTokenError as exc:
            raise InvalidToken(f"token invalid: {exc}") from exc

        jti = claims.get("jti", "")
        if self._store.is_revoked(jti):
            raise RevokedToken(f"token {jti} has been revoked")

        return claims

    def revoke_token(self, token: str) -> str:
        """Revoke a token by its jti, returning the revoked jti string.

        Does a lightweight decode without signature check (the token may be
        expired) to extract the jti, then adds it to the revocation set.
        """
        try:
            claims: dict = _jwt.decode(
                token,
                self._config.secret,
                algorithms=["HS256"],
                options={"verify_exp": False, "require": ["jti"]},
            )
        except _jwt.InvalidTokenError as exc:
            raise InvalidToken(f"cannot revoke malformed token: {exc}") from exc
        jti = claims["jti"]
        self._store.revoke(jti)
        return jti

    # ── FastAPI dependency ────────────────────────────────────────────────────

    def tenant_id_dependency(self):
        """Return a FastAPI ``Depends``-compatible callable.

        Two entirely separate callables are returned depending on the enabled flag.
        This is critical: when auth is disabled we must NOT include the HTTPBearer
        security scheme in the dependency graph at all, because FastAPI's OpenAPI
        validation will reject requests that lack an Authorization header even when
        auto_error=False is set on the scheme. The two-callable design ensures zero
        change in request validation semantics when auth is off.

        When auth is disabled (default): reads X-Tenant-Id header only — identical
        to all pre-Phase-12 behavior. No existing test needs modification.

        When auth is enabled: validates the Bearer JWT and derives tenant_id from
        the sub claim. HTTP 401 on missing, invalid, or revoked token. X-Tenant-Id
        is completely ignored once auth is on.
        """
        auth_service = self  # capture for closure

        if not auth_service.enabled:
            # Auth OFF path — plain header read, no bearer scheme in dependency graph.
            def _get_tenant_disabled(
                x_tenant_id: str = Header("default"),
            ) -> str:
                return x_tenant_id

            return _get_tenant_disabled

        # Auth ON path — bearer scheme + JWT validation.
        def _get_tenant_enabled(
            credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
        ) -> str:
            if credentials is None:
                raise HTTPException(
                    status_code=401,
                    detail="Bearer token required",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            try:
                claims = auth_service.validate_token(credentials.credentials)
            except RevokedToken as exc:
                raise HTTPException(
                    status_code=401,
                    detail=str(exc),
                    headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
                )
            except InvalidToken as exc:
                raise HTTPException(
                    status_code=401,
                    detail=str(exc),
                    headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
                )
            return claims["sub"]

        return _get_tenant_enabled
