"""Local HTTP API for the AetherOS desktop app (Phase 5 backend bridge).

A thin FastAPI surface over the resumable RunService. The Tauri/React frontend calls
these endpoints; the governed-execution moat (Rust policy engine + capability lease +
tamper-evident ledger) stays entirely UI-agnostic behind the service. The API is also
independently runnable and testable (uvicorn / httpx / curl) so the full stack can be
de-risked headlessly before any GUI exists.

Run locally:
    uvicorn aetheros_orchestrator.api:app --port 8765

Endpoints:
    GET  /health                          liveness
    GET  /config/policy                   the active policy rule set (admin)
    GET  /runs                            list runs
    POST /runs                            create a run from an intent -> plan
    GET  /runs/{run_id}                   run snapshot (plan + results + status)
    POST /runs/{run_id}/advance           execute until completion/halt/approval gate
    POST /runs/{run_id}/resume            apply a human approval decision, continue
    GET  /runs/{run_id}/evidence          verify + replay the tamper-evident ledger
    GET  /runs/{run_id}/transparency      signed tree head (+ ?leaf=N inclusion proof)
    GET  /runs/{run_id}/transparency/consistency  append-only proof (?first_size=M)
    GET  /runs/{run_id}/transparency/cosigned     STH + independent witness cosignatures
    POST /runs/{run_id}/cancel            cancel an in-progress run (records in ledger)
    DELETE /runs/{run_id}                 remove a terminal run from the registry
    POST /collaborations                  open (or retrieve) a tenant-scoped collaboration
    GET  /collaborations                  list all collaborations for the requesting tenant
    GET  /collaborations/{collaboration_id}  collaboration state + full shared ledger
    POST /collaborations/{collaboration_id}/admit      admit an agent with a capability lease
    POST /collaborations/{collaboration_id}/contribute  append an attributed entry to the chain
    GET  /marketplace/catalog             list all governed skills in the marketplace
    POST /marketplace/skills              publish a signed skill to the catalog
    POST /marketplace/skills/{skill_id}/install  install a skill under governance for a tenant
    GET  /marketplace/installed           list skills installed for the requesting tenant

Phase 22: Prometheus metrics bridge + admin introspection API:
    GET  /metrics                         Prometheus text-format scrape (OpenMetrics v1.0.0)
                                          Returns 404 when prometheus.enabled = False (default).
    GET  /admin/runs                      tenant run list with lightweight summary fields
    GET  /admin/tenants/{id}/budget       budget summary for a tenant (cross-tenant: 403)
    GET  /admin/policy/deny-rate          policy denial statistics for the tenant
    GET  /admin/summary                   service-level summary (all tenants, admin overview)

Rate limiting (Phase 17):
    When rate_limit.enabled = True in config, per-tenant, per-route sliding-window
    counters enforce configurable request limits. Breached limits return HTTP 429
    with Retry-After. When disabled (default), all prior behavior is unchanged.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

try:
    from fastapi import Depends, FastAPI, Header, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
except Exception as exc:  # pragma: no cover - import guard
    raise RuntimeError(
        "FastAPI is required for the API layer. Install with: pip install 'fastapi' 'uvicorn'"
    ) from exc

from .config import load_config, AuditConfig
from .run_service import RunService
from .health import make_health_router
from .metrics_exporter import make_metrics_router
from .admin import make_admin_router
from .tenancy import (
    DEFAULT_TENANT_ID,
    CrossTenantAccess,
    TenantError,
    UnknownTenant,
)
from .auth import AdminSecretMismatch, AuthService, InvalidToken, RevokedToken
from .rate_limiter import RateLimiter, RateLimitExceeded


# ── Phase 18 request models ───────────────────────────────────────────────────

class RotateKeyRequest(BaseModel):
    overlap_ttl_seconds: int | None = Field(
        None,
        description=(
            "Overlap window in seconds. During this window the old key stays verifiable "
            "so pre-rotation tokens remain valid. Defaults to key_rotation.overlap_ttl_seconds "
            "from config (typically equal to auth.token_ttl_seconds)."
        ),
    )


class CreateRunRequest(BaseModel):
    intent: str = Field(..., description="Natural-language intent / goal.")
    submitted_by: str = Field("human:operator")
    budget_minor: int = Field(100_000, ge=0)


class ResumeRequest(BaseModel):
    step_id: str
    approved: bool
    approver: str = Field("human:operator")


class CreateTenantRequest(BaseModel):
    display_name: str = Field(..., description="Human-readable workspace name.")
    tenant_id: str | None = Field(None, description="Optional explicit slug id.")
    max_budget_minor: int | None = Field(None, ge=0)
    max_autonomy_tier: int | None = Field(None, ge=0)


# ── Phase 11 request models ──────────────────────────────────────────────────

class OpenCollaborationRequest(BaseModel):
    collaboration_id: str = Field(..., description="Unique identifier for the shared ledger.")


class AdmitAgentRequest(BaseModel):
    agent_id: str = Field(..., description="The agent to admit.")
    lease: dict = Field(..., description="CapabilityLease JSON (as from lease.to_dict()).")


class ContributeRequest(BaseModel):
    agent_id: str = Field(..., description="The contributing agent id.")
    event_type: str = Field(..., description="Semantic event label (e.g. 'agent.analysis').")
    payload: dict = Field(default_factory=dict, description="Arbitrary structured payload.")


class PublishSkillRequest(BaseModel):
    manifest: dict = Field(
        ...,
        description=(
            "Skill manifest fields: skill_id, version, publisher_agent_id, "
            "publisher_public_key, required_scopes, declared_tools, description."
        ),
    )
    signature: str = Field(..., description="Ed25519 hex signature over canonical manifest bytes.")


class InstallSkillRequest(BaseModel):
    version: str = Field(..., description="Version of the skill to install.")
    permitted_scopes: list[str] = Field(
        default_factory=list,
        description="Scopes the tenant delegates to this skill (least-privilege gate).",
    )


class TokenRequest(BaseModel):
    tenant_id: str = Field(..., description="The tenant for which to issue a JWT.")
    admin_secret: str = Field(..., description="Server admin secret (from auth.admin_secret config).")


class RevokeRequest(BaseModel):
    token: str = Field(..., description="The JWT to revoke (by its jti).")


def create_app(
    service: RunService | None = None,
    auth_service: "AuthService | None" = None,
    audit_config: "AuditConfig | None" = None,
) -> "FastAPI":
    """Build the FastAPI app. A custom RunService and AuthService can be injected for tests."""
    app = FastAPI(title="AetherOS Control Plane API", version="0.9.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # local desktop app; tighten for any networked deployment
        allow_methods=["*"],
        allow_headers=["*"],
    )
    svc = service or RunService()
    app.state.service = svc

    # Build the AuthService from config if not injected (allows tests to inject a custom one).
    if auth_service is None:
        cfg = load_config()
        auth_svc = AuthService(cfg.auth)
        rl_cfg = cfg.rate_limit
        kr_cfg = cfg.key_rotation
        audit_cfg = audit_config if audit_config is not None else cfg.audit
    else:
        auth_svc = auth_service
        cfg = load_config()
        rl_cfg = cfg.rate_limit
        kr_cfg = cfg.key_rotation
        audit_cfg = audit_config if audit_config is not None else cfg.audit
    app.state.auth_service = auth_svc

    # Phase 21: health router (/health/live, /health/ready, /health/deep).
    # Must be added before route definitions that could shadow /health/*.
    app.include_router(make_health_router(cfg))

    # Phase 17: per-tenant, per-route sliding-window rate limiter.
    # When rate_limit.enabled = False (default) the limiter never raises, so all
    # prior tests pass unchanged with no modification.
    _rate_limiter = RateLimiter(
        window_seconds=rl_cfg.window_seconds,
        default_limit=rl_cfg.default_limit if rl_cfg.enabled else 0,
        route_limits=rl_cfg.route_limits if rl_cfg.enabled else {},
    )
    app.state.rate_limiter = _rate_limiter

    def _check_rate(tenant: str, route_key: str) -> None:
        """Raise HTTP 429 if the per-tenant, per-route rate limit is exceeded."""
        try:
            _rate_limiter.check_and_increment(tenant, route_key)
        except RateLimitExceeded as exc:
            raise HTTPException(
                status_code=429,
                detail=f"rate limit exceeded; retry after {exc.retry_after}s",
                headers={"Retry-After": str(exc.retry_after)},
            )

    # The tenant-resolution dependency. When auth is disabled this is identical to reading
    # the X-Tenant-Id header. When auth is enabled it validates the Bearer JWT and derives
    # tenant_id from the sub claim — the header is irrelevant and cannot be forged.
    get_tenant = auth_svc.tenant_id_dependency()

    # Phase 22: Prometheus metrics bridge and admin introspection API.
    # /metrics — Prometheus text-format scrape endpoint (OpenMetrics v1.0.0).
    # /admin/*  — read-only ops introspection (runs, budget, deny-rate, summary).
    app.include_router(make_metrics_router(cfg))
    app.include_router(make_admin_router(svc, get_tenant))

    # ── auth endpoints (Phase 12, always unprotected) ─────────────────────────

    @app.post("/auth/token")
    def issue_token(req: TokenRequest) -> dict[str, Any]:
        """Issue a signed JWT for a tenant.

        The caller must supply the correct ``admin_secret`` (from config). On success,
        returns ``{"token": "<jwt>", "token_type": "bearer", "expires_in": <seconds>}``.
        When auth is disabled this endpoint still works — useful for pre-provisioning
        tokens before flipping auth on.
        """
        _check_rate(req.tenant_id, "auth:token")
        try:
            token = auth_svc.issue_token(req.tenant_id, req.admin_secret)
        except AdminSecretMismatch:
            raise HTTPException(status_code=401, detail="invalid admin_secret")
        return {
            "token": token,
            "token_type": "bearer",
            "expires_in": auth_svc._config.token_ttl_seconds,  # noqa: SLF001 — same package
        }

    @app.post("/auth/revoke")
    def revoke_token(req: RevokeRequest) -> dict[str, Any]:
        """Revoke a JWT by its jti. The token will be rejected on all future requests."""
        # Extract tenant_id from the token (unverified, for rate-limiting only).
        # This keeps the endpoint unprotected (no auth required to revoke your own token).
        import jwt as _jwt_mod
        try:
            _claims = _jwt_mod.decode(
                req.token,
                options={"verify_signature": False, "verify_exp": False},
            )
            _revoke_tenant = _claims.get("sub", "unknown")
        except Exception:
            _revoke_tenant = "unknown"
        _check_rate(_revoke_tenant, "auth:revoke")
        try:
            jti = auth_svc.revoke_token(req.token)
        except (InvalidToken, RevokedToken) as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {"revoked_jti": jti}

    @app.get("/auth/jwks")
    def jwks() -> dict[str, Any]:
        """Publish per-tenant Ed25519 public keys as an RFC 7517 JWK Set.

        Verify-only material — never contains private keys. A downstream verifier
        selects the right key by matching a token's ``kid`` header to a JWK ``kid``.
        Under HS256 (the default) there are no asymmetric keys, so this returns an
        empty key set. Always unprotected: public keys are meant to be public.

        Phase 18: during a rotation overlap window, both ACTIVE and RETIRING keys
        appear in the JWKS so tokens issued before and after the rotation validate
        simultaneously.
        """
        return auth_svc.jwks()

    # ── key rotation endpoints (Phase 18) ─────────────────────────────────────

    @app.post("/auth/keys/{tenant_id}/rotate")
    def rotate_key(tenant_id: str, req: RotateKeyRequest) -> dict[str, Any]:
        """Rotate the Ed25519 signing key for a tenant (EdDSA only, Phase 18).

        Atomically generates a new Ed25519 keypair, moves the current ACTIVE key to
        RETIRING (verifiable but no longer signing), and stamps the new versioned kid
        on all subsequent tokens for this tenant.

        Returns the new ``kid``, the old (retiring) ``kid``, and the overlap window
        duration so the caller can audit the rotation event.

        HTTP 400 if auth.algorithm is not EdDSA (key rotation is meaningless for HS256).
        HTTP 403 if key_rotation.enabled = False in config.
        """
        if not kr_cfg.enabled:
            raise HTTPException(
                status_code=403,
                detail="key rotation is disabled; set key_rotation.enabled = true in config",
            )
        if auth_svc.algorithm != "EdDSA":
            raise HTTPException(
                status_code=400,
                detail="key rotation is only supported for EdDSA; auth.algorithm is HS256",
            )
        ks = auth_svc.keystore
        if ks is None:
            raise HTTPException(status_code=500, detail="keystore not initialised")
        overlap = req.overlap_ttl_seconds if req.overlap_ttl_seconds is not None else kr_cfg.overlap_ttl_seconds
        # Capture the old kid before rotation.
        old_kid = ks.active_kid(tenant_id)
        new_kid = ks.rotate(tenant_id, overlap_ttl_seconds=overlap)
        return {
            "tenant_id": tenant_id,
            "new_kid": new_kid,
            "retiring_kid": old_kid,
            "overlap_ttl_seconds": overlap,
        }

    @app.get("/auth/keys/{tenant_id}")
    def get_key_info(tenant_id: str) -> dict[str, Any]:
        """Return the key registry state for a tenant (EdDSA only, Phase 18).

        Lists all key versions (ACTIVE, RETIRING, EXPIRED) with their lifecycle
        timestamps. Suitable for ops inspection and rotation audit trails.

        HTTP 400 if auth.algorithm is not EdDSA.
        HTTP 403 if key_rotation.enabled = False in config.
        """
        if not kr_cfg.enabled:
            raise HTTPException(
                status_code=403,
                detail="key rotation is disabled; set key_rotation.enabled = true in config",
            )
        if auth_svc.algorithm != "EdDSA":
            raise HTTPException(
                status_code=400,
                detail="key info is only available for EdDSA",
            )
        ks = auth_svc.keystore
        if ks is None:
            raise HTTPException(status_code=500, detail="keystore not initialised")
        return ks.key_info(tenant_id)

    @app.delete("/auth/keys/{tenant_id}/retire")
    def emergency_retire_keys(tenant_id: str) -> dict[str, Any]:
        """Emergency: immediately expire all RETIRING keys for a tenant (Phase 18).

        This is a break-glass operation that invalidates all currently-retiring keys
        without waiting for the overlap window to expire. Tokens signed with the
        retired keys will be rejected immediately. The current ACTIVE key is unaffected.

        Use this when a key compromise is detected and immediate invalidation of all
        pre-rotation tokens is required.

        HTTP 400 if auth.algorithm is not EdDSA.
        HTTP 403 if key_rotation.enabled = False in config.
        """
        if not kr_cfg.enabled:
            raise HTTPException(
                status_code=403,
                detail="key rotation is disabled; set key_rotation.enabled = true in config",
            )
        if auth_svc.algorithm != "EdDSA":
            raise HTTPException(
                status_code=400,
                detail="emergency retire is only supported for EdDSA",
            )
        ks = auth_svc.keystore
        if ks is None:
            raise HTTPException(status_code=500, detail="keystore not initialised")
        count = ks.retire_all(tenant_id)
        return {
            "tenant_id": tenant_id,
            "keys_expired": count,
        }

    @app.get("/config/policy")
    def policy() -> dict[str, Any]:
        cfg = load_config()
        return {
            "default_allow": cfg.policy.default_allow,
            "require_approval_for_high_impact": cfg.policy.require_approval_for_high_impact,
            "autonomy": {
                "promotion_threshold": cfg.autonomy.promotion_threshold,
                "max_tier": cfg.autonomy.max_tier,
            },
            "rules": [
                {
                    "id": r.id,
                    "effect": r.effect,
                    "scope": r.scope,
                    "tool": r.tool,
                    "min_autonomy_tier": r.min_autonomy_tier,
                    "max_cost_minor": r.max_cost_minor,
                    "priority": r.priority,
                }
                for r in cfg.policy.rules
            ],
        }

    @app.get("/runs")
    def list_runs(tenant_id: str = Depends(get_tenant)) -> dict[str, Any]:
        try:
            svc.tenants.get(tenant_id)
        except UnknownTenant:
            raise HTTPException(status_code=404, detail="unknown tenant")
        return {"tenant_id": tenant_id, "runs": svc.list_runs(tenant_id)}

    @app.post("/runs")
    def create_run(
        req: CreateRunRequest, tenant_id: str = Depends(get_tenant)
    ) -> dict[str, Any]:
        _check_rate(tenant_id, "runs:create")
        try:
            run = svc.create_run(req.intent, req.submitted_by, req.budget_minor, tenant_id)
        except UnknownTenant:
            raise HTTPException(status_code=404, detail="unknown tenant")
        return run.to_view()

    @app.get("/runs/{run_id}")
    def get_run(run_id: str, tenant_id: str = Depends(get_tenant)) -> dict[str, Any]:
        try:
            return svc.get(run_id, tenant_id).to_view()
        except (KeyError, CrossTenantAccess):
            raise HTTPException(status_code=404, detail="unknown run")

    @app.post("/runs/{run_id}/advance")
    def advance(run_id: str, tenant_id: str = Depends(get_tenant)) -> dict[str, Any]:
        _check_rate(tenant_id, "runs:advance")
        try:
            return svc.advance(run_id, tenant_id).to_view()
        except (KeyError, CrossTenantAccess):
            raise HTTPException(status_code=404, detail="unknown run")

    @app.post("/runs/{run_id}/resume")
    def resume(
        run_id: str, req: ResumeRequest, tenant_id: str = Depends(get_tenant)
    ) -> dict[str, Any]:
        try:
            return svc.resume(
                run_id, req.step_id, req.approved, req.approver, tenant_id
            ).to_view()
        except (KeyError, CrossTenantAccess):
            raise HTTPException(status_code=404, detail="unknown run")
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc))

    @app.get("/runs/{run_id}/evidence")
    def evidence(run_id: str, tenant_id: str = Depends(get_tenant)) -> dict[str, Any]:
        try:
            return svc.evidence(run_id, tenant_id)
        except (KeyError, CrossTenantAccess):
            raise HTTPException(status_code=404, detail="unknown run")

    # ── transparency (Phase 8/9: RFC 6962 signed tree heads + proofs over the wire) ─

    @app.get("/runs/{run_id}/transparency")
    def transparency(
        run_id: str,
        leaf: int | None = None,
        tenant_id: str = Depends(get_tenant),
    ) -> dict[str, Any]:
        """Signed Tree Head over a run's evidence ledger; optional ?leaf=N inclusion proof."""
        try:
            return svc.transparency(run_id, tenant_id, leaf_index=leaf)
        except (KeyError, CrossTenantAccess):
            raise HTTPException(status_code=404, detail="unknown run")
        except IndexError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.get("/runs/{run_id}/transparency/consistency")
    def transparency_consistency(
        run_id: str,
        first_size: int,
        tenant_id: str = Depends(get_tenant),
    ) -> dict[str, Any]:
        """Append-only consistency proof from ?first_size=M to the current ledger size."""
        try:
            return svc.transparency_consistency(run_id, first_size, tenant_id)
        except (KeyError, CrossTenantAccess):
            raise HTTPException(status_code=404, detail="unknown run")
        except IndexError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.get("/runs/{run_id}/transparency/cosigned")
    def transparency_cosigned(
        run_id: str,
        tenant_id: str = Depends(get_tenant),
    ) -> dict[str, Any]:
        """Signed tree head plus independent witness cosignatures (split-view defense).

        Returns the STH, the gathered witness cosignatures, the panel size/threshold,
        and a `trustworthy` flag that is true once `threshold` distinct witnesses have
        cosigned the head along a consistent, append-only history.
        """
        try:
            return svc.transparency_cosigned(run_id, tenant_id)
        except (KeyError, CrossTenantAccess):
            raise HTTPException(status_code=404, detail="unknown run")
        except IndexError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    # ── analytics (per-tenant, projected from the evidence ledger) ────────────

    @app.get("/analytics")
    def analytics(tenant_id: str = Depends(get_tenant)) -> dict[str, Any]:
        try:
            return svc.analytics(tenant_id)
        except UnknownTenant:
            raise HTTPException(status_code=404, detail="unknown tenant")

    # ── compliance export (Phase 7: SOC2/GDPR, projected from the ledger) ─────

    @app.get("/compliance")
    def compliance(tenant_id: str = Depends(get_tenant)) -> dict[str, Any]:
        try:
            return svc.compliance(tenant_id)
        except UnknownTenant:
            raise HTTPException(status_code=404, detail="unknown tenant")

    # ── audit export (Phase 19: SIEM-ready event-level export) ───────────────

    @app.get("/audit/events")
    def audit_events(
        tenant_id: str = Depends(get_tenant),
        event_type: str | None = None,
        since: str | None = None,
        until: str | None = None,
        actor: str | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Paginated, filterable audit event export from the evidence ledger (Phase 19).

        Returns a JSON page of normalised ``AuditEvent`` records, suitable for
        SIEM ingestion (Splunk, Datadog, Elastic, Azure Sentinel). Filters:
          ``event_type`` — exact match on event type (e.g. ``tool.invoked``)
          ``since``      — ISO-8601 or Unix epoch lower bound (inclusive)
          ``until``      — ISO-8601 or Unix epoch upper bound (exclusive)
          ``actor``      — exact match on actor id
          ``offset``     — zero-based pagination offset
          ``limit``      — page size (capped at audit.max_page_size in config)

        HTTP 403 when audit.enabled = False (default, backward-compatible).
        Schema follows OCSF v1.0 (CISA 2022) field conventions.
        """
        if not audit_cfg.enabled:
            raise HTTPException(
                status_code=403,
                detail="audit export is disabled; set audit.enabled = true in config",
            )
        try:
            page = svc.audit_events(
                tenant_id=tenant_id,
                event_type=event_type,
                since=since,
                until=until,
                actor=actor,
                offset=offset,
                limit=limit,
                max_limit=audit_cfg.max_page_size,
            )
        except UnknownTenant:
            raise HTTPException(status_code=404, detail="unknown tenant")
        return page.to_dict()

    @app.get("/audit/summary")
    def audit_summary(tenant_id: str = Depends(get_tenant)) -> dict[str, Any]:
        """Lightweight audit event-count summary across all runs for a tenant (Phase 19).

        Returns event type counts, actor counts, and the audit window (earliest/latest
        timestamps) without paying the cost of a full event export. Suitable for
        SIEM health checks and dashboard widgets.

        HTTP 403 when audit.enabled = False (default, backward-compatible).
        """
        if not audit_cfg.enabled:
            raise HTTPException(
                status_code=403,
                detail="audit export is disabled; set audit.enabled = true in config",
            )
        try:
            return svc.audit_summary(tenant_id)
        except UnknownTenant:
            raise HTTPException(status_code=404, detail="unknown tenant")

    # ── constitution (Phase 7: supreme governance articles, read-only view) ───

    @app.get("/config/constitution")
    def constitution() -> dict[str, Any]:
        cfg = load_config()
        return {
            "version": cfg.constitution.version,
            "articles": [
                {
                    "id": a.id,
                    "principle": a.principle,
                    "verdict": a.verdict,
                    "scope": a.scope,
                    "tool": a.tool,
                    "min_cost_minor": a.min_cost_minor,
                    "high_impact_only": a.high_impact,
                }
                for a in cfg.constitution.articles
            ],
        }

    # ── tenants (multi-tenant workspace isolation) ────────────────────────────
    @app.get("/tenants")
    def list_tenants() -> dict[str, Any]:
        return {"tenants": [t.to_view() for t in svc.tenants.list()]}

    @app.post("/tenants")
    def create_tenant(req: CreateTenantRequest) -> dict[str, Any]:
        try:
            tenant = svc.tenants.create(
                req.display_name,
                tenant_id=req.tenant_id,
                max_budget_minor=req.max_budget_minor,
                max_autonomy_tier=req.max_autonomy_tier,
            )
        except TenantError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        return tenant.to_view()

    @app.get("/tenants/{tenant_id}")
    def get_tenant_by_id(tenant_id: str) -> dict[str, Any]:
        try:
            return svc.tenants.get(tenant_id).to_view()
        except UnknownTenant:
            raise HTTPException(status_code=404, detail="unknown tenant")

    # ── run lifecycle (Phase 11) ──────────────────────────────────────────────

    @app.post("/runs/{run_id}/cancel")
    def cancel_run(run_id: str, tenant_id: str = Depends(get_tenant)) -> dict[str, Any]:
        """Cancel a non-terminal run. The cancellation is recorded in the evidence ledger."""
        try:
            return svc.cancel_run(run_id, tenant_id).to_view()
        except (KeyError, CrossTenantAccess):
            raise HTTPException(status_code=404, detail="unknown run")

    @app.delete("/runs/{run_id}", status_code=204)
    def delete_run(run_id: str, tenant_id: str = Depends(get_tenant)) -> None:
        """Remove a terminal (completed/halted) run from the service registry.

        Returns 204 No Content on success. Active runs must be cancelled first.
        """
        try:
            svc.delete_run(run_id, tenant_id)
        except (KeyError, CrossTenantAccess):
            raise HTTPException(status_code=404, detail="unknown run")
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc))

    # ── collaboration (Phase 11) ─────────────────────────────────────────────

    @app.post("/collaborations", status_code=201)
    def open_collaboration(
        req: OpenCollaborationRequest, tenant_id: str = Depends(get_tenant)
    ) -> dict[str, Any]:
        """Open (or retrieve) a tenant-scoped shared ledger for multi-agent collaboration."""
        try:
            return svc.open_collaboration(req.collaboration_id, tenant_id)
        except UnknownTenant:
            raise HTTPException(status_code=404, detail="unknown tenant")

    @app.get("/collaborations")
    def list_collaborations(tenant_id: str = Depends(get_tenant)) -> dict[str, Any]:
        """List all collaborations visible to the requesting tenant."""
        try:
            return {"tenant_id": tenant_id, "collaborations": svc.list_collaborations(tenant_id)}
        except UnknownTenant:
            raise HTTPException(status_code=404, detail="unknown tenant")

    @app.get("/collaborations/{collaboration_id}")
    def get_collaboration(
        collaboration_id: str, tenant_id: str = Depends(get_tenant)
    ) -> dict[str, Any]:
        """Return a collaboration's full state and tamper-evident shared ledger."""
        try:
            return svc.get_collaboration(collaboration_id, tenant_id)
        except (CrossTenantAccess, KeyError):
            raise HTTPException(status_code=404, detail="unknown collaboration")
        except UnknownTenant:
            raise HTTPException(status_code=404, detail="unknown tenant")

    @app.post("/collaborations/{collaboration_id}/admit", status_code=201)
    def admit_agent(
        collaboration_id: str,
        req: AdmitAgentRequest,
        tenant_id: str = Depends(get_tenant),
    ) -> dict[str, Any]:
        """Admit an agent to a collaboration, verifying its capability lease signature."""
        try:
            return svc.admit_to_collaboration(
                collaboration_id, req.agent_id, req.lease, tenant_id
            )
        except (CrossTenantAccess, KeyError):
            raise HTTPException(status_code=404, detail="unknown collaboration")
        except UnknownTenant:
            raise HTTPException(status_code=404, detail="unknown tenant")
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.post("/collaborations/{collaboration_id}/contribute", status_code=201)
    def contribute(
        collaboration_id: str,
        req: ContributeRequest,
        tenant_id: str = Depends(get_tenant),
    ) -> dict[str, Any]:
        """Append an attributed, tamper-evident entry to the collaboration's shared ledger."""
        try:
            return svc.contribute_to_collaboration(
                collaboration_id, req.agent_id, req.event_type, req.payload, tenant_id
            )
        except (CrossTenantAccess, KeyError):
            raise HTTPException(status_code=404, detail="unknown collaboration")
        except UnknownTenant:
            raise HTTPException(status_code=404, detail="unknown tenant")
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    # ── marketplace (Phase 11) ────────────────────────────────────────────────

    @app.get("/marketplace/catalog")
    def marketplace_catalog() -> dict[str, Any]:
        """List all governed skills available in the marketplace catalog."""
        return {"skills": svc.marketplace_catalog()}

    @app.post("/marketplace/skills", status_code=201)
    def publish_skill(req: PublishSkillRequest, tenant_id: str = Depends(get_tenant)) -> dict[str, Any]:
        """Publish a signed skill to the marketplace catalog.

        The Ed25519 signature must verify over the manifest's canonical bytes.
        Raises 400 if the signature is invalid.
        """
        _check_rate(tenant_id, "marketplace:publish")
        try:
            return svc.marketplace_publish(req.manifest, req.signature)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.post("/marketplace/skills/{skill_id}/install", status_code=201)
    def install_skill(
        skill_id: str,
        req: InstallSkillRequest,
        tenant_id: str = Depends(get_tenant),
    ) -> dict[str, Any]:
        """Install a marketplace skill under the full governance gate for a tenant.

        Verifies Ed25519 origin, enforces least-privilege scope delegation, and
        evaluates constitutional supremacy. Returns 404 if skill not in catalog,
        400 if any governance check fails.
        """
        _check_rate(tenant_id, "marketplace:install")
        try:
            return svc.marketplace_install(
                skill_id, req.version, tenant_id, req.permitted_scopes
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except UnknownTenant:
            raise HTTPException(status_code=404, detail="unknown tenant")
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.get("/marketplace/installed")
    def marketplace_installed(tenant_id: str = Depends(get_tenant)) -> dict[str, Any]:
        """List all skills installed for the requesting tenant."""
        try:
            return {"tenant_id": tenant_id, "installed": svc.marketplace_installed(tenant_id)}
        except UnknownTenant:
            raise HTTPException(status_code=404, detail="unknown tenant")

    return app


app = create_app()
