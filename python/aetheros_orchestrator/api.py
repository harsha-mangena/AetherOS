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
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

try:
    from fastapi import FastAPI, Header, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
except Exception as exc:  # pragma: no cover - import guard
    raise RuntimeError(
        "FastAPI is required for the API layer. Install with: pip install 'fastapi' 'uvicorn'"
    ) from exc

from .config import load_config
from .run_service import RunService
from .tenancy import (
    DEFAULT_TENANT_ID,
    CrossTenantAccess,
    TenantError,
    UnknownTenant,
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


def create_app(service: RunService | None = None) -> "FastAPI":
    """Build the FastAPI app. A custom RunService can be injected for tests."""
    app = FastAPI(title="AetherOS Control Plane API", version="0.9.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # local desktop app; tighten for any networked deployment
        allow_methods=["*"],
        allow_headers=["*"],
    )
    svc = service or RunService()
    app.state.service = svc

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "service": "aetheros-control-plane"}

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
    def list_runs(x_tenant_id: str = Header(DEFAULT_TENANT_ID)) -> dict[str, Any]:
        try:
            svc.tenants.get(x_tenant_id)
        except UnknownTenant:
            raise HTTPException(status_code=404, detail="unknown tenant")
        return {"tenant_id": x_tenant_id, "runs": svc.list_runs(x_tenant_id)}

    @app.post("/runs")
    def create_run(
        req: CreateRunRequest, x_tenant_id: str = Header(DEFAULT_TENANT_ID)
    ) -> dict[str, Any]:
        try:
            run = svc.create_run(req.intent, req.submitted_by, req.budget_minor, x_tenant_id)
        except UnknownTenant:
            raise HTTPException(status_code=404, detail="unknown tenant")
        return run.to_view()

    @app.get("/runs/{run_id}")
    def get_run(run_id: str, x_tenant_id: str = Header(DEFAULT_TENANT_ID)) -> dict[str, Any]:
        try:
            return svc.get(run_id, x_tenant_id).to_view()
        except (KeyError, CrossTenantAccess):
            raise HTTPException(status_code=404, detail="unknown run")

    @app.post("/runs/{run_id}/advance")
    def advance(run_id: str, x_tenant_id: str = Header(DEFAULT_TENANT_ID)) -> dict[str, Any]:
        try:
            return svc.advance(run_id, x_tenant_id).to_view()
        except (KeyError, CrossTenantAccess):
            raise HTTPException(status_code=404, detail="unknown run")

    @app.post("/runs/{run_id}/resume")
    def resume(
        run_id: str, req: ResumeRequest, x_tenant_id: str = Header(DEFAULT_TENANT_ID)
    ) -> dict[str, Any]:
        try:
            return svc.resume(
                run_id, req.step_id, req.approved, req.approver, x_tenant_id
            ).to_view()
        except (KeyError, CrossTenantAccess):
            raise HTTPException(status_code=404, detail="unknown run")
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc))

    @app.get("/runs/{run_id}/evidence")
    def evidence(run_id: str, x_tenant_id: str = Header(DEFAULT_TENANT_ID)) -> dict[str, Any]:
        try:
            return svc.evidence(run_id, x_tenant_id)
        except (KeyError, CrossTenantAccess):
            raise HTTPException(status_code=404, detail="unknown run")

    # ── transparency (Phase 8/9: RFC 6962 signed tree heads + proofs over the wire) ─

    @app.get("/runs/{run_id}/transparency")
    def transparency(
        run_id: str,
        leaf: int | None = None,
        x_tenant_id: str = Header(DEFAULT_TENANT_ID),
    ) -> dict[str, Any]:
        """Signed Tree Head over a run's evidence ledger; optional ?leaf=N inclusion proof."""
        try:
            return svc.transparency(run_id, x_tenant_id, leaf_index=leaf)
        except (KeyError, CrossTenantAccess):
            raise HTTPException(status_code=404, detail="unknown run")
        except IndexError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.get("/runs/{run_id}/transparency/consistency")
    def transparency_consistency(
        run_id: str,
        first_size: int,
        x_tenant_id: str = Header(DEFAULT_TENANT_ID),
    ) -> dict[str, Any]:
        """Append-only consistency proof from ?first_size=M to the current ledger size."""
        try:
            return svc.transparency_consistency(run_id, first_size, x_tenant_id)
        except (KeyError, CrossTenantAccess):
            raise HTTPException(status_code=404, detail="unknown run")
        except IndexError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.get("/runs/{run_id}/transparency/cosigned")
    def transparency_cosigned(
        run_id: str,
        x_tenant_id: str = Header(DEFAULT_TENANT_ID),
    ) -> dict[str, Any]:
        """Signed tree head plus independent witness cosignatures (split-view defense).

        Returns the STH, the gathered witness cosignatures, the panel size/threshold,
        and a `trustworthy` flag that is true once `threshold` distinct witnesses have
        cosigned the head along a consistent, append-only history.
        """
        try:
            return svc.transparency_cosigned(run_id, x_tenant_id)
        except (KeyError, CrossTenantAccess):
            raise HTTPException(status_code=404, detail="unknown run")
        except IndexError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    # ── analytics (per-tenant, projected from the evidence ledger) ────────────

    @app.get("/analytics")
    def analytics(x_tenant_id: str = Header(DEFAULT_TENANT_ID)) -> dict[str, Any]:
        try:
            return svc.analytics(x_tenant_id)
        except UnknownTenant:
            raise HTTPException(status_code=404, detail="unknown tenant")

    # ── compliance export (Phase 7: SOC2/GDPR, projected from the ledger) ─────

    @app.get("/compliance")
    def compliance(x_tenant_id: str = Header(DEFAULT_TENANT_ID)) -> dict[str, Any]:
        try:
            return svc.compliance(x_tenant_id)
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
    def get_tenant(tenant_id: str) -> dict[str, Any]:
        try:
            return svc.tenants.get(tenant_id).to_view()
        except UnknownTenant:
            raise HTTPException(status_code=404, detail="unknown tenant")

    # ── run lifecycle (Phase 11) ──────────────────────────────────────────────

    @app.post("/runs/{run_id}/cancel")
    def cancel_run(run_id: str, x_tenant_id: str = Header(DEFAULT_TENANT_ID)) -> dict[str, Any]:
        """Cancel a non-terminal run. The cancellation is recorded in the evidence ledger."""
        try:
            return svc.cancel_run(run_id, x_tenant_id).to_view()
        except (KeyError, CrossTenantAccess):
            raise HTTPException(status_code=404, detail="unknown run")

    @app.delete("/runs/{run_id}", status_code=204)
    def delete_run(run_id: str, x_tenant_id: str = Header(DEFAULT_TENANT_ID)) -> None:
        """Remove a terminal (completed/halted) run from the service registry.

        Returns 204 No Content on success. Active runs must be cancelled first.
        """
        try:
            svc.delete_run(run_id, x_tenant_id)
        except (KeyError, CrossTenantAccess):
            raise HTTPException(status_code=404, detail="unknown run")
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc))

    # ── collaboration (Phase 11) ─────────────────────────────────────────────

    @app.post("/collaborations", status_code=201)
    def open_collaboration(
        req: OpenCollaborationRequest, x_tenant_id: str = Header(DEFAULT_TENANT_ID)
    ) -> dict[str, Any]:
        """Open (or retrieve) a tenant-scoped shared ledger for multi-agent collaboration."""
        try:
            return svc.open_collaboration(req.collaboration_id, x_tenant_id)
        except UnknownTenant:
            raise HTTPException(status_code=404, detail="unknown tenant")

    @app.get("/collaborations")
    def list_collaborations(x_tenant_id: str = Header(DEFAULT_TENANT_ID)) -> dict[str, Any]:
        """List all collaborations visible to the requesting tenant."""
        try:
            return {"tenant_id": x_tenant_id, "collaborations": svc.list_collaborations(x_tenant_id)}
        except UnknownTenant:
            raise HTTPException(status_code=404, detail="unknown tenant")

    @app.get("/collaborations/{collaboration_id}")
    def get_collaboration(
        collaboration_id: str, x_tenant_id: str = Header(DEFAULT_TENANT_ID)
    ) -> dict[str, Any]:
        """Return a collaboration's full state and tamper-evident shared ledger."""
        try:
            return svc.get_collaboration(collaboration_id, x_tenant_id)
        except (CrossTenantAccess, KeyError):
            raise HTTPException(status_code=404, detail="unknown collaboration")
        except UnknownTenant:
            raise HTTPException(status_code=404, detail="unknown tenant")

    @app.post("/collaborations/{collaboration_id}/admit", status_code=201)
    def admit_agent(
        collaboration_id: str,
        req: AdmitAgentRequest,
        x_tenant_id: str = Header(DEFAULT_TENANT_ID),
    ) -> dict[str, Any]:
        """Admit an agent to a collaboration, verifying its capability lease signature."""
        try:
            return svc.admit_to_collaboration(
                collaboration_id, req.agent_id, req.lease, x_tenant_id
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
        x_tenant_id: str = Header(DEFAULT_TENANT_ID),
    ) -> dict[str, Any]:
        """Append an attributed, tamper-evident entry to the collaboration's shared ledger."""
        try:
            return svc.contribute_to_collaboration(
                collaboration_id, req.agent_id, req.event_type, req.payload, x_tenant_id
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
    def publish_skill(req: PublishSkillRequest) -> dict[str, Any]:
        """Publish a signed skill to the marketplace catalog.

        The Ed25519 signature must verify over the manifest's canonical bytes.
        Raises 400 if the signature is invalid.
        """
        try:
            return svc.marketplace_publish(req.manifest, req.signature)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.post("/marketplace/skills/{skill_id}/install", status_code=201)
    def install_skill(
        skill_id: str,
        req: InstallSkillRequest,
        x_tenant_id: str = Header(DEFAULT_TENANT_ID),
    ) -> dict[str, Any]:
        """Install a marketplace skill under the full governance gate for a tenant.

        Verifies Ed25519 origin, enforces least-privilege scope delegation, and
        evaluates constitutional supremacy. Returns 404 if skill not in catalog,
        400 if any governance check fails.
        """
        try:
            return svc.marketplace_install(
                skill_id, req.version, x_tenant_id, req.permitted_scopes
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except UnknownTenant:
            raise HTTPException(status_code=404, detail="unknown tenant")
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.get("/marketplace/installed")
    def marketplace_installed(x_tenant_id: str = Header(DEFAULT_TENANT_ID)) -> dict[str, Any]:
        """List all skills installed for the requesting tenant."""
        try:
            return {"tenant_id": x_tenant_id, "installed": svc.marketplace_installed(x_tenant_id)}
        except UnknownTenant:
            raise HTTPException(status_code=404, detail="unknown tenant")

    return app


app = create_app()
