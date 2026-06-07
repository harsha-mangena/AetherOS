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
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
except Exception as exc:  # pragma: no cover - import guard
    raise RuntimeError(
        "FastAPI is required for the API layer. Install with: pip install 'fastapi' 'uvicorn'"
    ) from exc

from .config import load_config
from .run_service import RunService


class CreateRunRequest(BaseModel):
    intent: str = Field(..., description="Natural-language intent / goal.")
    submitted_by: str = Field("human:operator")
    budget_minor: int = Field(100_000, ge=0)


class ResumeRequest(BaseModel):
    step_id: str
    approved: bool
    approver: str = Field("human:operator")


def create_app(service: RunService | None = None) -> "FastAPI":
    """Build the FastAPI app. A custom RunService can be injected for tests."""
    app = FastAPI(title="AetherOS Control Plane API", version="0.5.0")
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
    def list_runs() -> dict[str, Any]:
        return {"runs": svc.list_runs()}

    @app.post("/runs")
    def create_run(req: CreateRunRequest) -> dict[str, Any]:
        run = svc.create_run(req.intent, req.submitted_by, req.budget_minor)
        return run.to_view()

    @app.get("/runs/{run_id}")
    def get_run(run_id: str) -> dict[str, Any]:
        try:
            return svc.get(run_id).to_view()
        except KeyError:
            raise HTTPException(status_code=404, detail="unknown run")

    @app.post("/runs/{run_id}/advance")
    def advance(run_id: str) -> dict[str, Any]:
        try:
            return svc.advance(run_id).to_view()
        except KeyError:
            raise HTTPException(status_code=404, detail="unknown run")

    @app.post("/runs/{run_id}/resume")
    def resume(run_id: str, req: ResumeRequest) -> dict[str, Any]:
        try:
            return svc.resume(run_id, req.step_id, req.approved, req.approver).to_view()
        except KeyError:
            raise HTTPException(status_code=404, detail="unknown run")
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc))

    @app.get("/runs/{run_id}/evidence")
    def evidence(run_id: str) -> dict[str, Any]:
        try:
            return svc.evidence(run_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="unknown run")

    return app


app = create_app()
