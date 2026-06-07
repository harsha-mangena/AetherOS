"""Admin introspection API for AetherOS — Phase 22.

Provides lightweight, read-only admin endpoints over the RunService state for
ops tooling, dashboards, and SIEM pipelines. All endpoints use the standard
get_tenant FastAPI dependency so they inherit auth protection when auth is enabled.

Standards / research net
────────────────────────
* Google API Design Guide (cloud.google.com/apis/design 2023): read-only collection
  resources, GET /admin/{collection} naming, summary sub-resources. Resource-oriented
  design: expose state as named resources, not RPC verbs.
* RFC 7807 Problem Details for HTTP APIs (IETF 2016): error response shape —
  {"detail": "<human-readable problem>"} for HTTP 4xx/5xx responses, consistent
  with FastAPI's built-in HTTPException format.
"""

from __future__ import annotations

from typing import Any

try:
    from fastapi import APIRouter, Depends, HTTPException
    _FASTAPI_AVAILABLE = True
except ImportError:  # pragma: no cover
    _FASTAPI_AVAILABLE = False

from .run_service import RunService


def make_admin_router(svc: RunService, get_tenant: Any) -> "APIRouter":
    """Return a FastAPI APIRouter with /admin/* introspection endpoints (Phase 22).

    All endpoints are read-only projections over RunService state. They do not
    call analytics() (which replays evidence ledgers) and are therefore O(runs)
    not O(evidence_entries). Auth protection is inherited from the get_tenant
    dependency — when auth is disabled all tests pass without headers.

    Parameters
    ----------
    svc:
        The RunService instance to introspect.
    get_tenant:
        FastAPI dependency that resolves tenant_id from the request. Returned by
        AuthService.tenant_id_dependency() — when auth is disabled this reads the
        X-Tenant-Id header (defaulting to "default").
    """
    if not _FASTAPI_AVAILABLE:
        raise RuntimeError("fastapi is required; pip install fastapi")

    router = APIRouter(prefix="/admin")

    # ── helper: project a run-view dict to a lightweight summary ─────────────

    def _summarise(view: dict[str, Any]) -> dict[str, Any]:
        """Project a full run view to the lightweight admin summary shape."""
        results = view.get("results", [])
        plan = view.get("plan", [])
        step_count = len(plan)
        completed_steps = sum(
            1 for r in results if r.get("status") in ("executed", "completed")
        )
        denied_steps = sum(1 for r in results if r.get("status") == "denied")
        budget = view.get("intent", {}).get("budget_minor", 0)
        remaining = view.get("remaining_minor", budget)
        return {
            "run_id": view.get("run_id", ""),
            "status": view.get("status", ""),
            "total_cost_minor": view.get("total_cost_minor", 0),
            "step_count": step_count,
            "completed_steps": completed_steps,
            "denied_steps": denied_steps,
            "created_at": view.get("created_at", ""),
            "budget_minor": budget,
            "remaining_minor": remaining if remaining is not None else budget,
        }

    # ── GET /admin/runs ───────────────────────────────────────────────────────

    @router.get("/runs")
    def admin_list_runs(
        status: str | None = None,
        tenant_id: str = Depends(get_tenant),
    ) -> dict[str, Any]:
        """List all governed runs for the requesting tenant with summary fields.

        Query params:
          status — optional filter by run status string (e.g. "completed", "halted").

        Response shape:
          {"tenant_id": "...", "total": N, "runs": [{summary}, ...]}

        Does not call analytics() — projection is O(runs), not O(evidence).
        """
        views = svc.list_runs(tenant_id)
        summaries = [_summarise(v) for v in views]
        if status is not None:
            summaries = [s for s in summaries if s["status"] == status]
        return {
            "tenant_id": tenant_id,
            "total": len(summaries),
            "runs": summaries,
        }

    # ── GET /admin/tenants/{tenant_id}/budget ─────────────────────────────────

    @router.get("/tenants/{target_tenant_id}/budget")
    def admin_budget(
        target_tenant_id: str,
        tenant_id: str = Depends(get_tenant),
    ) -> dict[str, Any]:
        """Budget summary for a specific tenant.

        The requesting tenant must match target_tenant_id — cross-tenant access
        is forbidden (HTTP 403). Response includes total budget allocated, total
        spent, remaining, and run counts by status.
        """
        if tenant_id != target_tenant_id:
            raise HTTPException(
                status_code=403,
                detail="cross-tenant budget access is forbidden",
            )

        views = svc.list_runs(target_tenant_id)
        total_budget = sum(v.get("intent", {}).get("budget_minor", 0) for v in views)
        total_cost = sum(v.get("total_cost_minor", 0) for v in views)
        remaining = total_budget - total_cost

        statuses = [v.get("status", "") for v in views]
        active = sum(
            1 for s in statuses if s in ("planned", "running", "awaiting_approval")
        )
        completed = sum(1 for s in statuses if s == "completed")

        return {
            "tenant_id": target_tenant_id,
            "total_budget_allocated_minor": total_budget,
            "total_cost_minor": total_cost,
            "total_remaining_minor": remaining,
            "run_count": len(views),
            "active_runs": active,
            "completed_runs": completed,
        }

    # ── GET /admin/policy/deny-rate ───────────────────────────────────────────

    @router.get("/policy/deny-rate")
    def admin_deny_rate(tenant_id: str = Depends(get_tenant)) -> dict[str, Any]:
        """Policy denial statistics for the requesting tenant.

        Counts steps with status "denied" across all runs without replaying
        the evidence ledger. Response includes total_steps, denied_steps,
        deny_rate (0.0–1.0, rounded to 3dp), and a per-run breakdown.
        """
        views = svc.list_runs(tenant_id)
        total_steps = 0
        denied_steps = 0
        denied_by_run: dict[str, int] = {}

        for v in views:
            results = v.get("results", [])
            run_id = v.get("run_id", "")
            run_denied = sum(1 for r in results if r.get("status") == "denied")
            total_steps += len(results)
            denied_steps += run_denied
            if run_denied:
                denied_by_run[run_id] = run_denied

        deny_rate = round(denied_steps / total_steps, 3) if total_steps > 0 else 0.0

        return {
            "tenant_id": tenant_id,
            "total_steps": total_steps,
            "denied_steps": denied_steps,
            "deny_rate": deny_rate,
            "denied_by_run": denied_by_run,
        }

    # ── GET /admin/summary ────────────────────────────────────────────────────

    @router.get("/summary")
    def admin_summary(tenant_id: str = Depends(get_tenant)) -> dict[str, Any]:
        """Combined service-level summary across all tenants (admin overview).

        Aggregates total runs, active/completed/halted counts, total cost, and
        unique tenant count. Auth protection is inherited from get_tenant, so this
        requires a valid token when auth is enabled.

        Response shape:
          {"service": "aetheros-control-plane", "total_runs": N, ...}
        """
        # Collect all runs across all tenants (pass None = no tenant filter).
        all_views = svc.list_runs(tenant_id=None)

        statuses = [v.get("status", "") for v in all_views]
        active = sum(
            1 for s in statuses if s in ("planned", "running", "awaiting_approval")
        )
        completed = sum(1 for s in statuses if s == "completed")
        halted = sum(1 for s in statuses if s == "halted")
        total_cost = sum(v.get("total_cost_minor", 0) for v in all_views)
        tenant_ids = {v.get("tenant_id", "") for v in all_views}

        return {
            "service": "aetheros-control-plane",
            "total_runs": len(all_views),
            "active_runs": active,
            "completed_runs": completed,
            "halted_runs": halted,
            "total_cost_minor": total_cost,
            "tenant_count": len(tenant_ids),
        }

    return router
