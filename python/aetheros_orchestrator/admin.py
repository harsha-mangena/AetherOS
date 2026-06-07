"""Admin introspection API for AetherOS — Phase 22/25.

Provides lightweight, read-only admin endpoints over the RunService state for
ops tooling, dashboards, and SIEM pipelines. All endpoints use the standard
get_tenant FastAPI dependency so they inherit auth protection when auth is enabled.

Phase 25 adds GET /admin/events — a real-time SSE stream (W3C 2015) of governed
run state changes, with events formatted as CloudEvents v1.0.2 JSON payloads.

Standards / research net
────────────────────────
* Google API Design Guide (cloud.google.com/apis/design 2023): read-only collection
  resources, GET /admin/{collection} naming, summary sub-resources. Resource-oriented
  design: expose state as named resources, not RPC verbs.
* RFC 7807 Problem Details for HTTP APIs (IETF 2016): error response shape —
  {"detail": "<human-readable problem>"} for HTTP 4xx/5xx responses, consistent
  with FastAPI's built-in HTTPException format.
* W3C Server-Sent Events (W3C Recommendation 2015): text/event-stream, event/data/id.
* CloudEvents v1.0.2 (CNCF 2022): specversion, id, source, type, time, data.
"""

from __future__ import annotations

import asyncio
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

    # ── GET /admin/events ─────────────────────────────────────────────────────

    @router.get("/events")
    async def admin_events(
        tenant_id: str = Depends(get_tenant),
        poll_interval: float = 0.1,
        heartbeat_interval: int = 15,
    ) -> Any:
        """Real-time SSE stream of governed run state changes.

        Streams Server-Sent Events (W3C 2015) as the governance engine processes
        runs. Each event is a JSON-encoded RunEvent (CloudEvents v1.0.2 aligned)
        with type aetheros.run.{created|step_completed|halted|completed|approval_required}
        plus periodic heartbeats to keep the connection alive through proxies.

        Connect with EventSource (browser) or httpx-sse (Python):
            eventsource = new EventSource('/admin/events', {headers: {Authorization: ...}})
            eventsource.onmessage = (e) => console.log(JSON.parse(e.data))

        Parameters
        ----------
        poll_interval:
            Seconds between RunService snapshot polls (default 0.1s = 100ms).
        heartbeat_interval:
            Seconds between heartbeat events to keep connections alive (default 15s).
        """
        from .events import diff_snapshots, RunEvent, get_event_bus

        try:
            from sse_starlette.sse import EventSourceResponse
        except ImportError:
            raise HTTPException(status_code=503, detail="sse_starlette not installed")

        bus = get_event_bus()

        async def event_generator():
            prev_snapshot: dict[str, dict] = {}
            loop = asyncio.get_running_loop()
            last_heartbeat = loop.time()
            seq = 0
            try:
                while True:
                    # Snapshot current run state (non-blocking via to_thread).
                    runs = await asyncio.to_thread(svc.list_runs, tenant_id)
                    current_snapshot = {r["run_id"]: r for r in runs}

                    # Diff and yield events.
                    for event in diff_snapshots(prev_snapshot, current_snapshot):
                        seq += 1
                        yield {
                            "event": event.type,
                            "data": event.to_sse_data(),
                            "id": str(seq),
                        }
                    prev_snapshot = current_snapshot

                    # Heartbeat to keep proxies from closing the connection.
                    now = asyncio.get_running_loop().time()
                    if now - last_heartbeat >= heartbeat_interval:
                        seq += 1
                        hb = RunEvent(
                            type="aetheros.heartbeat",
                            data={"subscriber_count": bus.subscriber_count},
                        )
                        yield {
                            "event": "aetheros.heartbeat",
                            "data": hb.to_sse_data(),
                            "id": str(seq),
                        }
                        last_heartbeat = now

                    await asyncio.sleep(poll_interval)
            except asyncio.CancelledError:
                pass  # client disconnected — clean exit

        return EventSourceResponse(event_generator())

    return router
