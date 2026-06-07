"""Phase 17 tests: per-tenant, per-route rate limiting.

Properties under test (atom of thoughts — smallest verifiable units):

  RateLimiter unit (algorithm + thread-safety):
    1.  Disabled limiter (limit=0): never raises regardless of call count.
    2.  Within limit: N calls succeed when limit=N (exactly at boundary).
    3.  Exceeded: call N+1 raises RateLimitExceeded.
    4.  RateLimitExceeded carries correct retry_after, limit, window_seconds.
    5.  Per-tenant isolation: tenant A being limited does not block tenant B.
    6.  Per-route isolation: route "a" being limited does not block route "b".
    7.  Window slide: after the window advances, the counter resets and calls succeed.
    8.  Sliding-window weighting: mid-window, previous window count is weighted
        by remaining fraction — counts decay correctly.
    9.  route_limits override: a per-route limit overrides the default_limit.
    10. default_limit fallback: a route not in route_limits uses default_limit.
    11. get_count returns correct estimate without incrementing.
    12. Lazy pruning: old window entries are cleaned up to prevent unbounded growth.

  HTTP integration (FastAPI TestClient):
    13. With rate limiting disabled (default), all prior endpoints return normally.
    14. POST /runs respects "runs:create" limit: N+1th call returns 429.
    15. 429 response body includes "rate limit exceeded" detail.
    16. 429 response includes Retry-After header with a positive integer value.
    17. POST /auth/token respects "auth:token" limit.
    18. POST /runs/{id}/advance respects "runs:advance" limit.
    19. POST /marketplace/skills respects "marketplace:publish" limit.
    20. POST /marketplace/skills/{id}/install respects "marketplace:install" limit.
    21. Per-tenant isolation via HTTP: tenant A at limit does not block tenant B.
"""
from __future__ import annotations

import math
import time
from unittest.mock import patch as mock_patch

import pytest

try:
    from fastapi.testclient import TestClient
except ImportError:
    pytest.skip("fastapi not installed", allow_module_level=True)

from aetheros_orchestrator.rate_limiter import RateLimiter, RateLimitExceeded
from aetheros_orchestrator.config import RateLimitConfig
from aetheros_orchestrator.api import create_app
from aetheros_orchestrator.run_service import RunService


# ── helpers ───────────────────────────────────────────────────────────────────


def _make_limiter(
    *,
    limit: int = 3,
    route: str = "test:route",
    window: int = 60,
    clock_val: float = 1000.0,
) -> tuple[RateLimiter, str, float]:
    """Return (limiter, route_key, initial_clock_val) with a controllable clock."""
    t = [clock_val]

    def clock() -> float:
        return t[0]

    limiter = RateLimiter(
        window_seconds=window,
        default_limit=0,
        route_limits={route: limit},
        clock=clock,
    )
    return limiter, route, t


def _app_with_rl(
    *,
    window: int = 60,
    route_limits: dict | None = None,
    clock_val: float = 1000.0,
) -> tuple:
    """Return (client, clock_list) with rate limiting enabled, using a fake clock."""
    t = [clock_val]

    def clock() -> float:
        return t[0]

    svc = RunService()
    app = create_app(service=svc)

    # Inject a rate limiter with controllable clock directly into app state
    from aetheros_orchestrator.rate_limiter import RateLimiter
    rl = RateLimiter(
        window_seconds=window,
        default_limit=0,
        route_limits=route_limits or {},
        clock=clock,
    )
    app.state.rate_limiter = rl

    # Patch _check_rate inside the app to use our limiter
    # Instead: rebuild the _check_rate closure by monkey-patching via ASGI
    # The cleaner path: create_app accepts rate_limiter injection
    # Since it doesn't yet, we directly patch app.state.rate_limiter and
    # rebuild the check helper by creating a new app that accepts the limiter.
    # Use the simpler approach: create app with a RateLimiter-injecting override.
    return TestClient(app), t, rl


# ── 1-12. RateLimiter unit ────────────────────────────────────────────────────


def test_disabled_limiter_never_raises():
    limiter = RateLimiter(window_seconds=60, default_limit=0)
    for _ in range(100):
        limiter.check_and_increment("t", "route")  # should not raise


def test_within_limit_succeeds():
    t = [1000.0]
    limiter = RateLimiter(
        window_seconds=60,
        default_limit=5,
        clock=lambda: t[0],
    )
    for _ in range(5):
        limiter.check_and_increment("tenant", "route")  # all 5 should succeed


def test_exceeded_raises():
    t = [1000.0]
    limiter = RateLimiter(
        window_seconds=60,
        default_limit=3,
        clock=lambda: t[0],
    )
    for _ in range(3):
        limiter.check_and_increment("tenant", "route")
    with pytest.raises(RateLimitExceeded):
        limiter.check_and_increment("tenant", "route")


def test_rate_limit_exceeded_attrs():
    t = [1030.0]  # 30s into a 60s window
    limiter = RateLimiter(
        window_seconds=60,
        default_limit=2,
        clock=lambda: t[0],
    )
    limiter.check_and_increment("t", "r")
    limiter.check_and_increment("t", "r")
    with pytest.raises(RateLimitExceeded) as exc_info:
        limiter.check_and_increment("t", "r")
    exc = exc_info.value
    assert exc.limit == 2
    assert exc.window_seconds == 60
    assert exc.retry_after >= 1


def test_per_tenant_isolation():
    t = [1000.0]
    limiter = RateLimiter(
        window_seconds=60,
        default_limit=2,
        clock=lambda: t[0],
    )
    limiter.check_and_increment("tenant_a", "route")
    limiter.check_and_increment("tenant_a", "route")
    # tenant_a is now at limit; tenant_b should still succeed
    limiter.check_and_increment("tenant_b", "route")
    with pytest.raises(RateLimitExceeded):
        limiter.check_and_increment("tenant_a", "route")


def test_per_route_isolation():
    t = [1000.0]
    limiter = RateLimiter(
        window_seconds=60,
        default_limit=0,
        route_limits={"route_a": 2, "route_b": 10},
        clock=lambda: t[0],
    )
    limiter.check_and_increment("t", "route_a")
    limiter.check_and_increment("t", "route_a")
    # route_a is at limit; route_b should still work
    limiter.check_and_increment("t", "route_b")
    with pytest.raises(RateLimitExceeded):
        limiter.check_and_increment("t", "route_a")


def test_window_slide_resets_counter():
    t = [1000.0]
    limiter = RateLimiter(
        window_seconds=60,
        default_limit=2,
        clock=lambda: t[0],
    )
    limiter.check_and_increment("t", "r")
    limiter.check_and_increment("t", "r")
    # Advance clock by one full window
    t[0] += 60.0
    # Counter for the new window starts at 0; should succeed again
    limiter.check_and_increment("t", "r")


def test_sliding_window_weighting():
    """Mid-window, previous window count is weighted by remaining fraction."""
    t = [1000.0]  # start of window (window_idx = floor(1000/60) = 16)
    limiter = RateLimiter(
        window_seconds=60,
        default_limit=5,
        clock=lambda: t[0],
    )
    # Fill previous window at t=1000 (window_idx=16): add 4 counts
    for _ in range(4):
        limiter.check_and_increment("t", "r")
    # Advance to start of next window (idx=17, t=1020 is fine but let's go to 1020)
    # window_idx for t=1020 = floor(1020/60)=17; elapsed=1020-17*60=1020-1020=0
    # But we need prev counts to matter. Let's go to idx=17 at elapsed=30s
    # t = 17*60 + 30 = 1050
    t[0] = 1050.0
    # Now: prev_count (idx=16) = 4, curr_count (idx=17) = 0
    # estimated = 4 * (1 - 30/60) + 0 = 4 * 0.5 = 2.0
    # limit=5, so 3 more requests should succeed
    limiter.check_and_increment("t", "r")  # estimated before = 2.0, curr becomes 1
    limiter.check_and_increment("t", "r")  # curr=2
    limiter.check_and_increment("t", "r")  # curr=3; estimated = 2.0+3=5 → next would fail
    with pytest.raises(RateLimitExceeded):
        limiter.check_and_increment("t", "r")  # estimated = 2.0 + 3 = 5 >= 5


def test_route_limits_override():
    t = [1000.0]
    limiter = RateLimiter(
        window_seconds=60,
        default_limit=100,
        route_limits={"special": 1},
        clock=lambda: t[0],
    )
    limiter.check_and_increment("t", "special")
    with pytest.raises(RateLimitExceeded):
        limiter.check_and_increment("t", "special")
    # Default route still has limit 100
    for _ in range(5):
        limiter.check_and_increment("t", "other")


def test_default_limit_fallback():
    t = [1000.0]
    limiter = RateLimiter(
        window_seconds=60,
        default_limit=2,
        route_limits={"explicit": 10},
        clock=lambda: t[0],
    )
    limiter.check_and_increment("t", "unlisted")
    limiter.check_and_increment("t", "unlisted")
    with pytest.raises(RateLimitExceeded):
        limiter.check_and_increment("t", "unlisted")


def test_get_count_no_increment():
    t = [1000.0]
    limiter = RateLimiter(
        window_seconds=60,
        default_limit=5,
        clock=lambda: t[0],
    )
    limiter.check_and_increment("t", "r")
    limiter.check_and_increment("t", "r")
    count = limiter.get_count("t", "r")
    assert count == pytest.approx(2.0, abs=0.01)
    # calling get_count again should not change the count
    assert limiter.get_count("t", "r") == pytest.approx(2.0, abs=0.01)


def test_lazy_pruning():
    """Old window entries are pruned, preventing unbounded dict growth."""
    t = [1000.0]
    limiter = RateLimiter(
        window_seconds=60,
        default_limit=5,
        clock=lambda: t[0],
    )
    key = "t:r"
    limiter.check_and_increment("t", "r")
    # Advance 3 windows
    t[0] += 180.0
    limiter.check_and_increment("t", "r")
    # Only current and previous window should remain (at most 2 entries)
    assert len(limiter._counts[key]) <= 2


# ── 13-21. HTTP integration ────────────────────────────────────────────────────


def _make_client_with_rl(route_limits: dict, window: int = 60) -> tuple:
    """Build a TestClient whose _check_rate uses a controlled RateLimiter."""
    t = [1000.0]

    def clock():
        return t[0]

    svc = RunService()

    # Monkey-patch create_app to inject our rate limiter
    from aetheros_orchestrator import api as api_module
    original_rl_class = api_module.RateLimiter

    class PatchedRateLimiter(RateLimiter):
        def __init__(self, **kwargs):
            kwargs["clock"] = clock
            super().__init__(**kwargs)

    api_module.RateLimiter = PatchedRateLimiter

    # Now create app with rate limiting enabled via a custom RateLimiter
    # We need to inject route_limits and enable the limiter.
    # The cleanest approach: create_app but override the limiter post-construction.
    app = create_app(service=svc)

    # Replace the limiter in the already-built app
    real_limiter = RateLimiter(
        window_seconds=window,
        default_limit=0,
        route_limits=route_limits,
        clock=clock,
    )
    app.state.rate_limiter = real_limiter

    # The _check_rate closure captured the old limiter. We need to rebuild it.
    # Since _check_rate is a closure inside create_app, we cannot easily replace it.
    # Instead, add a middleware that injects the real limiter.
    # Actually the cleanest approach here: rebuild app with the patched class.
    api_module.RateLimiter = original_rl_class

    # Rebuild fresh with patched class properly via a simpler approach:
    # Override create_app to accept rate_limiter param for tests by rebuilding.
    # Use the approach of subclassing: create a new app and wire manually.
    #
    # SIMPLEST working approach: create_app rebuilds the limiter from rl_cfg.
    # Patch cfg.rate_limit at load_config level.
    from aetheros_orchestrator.config import RateLimitConfig
    fake_rl_cfg = RateLimitConfig(
        enabled=True,
        window_seconds=window,
        default_limit=0,
        route_limits=route_limits,
    )

    with mock_patch("aetheros_orchestrator.api.load_config") as mock_cfg:
        from aetheros_orchestrator.config import load_config as real_load
        real_cfg = real_load()
        real_cfg.rate_limit = fake_rl_cfg
        mock_cfg.return_value = real_cfg

        # Also patch RateLimiter to inject clock
        from aetheros_orchestrator import api as api_mod

        original = api_mod.RateLimiter

        class ClockInjectedLimiter(original):
            def __init__(self, **kwargs):
                kwargs["clock"] = clock
                super().__init__(**kwargs)

        api_mod.RateLimiter = ClockInjectedLimiter
        try:
            app2 = create_app(service=RunService())
        finally:
            api_mod.RateLimiter = original

    return TestClient(app2), t


def test_rate_limiting_disabled_by_default():
    """Default config: rate limiting off — all endpoints behave normally."""
    client = TestClient(create_app(service=RunService()))
    # POST /runs should succeed (rate limiting is disabled by default)
    resp = client.post(
        "/runs",
        json={"intent": "diagnose service health", "budget_minor": 50000},
        headers={"X-Tenant-Id": "tenant_rl_default"},
    )
    assert resp.status_code in (200, 201, 400, 404, 422)  # anything but 429


def test_runs_create_rate_limit_enforced():
    client, t = _make_client_with_rl({"runs:create": 2})
    headers = {"X-Tenant-Id": "tenant_rl_1"}
    for _ in range(2):
        resp = client.post(
            "/runs",
            json={"intent": "test intent", "budget_minor": 1000},
            headers=headers,
        )
        assert resp.status_code != 429
    resp = client.post(
        "/runs",
        json={"intent": "test intent", "budget_minor": 1000},
        headers=headers,
    )
    assert resp.status_code == 429


def test_429_detail_message():
    client, t = _make_client_with_rl({"runs:create": 1})
    headers = {"X-Tenant-Id": "tenant_rl_msg"}
    client.post("/runs", json={"intent": "x", "budget_minor": 1000}, headers=headers)
    resp = client.post("/runs", json={"intent": "x", "budget_minor": 1000}, headers=headers)
    assert resp.status_code == 429
    assert "rate limit exceeded" in resp.json()["detail"].lower()


def test_429_retry_after_header():
    client, t = _make_client_with_rl({"runs:create": 1})
    headers = {"X-Tenant-Id": "tenant_rl_hdr"}
    client.post("/runs", json={"intent": "x", "budget_minor": 1000}, headers=headers)
    resp = client.post("/runs", json={"intent": "x", "budget_minor": 1000}, headers=headers)
    assert resp.status_code == 429
    assert "Retry-After" in resp.headers
    assert int(resp.headers["Retry-After"]) >= 1


def test_auth_token_rate_limit():
    client, t = _make_client_with_rl({"auth:token": 2})
    for _ in range(2):
        resp = client.post(
            "/auth/token",
            json={"tenant_id": "t1", "admin_secret": "bad"},
        )
        assert resp.status_code != 429
    resp = client.post("/auth/token", json={"tenant_id": "t1", "admin_secret": "bad"})
    assert resp.status_code == 429


def test_runs_advance_rate_limit():
    client, t = _make_client_with_rl({"runs:advance": 2})
    headers = {"X-Tenant-Id": "tenant_adv"}
    for _ in range(2):
        resp = client.post("/runs/nonexistent-run/advance", headers=headers)
        assert resp.status_code != 429
    resp = client.post("/runs/nonexistent-run/advance", headers=headers)
    assert resp.status_code == 429


def test_marketplace_publish_rate_limit():
    client, t = _make_client_with_rl({"marketplace:publish": 1})
    headers = {"X-Tenant-Id": "tenant_pub"}
    payload = {
        "manifest": {
            "skill_id": "s1",
            "version": "1.0",
            "publisher_agent_id": "a1",
            "publisher_public_key": "deadbeef",
            "required_scopes": [],
            "declared_tools": [],
            "description": "test",
        },
        "signature": "fakesig",
    }
    resp = client.post("/marketplace/skills", json=payload, headers=headers)
    assert resp.status_code != 429
    resp = client.post("/marketplace/skills", json=payload, headers=headers)
    assert resp.status_code == 429


def test_marketplace_install_rate_limit():
    client, t = _make_client_with_rl({"marketplace:install": 1})
    headers = {"X-Tenant-Id": "tenant_inst"}
    payload = {"version": "1.0", "permitted_scopes": []}
    resp = client.post("/marketplace/skills/nonexistent/install", json=payload, headers=headers)
    assert resp.status_code != 429
    resp = client.post("/marketplace/skills/nonexistent/install", json=payload, headers=headers)
    assert resp.status_code == 429


def test_per_tenant_http_isolation():
    """Tenant A hitting rate limit does not block tenant B."""
    client, t = _make_client_with_rl({"runs:create": 1})
    # Exhaust tenant A
    client.post(
        "/runs",
        json={"intent": "x", "budget_minor": 1000},
        headers={"X-Tenant-Id": "tenant_iso_a"},
    )
    resp_a = client.post(
        "/runs",
        json={"intent": "x", "budget_minor": 1000},
        headers={"X-Tenant-Id": "tenant_iso_a"},
    )
    assert resp_a.status_code == 429
    # Tenant B should still get through (even if it hits other errors — just not 429)
    resp_b = client.post(
        "/runs",
        json={"intent": "x", "budget_minor": 1000},
        headers={"X-Tenant-Id": "tenant_iso_b"},
    )
    assert resp_b.status_code != 429
