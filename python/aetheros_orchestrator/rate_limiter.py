"""Per-tenant, per-route sliding-window rate limiter — Phase 17.

Design
──────
AetherOS exposes a FastAPI control-plane API. Without enforced rate limits, any
caller can flood ``POST /runs``, ``POST /auth/token``, or any other endpoint without
bound, undermining every prior security layer (auth, leases, governance). Phase 17
closes OWASP API Security Top 10 2023 API4: "Unrestricted Resource Consumption".

Algorithm: sliding-window counter (Cloudflare, 2020)
─────────────────────────────────────────────────────
A true sliding-window log is accurate but O(n) per key (one timestamp per request).
A fixed-window counter is O(1) but allows bursting at window boundaries. The
sliding-window *counter* blends both:

    estimated_rate = prev_window_count × (1 − elapsed / window_size)
                   + curr_window_count

where ``elapsed`` is how far into the current window the request arrives. This
produces at most ~0.4% error vs. the true sliding window (proven by Cloudflare),
is O(1) per key (only two counters per window period per key), and is fully
deterministic and testable with a fake clock.

Key space: ``(key, window_index)`` where ``key = f"{tenant_id}:{route_key}"`` and
``window_index = floor(now / window_seconds)``. Only two window indices are ever
live per key; older entries are inert and pruned lazily.

HTTP semantics: RFC 6585 §4 — 429 Too Many Requests with a ``Retry-After`` header
(integer seconds until the current window closes and count resets).

Config: per-route limits in ``RateLimitConfig.route_limits`` (a dict mapping route
key → max requests per window). A ``default_limit`` applies to any route not in the
map. Setting a limit to 0 disables rate limiting for that route. When the master
``enabled`` flag is False (the default) the limiter is a transparent no-op so all
prior tests pass unchanged.

References
──────────
* RFC 6585 §4 — 429 Too Many Requests, Retry-After.
* Cloudflare blog (2020) — "How we built rate limiting capable of scaling to
  millions of domains": the sliding-window counter formula and its accuracy proof.
* OWASP API Security Top 10 2023 — API4: Unrestricted Resource Consumption.
"""
from __future__ import annotations

import math
import threading
import time
from collections import defaultdict
from typing import Callable


class RateLimitExceeded(Exception):
    """Raised when a request exceeds the configured rate limit.

    Attributes
    ----------
    retry_after : int
        Seconds until the current window closes and the counter resets.
        Callers should surface this as the ``Retry-After`` HTTP header.
    limit : int
        The configured maximum requests per window for this key.
    window_seconds : int
        The window duration in seconds.
    """

    def __init__(self, retry_after: int, limit: int, window_seconds: int) -> None:
        self.retry_after = retry_after
        self.limit = limit
        self.window_seconds = window_seconds
        super().__init__(
            f"rate limit {limit} req/{window_seconds}s exceeded; retry after {retry_after}s"
        )


class RateLimiter:
    """Thread-safe sliding-window counter rate limiter.

    Parameters
    ----------
    window_seconds:
        Duration of one rate-limiting window (e.g. 60 for per-minute limits).
    default_limit:
        Maximum requests per window for routes not in ``route_limits``.
        0 = disabled (no limiting) for that route.
    route_limits:
        Per-route overrides: mapping of route key → max requests per window.
        An absent key falls back to ``default_limit``.  0 = disabled.
    clock:
        Callable returning the current time as a float (seconds since epoch).
        Defaults to ``time.time``.  Injected in tests for determinism.
    """

    def __init__(
        self,
        window_seconds: int = 60,
        default_limit: int = 0,
        route_limits: dict[str, int] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._window = window_seconds
        self._default_limit = default_limit
        self._route_limits: dict[str, int] = route_limits or {}
        self._clock = clock or time.time
        # _counts[key][window_index] = count
        self._counts: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))
        self._lock = threading.Lock()

    # ── public API ────────────────────────────────────────────────────────────

    def check_and_increment(self, tenant_id: str, route_key: str) -> None:
        """Record a request and raise ``RateLimitExceeded`` if the limit is breached.

        Call this at the start of each request handler.  On success the request
        count is incremented (the request is counted whether it proceeds or not).
        On failure ``RateLimitExceeded`` is raised *before* the count is
        incremented — matching the semantics of most production rate limiters
        (a rejected request does not consume quota).

        Parameters
        ----------
        tenant_id:
            The requesting tenant.  Each tenant has an independent counter so a
            single high-volume tenant cannot crowd out others.
        route_key:
            A short string identifying the route being called (e.g. ``"runs:create"``).
            This is the key into ``route_limits``.
        """
        limit = self._route_limits.get(route_key, self._default_limit)
        if limit == 0:
            return  # rate limiting disabled for this route

        now = self._clock()
        window_idx = math.floor(now / self._window)
        elapsed = now - window_idx * self._window

        key = f"{tenant_id}:{route_key}"

        with self._lock:
            curr = self._counts[key][window_idx]
            prev = self._counts[key].get(window_idx - 1, 0)

            # Cloudflare sliding-window estimate
            estimated = prev * (1.0 - elapsed / self._window) + curr

            if estimated >= limit:
                retry_after = math.ceil(self._window - elapsed)
                raise RateLimitExceeded(
                    retry_after=max(retry_after, 1),
                    limit=limit,
                    window_seconds=self._window,
                )

            # Count the accepted request
            self._counts[key][window_idx] += 1

            # Lazy prune: remove any windows older than previous (keep current + prev only)
            old_keys = [w for w in self._counts[key] if w < window_idx - 1]
            for w in old_keys:
                del self._counts[key][w]

    def get_count(self, tenant_id: str, route_key: str) -> float:
        """Return the estimated current request rate for a (tenant, route) pair.

        Returns the same sliding-window estimate used by ``check_and_increment``,
        without incrementing or raising.  Useful for monitoring and tests.
        """
        limit = self._route_limits.get(route_key, self._default_limit)
        if limit == 0:
            return 0.0

        now = self._clock()
        window_idx = math.floor(now / self._window)
        elapsed = now - window_idx * self._window

        key = f"{tenant_id}:{route_key}"
        with self._lock:
            curr = self._counts[key][window_idx]
            prev = self._counts[key].get(window_idx - 1, 0)
        return prev * (1.0 - elapsed / self._window) + curr
