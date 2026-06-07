"""Egress proxy gateway (Phase 4).

External, side-effecting tool calls (restart a service, post to Slack, hit an API)
must pass through a governed proxy that enforces an egress allowlist and records
provenance. Internal/read-only tools bypass egress control but are still subject to
the upstream policy + lease authorization.

The gateway is intentionally simple and deterministic: it classifies a call by its
declared destination/tool and checks it against a configured allowlist. A denied
egress raises EgressDenied (which the sandbox surfaces as a governed failure, recorded
as evidence). This is the seam where a real network proxy / E2B egress filter plugs
in later.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch


class EgressDenied(RuntimeError):
    """Raised when an external call targets a non-allowlisted destination."""


@dataclass
class GatewayConfig:
    """Egress policy for external tool calls."""

    # Glob patterns of allowed external destinations, e.g. "slack.com", "*.internal".
    allow_destinations: list[str] = field(default_factory=list)
    # Tool names considered external/side-effecting (must pass egress checks).
    external_tools: list[str] = field(default_factory=list)
    # If True, any tool not explicitly internal is treated as external (safe default).
    deny_by_default: bool = True


class ProxyGateway:
    """Mediates external tool calls against an egress allowlist."""

    def __init__(self, config: GatewayConfig) -> None:
        self._config = config

    def is_external(self, tool: str) -> bool:
        return tool in self._config.external_tools

    def check(self, tool: str, destination: str | None) -> None:
        """Authorize an external call's destination. No-op for internal tools.

        Raises EgressDenied if an external call targets a destination that does not
        match any allowlist pattern.
        """
        if not self.is_external(tool):
            return
        if destination is None:
            if self._config.deny_by_default:
                raise EgressDenied(
                    f"external tool '{tool}' did not declare a destination"
                )
            return
        for pattern in self._config.allow_destinations:
            if fnmatch(destination, pattern):
                return
        raise EgressDenied(
            f"egress to '{destination}' for tool '{tool}' is not allowlisted"
        )
