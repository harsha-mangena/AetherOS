"""Config-driven design for AetherOS (zero-hardcoding principle).

All tunable behavior is loaded from `config/default.yaml`, validated by Pydantic
models, and overridable via environment variables prefixed `AETHER__` with double
underscores marking nesting (e.g. `AETHER__GOVERNANCE__DEFAULT_BUDGET_MINOR=50000`).
Code reads typed config objects rather than embedding constants.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

ENV_PREFIX = "AETHER__"


class CoreConfig(BaseModel):
    default_currency: str = "USD"
    ledger_hash: str = "sha256"


class IdentityConfig(BaseModel):
    timezone: str = "UTC"


class GovernanceConfig(BaseModel):
    default_lease_ttl_seconds: int = 3600
    default_budget_minor: int = 10_000
    require_human_approval: bool = True
    high_impact_scopes: list[str] = Field(default_factory=list)


class MemoryConfig(BaseModel):
    ephemeral_max_entries: int = 200
    durable_namespace: str = "org"


class EvidenceConfig(BaseModel):
    ledger_path: str = "data/evidence.ledger"


class OrchestrationConfig(BaseModel):
    max_plan_steps: int = 25
    default_model: str = "configured-by-runtime"


class PolicyRuleConfig(BaseModel):
    id: str
    effect: str = "allow"
    scope: str | None = None
    tool: str | None = None
    min_autonomy_tier: int | None = None
    max_cost_minor: int | None = None
    priority: int = 0


class PolicyConfig(BaseModel):
    default_allow: bool = False
    require_approval_for_high_impact: bool = True
    rules: list[PolicyRuleConfig] = Field(default_factory=list)


class ArticleConfig(BaseModel):
    """One constitutional article: an inviolable principle and the actions it governs."""

    id: str
    principle: str
    verdict: str = "forbid"  # "forbid" | "require_approval"
    scope: str | None = None
    tool: str | None = None
    high_impact: bool | None = None
    min_cost_minor: int | None = None


class ConstitutionConfig(BaseModel):
    """The supreme governance layer: articles evaluated above policy in the Rust core."""

    version: str = "v0"
    articles: list[ArticleConfig] = Field(default_factory=list)


class AutonomyConfig(BaseModel):
    promotion_threshold: int = 5
    max_tier: int = 3


class TransparencyConfig(BaseModel):
    """Witness-cosigning panel for split-view (equivocation) defense.

    A panel of ``witness_count`` independent witnesses cosigns each Signed Tree Head.
    A cosigned head is publicly trustworthy once at least ``witness_threshold``
    distinct witnesses endorse it. ``witness_threshold = 0`` selects a strict
    majority at runtime (the smallest panel no single equivocation fools).
    """

    witness_count: int = 3
    # 0 → strict majority (n // 2 + 1) computed from witness_count at construction.
    witness_threshold: int = 0


class StorageConfig(BaseModel):
    """Ledger durability backend (Phase 10).

    Controls whether run evidence ledgers are persisted to SQLite so that they
    survive service restarts. When ``backend = "none"`` (default) ledgers remain
    in-memory only — the current MVP behavior, backward-compatible with all prior
    tests. When ``backend = "sqlite"`` each run's canonical ledger JSON is written
    to ``db_dir`` after every append and restored via ``EvidenceLedger.from_json``
    on startup, which re-verifies the hash chain atomically.
    """

    # "none" | "sqlite"
    backend: str = "none"
    # Directory for SQLite databases (one file per tenant, keyed by tenant_id).
    db_dir: str = "./ledgers"

    # ── Run-state durability (Phase 13) ──────────────────────────────────────
    # Whether the resumable RunService run state (status, cursor, pending approval
    # gate, results, and the signed lease + agent identities that hold the run's
    # authority) is persisted to SQLite so in-flight governed runs — including those
    # paused at a human approval gate — survive a service restart. When False (the
    # default) run state lives in memory only, identical to pre-Phase-13 behavior
    # and backward-compatible with all prior tests. The evidence ledger durability
    # above is independent; enabling persist_runs without backend="sqlite" persists
    # the run scalars + lease but restores ledgers as fresh (use both together for a
    # fully durable run).
    persist_runs: bool = False
    # Directory for the per-tenant run-state SQLite databases.
    run_state_db_dir: str = "./run_states"

    # ── At-rest encryption (Phase 16) ─────────────────────────────────────────
    # Operator passphrase for AES-256-GCM at-rest encryption of secrets stored in
    # SQLite and on-disk PEM files. When non-empty, ``state_json`` blobs persisted
    # by ``RunStateStore`` (which contain Ed25519 seed_hex values) and per-tenant
    # Ed25519 PKCS#8 PEM files written by ``TenantKeyStore`` are encrypted with an
    # authenticated envelope (AES-256-GCM, scrypt KDF — NIST SP 800-38D, RFC 7914).
    # Empty string (the default) = plaintext mode — byte-for-byte identical to all
    # prior phases; no existing test requires modification.
    # Set via AETHER__STORAGE__ENCRYPTION_PASSPHRASE env var in production.
    encryption_passphrase: str = ""


class AuthConfig(BaseModel):
    """API authentication configuration (Phase 12).

    When ``enabled = False`` (the default) the control plane operates without
    authentication — identical to all prior behavior, so no existing test needs
    modification. When ``enabled = True`` every protected endpoint requires a
    valid Bearer JWT in the ``Authorization`` header.

    Tokens are signed with HMAC-SHA256 (HS256, RFC 7519). The server holds one
    shared secret (``secret``); clients exchange ``tenant_id`` + ``admin_secret``
    at ``POST /auth/token`` and receive a signed JWT carrying ``sub = tenant_id``.
    The admin secret is a separate config value that controls who may issue tokens.

    Zero-hardcoding: change ``auth.secret`` in ``config/default.yaml`` or via the
    ``AETHER__AUTH__SECRET`` environment variable before any networked deployment.
    """

    # Master switch. False = pass-through (backward-compatible with all tests).
    enabled: bool = False
    # Token signing algorithm. Phase 12 "HS256" (shared HMAC secret) remains the
    # default for full backward-compatibility. Phase 14 adds "EdDSA": asymmetric
    # per-tenant Ed25519 tokens (RFC 8037) where each tenant has its own keypair,
    # so a compromised verifier key for one tenant cannot forge another tenant's
    # token, and public keys can be published (JWKS) for offline verification.
    algorithm: str = "HS256"
    # HMAC-SHA256 signing secret (HS256 only). Must be ≥ 32 bytes in production.
    secret: str = "change-me-before-production-at-least-32-bytes!!"
    # Separate secret required at POST /auth/token to receive a JWT.
    admin_secret: str = "admin-change-me"
    # JWT lifetime in seconds (default: 1 hour).
    token_ttl_seconds: int = 3600
    # Directory for the per-tenant Ed25519 keystore (EdDSA only). Each tenant's
    # private key is generated on first issuance and persisted here so issued
    # tokens stay verifiable across restarts. Empty string = ephemeral in-memory
    # keystore (keys regenerated each process start — test/dev only).
    token_keystore_dir: str = ""
    # Directory for the durable JWT revocation store (Phase 15). When set, revoked
    # token IDs (jti) are persisted to SQLite with their expiry, so a revoked token
    # stays revoked across a restart and the denylist self-prunes once entries pass
    # their own exp. Empty string = in-memory revocation only (lost on restart —
    # identical to Phase 12/14 behaviour, the default).
    revocation_store_dir: str = ""
    # At-rest encryption passphrase for the per-tenant Ed25519 keystore PEM files
    # (Phase 16). When non-empty, each tenant's PKCS#8 PEM file is written with
    # PBES2 encryption (BestAvailableEncryption — RFC 8018 §6.2). Empty string =
    # plaintext PEM, byte-for-byte identical to Phase 14/15. Set via
    # AETHER__AUTH__KEYSTORE_PASSPHRASE env var in production.
    keystore_passphrase: str = ""


class GatewayConfigModel(BaseModel):
    allow_destinations: list[str] = Field(default_factory=list)
    external_tools: list[str] = Field(default_factory=list)
    deny_by_default: bool = True


class SandboxConfig(BaseModel):
    backend: str = "local"
    timeout_seconds: float = 10.0
    # Map of tool name -> external destination (used for egress checks).
    tool_destinations: dict[str, str] = Field(default_factory=dict)
    gateway: GatewayConfigModel = Field(default_factory=GatewayConfigModel)


class ShutdownConfig(BaseModel):
    """Graceful shutdown configuration (Phase 23).

    When the service receives SIGTERM (via uvicorn's lifespan shutdown event),
    it sets a drain flag on RunService so advance() halts any in-flight run
    with a terminal ledger entry before the process exits. This guarantees
    no run is silently lost on a rolling restart.

    drain_timeout_seconds: max seconds to wait for in-flight runs to reach
    a terminal state. Kubernetes default terminationGracePeriodSeconds is 30s.
    Zero-hardcoding: override via AETHER__SHUTDOWN__* env vars.
    """
    drain_timeout_seconds: int = 30


class EventStreamConfig(BaseModel):
    """Real-time SSE event stream configuration (Phase 25).

    poll_interval_seconds: how often the SSE generator polls RunService for
      state changes. Lower values = lower latency but more CPU.
    heartbeat_interval_seconds: how often to send keepalive events to prevent
      proxies from closing idle connections. Standard: 15-30s.
    max_subscribers: maximum concurrent SSE connections (0 = unlimited).
    """

    poll_interval_seconds: float = 0.1
    heartbeat_interval_seconds: int = 15
    max_subscribers: int = 0  # 0 = unlimited; enforce in Phase 26


class PrometheusConfig(BaseModel):
    """Prometheus metrics exposition configuration (Phase 22).

    When enabled = True, GET /metrics exposes all OTEL instruments as
    Prometheus text format (OpenMetrics v1.0.0). The PrometheusMetricReader
    bridges the opentelemetry-sdk MeterProvider to prometheus_client.

    When enabled = False (default), /metrics returns HTTP 404.
    Zero-hardcoding: override via AETHER__PROMETHEUS__* env vars.
    """

    enabled: bool = False
    # Optional metric name prefix for all instruments (e.g. "aetheros_").
    # Empty string = no prefix, instruments use their natural names.
    prefix: str = ""


class HealthConfig(BaseModel):
    """Health endpoint configuration (Phase 21).

    Controls the /health/live, /health/ready, /health/deep probes.
    When enabled = False (default), health endpoints still respond but return
    minimal information — no dependency checks that could leak internal topology.
    When enabled = True, /health/ready and /health/deep perform real dependency checks.
    """

    enabled: bool = True
    # Whether /health/deep performs ledger chain integrity verification.
    deep_checks: bool = True


class TracingConfig(BaseModel):
    """OpenTelemetry tracing and metrics configuration (Phase 20).

    Controls distributed tracing for the governed execution engine. When
    ``enabled = False`` (the default) all tracing calls are no-ops — zero
    overhead, zero imports in callers, all 461 prior tests unaffected.

    When ``enabled = True``, ``TracedGovernedEngine`` emits spans for each
    governance stage (authorize, tool.invoke, ledger.append) with attributes
    including tenant_id, run_id, step_id, tool, scope, cost_minor. A root span
    ``aetheros.run.advance`` wraps each governed run.

    Exporter types:
      ``none``    — spans are created and immediately discarded (useful for
                    testing instrumentation code paths without export overhead).
      ``console`` — spans are printed to stdout (development / debugging).
      ``otlp``    — spans exported via OTLP/gRPC to Jaeger, Grafana Tempo,
                    Datadog Agent, or any OTEL-compatible backend.

    Zero-hardcoding: override via AETHER__TRACING__* env vars.
    """

    # Master switch. False = no-op tracing (backward-compatible default).
    enabled: bool = False
    # Exporter backend. "none" | "console" | "otlp"
    exporter_type: str = "none"
    # OTLP/gRPC endpoint (only used when exporter_type = "otlp").
    # Default: standard OTEL collector port on localhost.
    otlp_endpoint: str = "http://localhost:4317"


class AuditConfig(BaseModel):
    """Structured audit-log export configuration (Phase 19).
    (the default) the ``GET /audit/events`` and ``GET /audit/summary`` endpoints
    return HTTP 403 and behavior is identical to all prior phases.

    When ``enabled = True`` the endpoints expose paginated, filterable audit
    events derived from the evidence ledger — suitable for ingestion by Splunk,
    Datadog, Elastic, Azure Sentinel, or any NDJSON-capable log aggregator.

    Schema follows OCSF (Open Cybersecurity Schema Framework v1.0, CISA 2022)
    field conventions: ``time_iso``, ``event_type``, ``actor``, ``tenant_id``,
    ``run_id``, ``seq``, ``entry_hash``, ``prev_hash``, ``payload``.

    Zero-hardcoding: override via AETHER__AUDIT__* env vars.
    """

    # Master switch. False = no audit export endpoints (backward-compatible default).
    enabled: bool = False
    # Maximum events per page. Requests asking for more are silently capped.
    max_page_size: int = 1000


class KeyRotationConfig(BaseModel):
    """Key rotation configuration (Phase 18).
    keys. When ``enabled = False`` (the default) no rotation endpoints are exposed
    and behavior is identical to Phase 14/15/16. When ``enabled = True`` the
    POST /auth/keys/{tenant_id}/rotate endpoint is available to operators.

    Algorithm: ACTIVE → RETIRING → EXPIRED state machine (NIST SP 800-57 Part 1
    Rev 5 §5.3 / §5.3.5). An ACTIVE key signs new tokens. On rotation it moves to
    RETIRING — it still verifies tokens issued before the rotation, but never signs
    again. After ``overlap_ttl_seconds`` passes (enough time for all pre-rotation
    tokens to expire naturally), the key moves to EXPIRED and is omitted from the
    JWKS so downstream verifiers no longer accept tokens signed with it.

    Zero-hardcoding: override via AETHER__KEY_ROTATION__* env vars.
    """

    # Master switch. False = no rotation endpoints (backward-compatible default).
    enabled: bool = False
    # Overlap window: how long a RETIRING key remains verifiable after rotation.
    # Should be >= auth.token_ttl_seconds so no valid token is rejected mid-flight.
    # Default: 3600 s (1 hour), matching the default token TTL.
    overlap_ttl_seconds: int = 3600


class RateLimitConfig(BaseModel):
    """Per-route rate limiting configuration (Phase 17).

    Controls the sliding-window counter rate limiter applied to every inbound
    request on the control-plane API. When ``enabled = False`` (the default) the
    limiter is a transparent no-op — identical to all prior behavior, so no
    existing test requires modification.

    Algorithm: sliding-window counter (Cloudflare 2020) — accurate to within
    ~0.4% of a true sliding window, O(1) per key. Two counters (previous window
    + current window) derive a weighted rate estimate:
        estimated_rate = prev × (1 − elapsed/window) + curr
    If estimated_rate >= limit, the request is rejected with HTTP 429 and a
    ``Retry-After`` header (RFC 6585 §4).

    Per-route limits override the default for specific endpoint categories.
    Setting a limit to 0 disables rate limiting for that category.

    Zero-hardcoding: override any value via AETHER__RATE_LIMIT__* env vars.
    """

    # Master switch. false = transparent no-op (default, backward-compatible).
    enabled: bool = False
    # Rate-limit window duration in seconds.
    window_seconds: int = 60
    # Default max requests per window for routes not in route_limits.
    # 0 = disabled (no limiting).
    default_limit: int = 0
    # Per-route overrides (route_key -> max requests per window).
    # Route keys used in Phase 17:
    #   "runs:create"       POST /runs
    #   "runs:advance"      POST /runs/{id}/advance
    #   "auth:token"        POST /auth/token
    #   "auth:revoke"       POST /auth/revoke
    #   "marketplace:publish"  POST /marketplace/skills
    #   "marketplace:install"  POST /marketplace/skills/{id}/install
    # 0 = disabled for that route.
    route_limits: dict = Field(default_factory=dict)


class AetherConfig(BaseModel):
    """Top-level validated configuration for AetherOS."""

    core: CoreConfig = Field(default_factory=CoreConfig)
    identity: IdentityConfig = Field(default_factory=IdentityConfig)
    governance: GovernanceConfig = Field(default_factory=GovernanceConfig)
    memory: MemoryConfig = Field(default_factory=MemoryConfig)
    evidence: EvidenceConfig = Field(default_factory=EvidenceConfig)
    orchestration: OrchestrationConfig = Field(default_factory=OrchestrationConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    constitution: ConstitutionConfig = Field(default_factory=ConstitutionConfig)
    autonomy: AutonomyConfig = Field(default_factory=AutonomyConfig)
    transparency: TransparencyConfig = Field(default_factory=TransparencyConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    shutdown: ShutdownConfig = Field(default_factory=ShutdownConfig)
    event_stream: EventStreamConfig = Field(default_factory=EventStreamConfig)
    prometheus: PrometheusConfig = Field(default_factory=PrometheusConfig)
    health: HealthConfig = Field(default_factory=HealthConfig)
    tracing: TracingConfig = Field(default_factory=TracingConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    key_rotation: KeyRotationConfig = Field(default_factory=KeyRotationConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)


def _default_config_path() -> Path:
    """Locate `config/default.yaml` by walking up from this file."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "config" / "default.yaml"
        if candidate.exists():
            return candidate
    raise FileNotFoundError("config/default.yaml not found in any parent directory")


def _coerce(value: str) -> Any:
    """Coerce an environment string into bool/int/float/str."""
    low = value.lower()
    if low in ("true", "false"):
        return low == "true"
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


def _apply_env_overrides(data: dict[str, Any]) -> dict[str, Any]:
    """Apply AETHER__SECTION__KEY environment overrides onto a config dict."""
    for env_key, env_val in os.environ.items():
        if not env_key.startswith(ENV_PREFIX):
            continue
        path = env_key[len(ENV_PREFIX) :].lower().split("__")
        cursor = data
        for part in path[:-1]:
            cursor = cursor.setdefault(part, {})
            if not isinstance(cursor, dict):
                break
        else:
            cursor[path[-1]] = _coerce(env_val)
    return data


def load_config(path: str | Path | None = None) -> AetherConfig:
    """Load and validate AetherOS configuration.

    Reads `config/default.yaml` (or `path`), applies environment overrides, and
    returns a validated `AetherConfig`.
    """
    config_path = Path(path) if path else _default_config_path()
    with open(config_path, "r", encoding="utf-8") as fh:
        data: dict[str, Any] = yaml.safe_load(fh) or {}
    data = _apply_env_overrides(data)
    return AetherConfig.model_validate(data)
