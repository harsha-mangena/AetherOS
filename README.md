# AetherOS

**Trusted Execution Kernel for Enterprise AI Agents** — a hybrid Rust + Python +
Tauri/React system that makes autonomous AI agents safe, observable, and governable.

AetherOS gives every agent a cryptographic identity, scoped capability leases,
runtime budget and policy enforcement, hybrid memory, and a tamper-evident evidence
ledger — sitting on top of existing systems through the Model Context Protocol (MCP).
Every governance decision is cryptographically provable, every action is auditable,
and every deployment is Kubernetes-ready with Prometheus-native observability.

> Traditional operating systems manage processes for humans.
> AetherOS manages **intelligence and intent** for both humans and autonomous agents.

## Architecture (hybrid)

| Layer            | Technology          | Responsibility                                              |
|------------------|---------------------|-------------------------------------------------------------|
| Core primitives  | Rust                | Identity, capability leases, evidence ledger, policy        |
| Orchestration    | Python + LangGraph  | Intent compilation, task graphs, human checkpoints          |
| Interop          | PyO3                | Python ↔ Rust, byte-reproducible canonical serialization    |
| Sandbox          | Rust-controlled     | Secure code execution with governance hooks                 |
| Memory           | Hybrid (Rust + Py)  | Durable ledger in Rust, flexible RAG in Python              |
| UI               | Tauri + React       | Native desktop console, execution canvas, admin surfaces    |

## Repository layout

```
crates/aether-core      Rust core: identity, leases, evidence ledger, canonical hashing,
                        policy engine, earned-autonomy tiers
bindings/aether-py      PyO3 bindings + Pydantic models (the `aetheros` package)
python/                 Orchestration layer: intent compiler, governed engine, LangGraph,
                        hybrid memory, MCP adapters, sandbox, gateway, control-plane API
config/                 Config-driven defaults (zero-hardcoding)
config/alerting/        Prometheus recording + alerting rules (4 golden signals)
ui/                     Tauri + React desktop app (Intent Console, Execution Canvas,
                        Evidence Viewer, Governance Admin)
examples/               End-to-end Production Incident demo
docs/                   Architecture docs + committed OpenAPI 1.0 spec (openapi.json)
scripts/                Dev tooling: generate_openapi.py, run_desktop.sh
```

## Status

All 25 phases are implemented and tested end to end: **620 Python tests + Rust core
tests, all green**. API version 1.0.0, OpenAPI 3.1 spec committed at `docs/openapi.json`.

1.  **Foundations** — Rust core primitives, PyO3 bindings, Pydantic models, config,
    hybrid memory.
2.  **Orchestration** — intent compiler, governed engine, LangGraph human-in-the-loop
    graph.
3.  **Governance & Memory** — Rust-evaluated policy engine, runtime budgets, earned
    autonomy, policy-mediated durable memory.
4.  **MCP + Sandbox** — MCP adapters, all tool calls routed through the Rust governance
    gate then an egress-controlled sandbox with provenance, proxy gateway.
5.  **Desktop UI + Control Plane** — FastAPI control plane over a resumable run service,
    and a Tauri + React desktop app with four governance surfaces.
6.  **Hardening & Scale** — Multi-tenant workspace isolation, enterprise IdP onboarding,
    analytics dashboard, adaptive autonomy, pluggable sandbox backends.
7.  **Constitutional Governance & Compliance** — Inviolable agent constitutions in Rust,
    multi-agent collaboration with shared attributed ledgers, compliance attestation,
    agent capability marketplace with signed manifests.
8.  **Merkle Transparency Logs** — RFC 6962/9162 inclusion and consistency proofs over
    the evidence ledger, signed tree heads, compact audit trails for regulators.
9.  **Rate Limiting** — per-tenant token-bucket rate limiting on all governed tool calls,
    config-driven limits, `Retry-After` headers.
10. **Run-State Durability** — SQLite-backed run resumption across restarts, configurable
    persistence, snapshot/restore for in-flight runs.
11. **EdDSA Identities + JWKS** — per-tenant Ed25519 key pairs, JWKS endpoint
    (`/auth/jwks`), JWT issuance and verification, key rotation.
12. **JWT Revocation** — durable JWT revocation store (in-memory + SQLite), self-pruning
    jti+exp index, `/auth/revoke` endpoint.
13. **At-Rest Encryption** — AES-256-GCM envelope encryption for persisted run state via
    scrypt KDF; PKCS#8 PBES2 keystore.
14. **Key Rotation** — zero-downtime EdDSA key rotation, JWKS multi-key window, rotation
    event in the evidence ledger.
15. **Compliance Attestation** — signed compliance reports, constitution hash in
    attestation, `/compliance` endpoint.
16. **SIEM Audit Export** — OCSF-aligned `AuditEvent` schema, paginated
    `/audit/events` + `/audit/summary`, NDJSON export, Splunk HEC bridge.
17. **OpenTelemetry Tracing + Metrics** — OTEL Spec v1.27.0 distributed traces
    (`aetheros.run.advance`, `governance.authorize`, `tool.invoke`, `ledger.append`),
    8 metric instruments, `TracingConfig`.
18. **Log-Trace Correlation** — RFC 5424 structured logging, W3C Trace-Context
    `trace_id`/`span_id` injection into every log line, OTEL Logs Bridge.
19. **Health API** — `/health/live`, `/health/ready`, `/health/deep` (IETF draft-06);
    deep check validates ledger, keystore, run-state store connectivity.
20. **Prometheus Metrics Bridge** — `GET /metrics` in OpenMetrics v1.0.0 format; isolated
    `CollectorRegistry` for test safety; 8 OTEL instruments bridged to Prometheus.
21. **Admin Introspection API** — `/admin/runs`, `/admin/tenants/{id}/budget`,
    `/admin/policy/deny-rate`, `/admin/summary`; auth-gated, thread-safe locked reads.
22. **Graceful Shutdown** — `RunService.drain(timeout)` sets a drain flag; `advance()`
    checks it before each step; FastAPI lifespan calls `asyncio.to_thread(svc.drain)` on
    SIGTERM; every in-flight run gets a terminal `run.drain_halted` ledger entry.
23. **Prometheus Alerting Rules** — `config/alerting/rules.yml` ships 5 recording rules
    (deny rate, completion rate, p95 run duration, p99 step duration, budget throughput)
    and 6 alerting rules covering the 4 golden signals; served at `GET /config/alerting`.
24. **CI Hardening + OpenAPI 1.0 Contract** — full dependency matrix in
    `.github/workflows/ci.yml`; `scripts/generate_openapi.py --check` in CI (fails on
    schema drift); `docs/openapi.json` committed (43 paths, 3.1.0); API bumped to v1.0.0.
25. **Real-Time SSE Event Stream** — `GET /admin/events` streams CloudEvents v1.0.2
    JSON events (`aetheros.run.created`, `.step_completed`, `.halted`, `.completed`,
    `.approval_required`) via W3C Server-Sent Events; `EventBus` pub/sub,
    `diff_snapshots` differ, periodic heartbeats.

The full governed flow — intent → least-privilege plan → policy + lease authorization →
sandboxed execution with provenance → human approval gates → tamper-evident, replayable
evidence with cryptographic transparency proofs — is validated by **620 Python tests**
and Rust core tests, all green.

## Security & Compliance

- **Cryptographic identity**: every agent has an Ed25519 key pair; all tokens are EdDSA-signed JWTs.
- **At-rest encryption**: AES-256-GCM with scrypt KDF; PKCS#8 PBES2 keystore.
- **JWT revocation**: durable jti blocklist, self-pruning by expiry, O(1) lookup.
- **Constitutional governance**: inviolable Rust-enforced agent constitutions; no Python override path.
- **Merkle transparency**: RFC 6962/9162 inclusion and consistency proofs; signed tree heads.
- **SIEM export**: OCSF-aligned NDJSON at `/audit/events`; Splunk HEC bridge; paginated.
- **Compliance attestation**: signed reports with constitution hash at `/compliance`.

## Observability

- **Distributed traces**: OTEL Spec v1.27.0 spans with `aetheros.*` attributes on every governed step.
- **Metrics**: 8 OTEL instruments (runs started/completed/halted, policy denied, tool invoked, budget spent, duration histograms) scraped at `GET /metrics` in OpenMetrics format.
- **Log-trace correlation**: W3C `trace_id` + `span_id` stamped into every structured log line.
- **Health probes**: `/health/live` (liveness), `/health/ready` (readiness), `/health/deep` (connectivity).
- **Real-time event stream**: `GET /admin/events` SSE (CloudEvents v1.0.2).
- **Admin snapshots**: `/admin/runs`, `/admin/tenants/{id}/budget`, `/admin/policy/deny-rate`, `/admin/summary`.
- **Alerting rules**: pre-built Prometheus recording + alerting rules at `config/alerting/rules.yml`.

## Quick start

Prerequisites: Rust stable, Python 3.10+, [`uv`](https://docs.astral.sh/uv/),
[`maturin`](https://www.maturin.rs/), Node 20+ (UI only).

```bash
# Set up the Python environment and build the native extension
make setup        # create .venv, install all deps, build Rust extension

# Run all tests (Rust core + Python suite)
make test         # 620 Python tests + Rust tests

# Regenerate or verify the committed OpenAPI spec
make spec         # regenerate docs/openapi.json
make check-spec   # fail if docs/openapi.json is stale (runs in CI)
```

## Running the control-plane API

```bash
# Start the FastAPI control plane on port 8765
.venv/bin/uvicorn aetheros_orchestrator.api:app --reload --port 8765

# Or use the desktop launcher (API + React UI on http://localhost:5173)
./scripts/run_desktop.sh
```

Key environment variables (all have config-file defaults; override via `AETHER__*` env vars):

```
AETHER__AUTH__ENABLED=true          # enable JWT auth (default: false in dev)
AETHER__AUTH__ADMIN_SECRET=<secret> # required when auth is enabled
AETHER__STORAGE__PERSIST_RUNS=true  # enable SQLite run-state persistence
AETHER__TRACING__ENABLED=true       # enable OTEL distributed tracing
AETHER__PROMETHEUS__ENABLED=true    # enable /metrics endpoint
```

## API surface

The OpenAPI 3.1 spec is committed at `docs/openapi.json` (43 paths). Key groups:

| Group | Endpoints | Description |
|---|---|---|
| `/runs` | 9 | Create, advance, resume, cancel, delete runs; evidence; approvals |
| `/auth` | 6 | Token issuance, revocation, JWKS, key rotation |
| `/health` | 5 | Live, ready, deep health probes |
| `/admin` | 5 | Runs list, budget, deny-rate, summary, SSE event stream |
| `/audit` | 2 | SIEM-ready NDJSON event export and summary |
| `/config` | 3 | Policy, constitution, Prometheus alerting rules |
| `/metrics` | 1 | OpenMetrics/Prometheus scrape endpoint |
| `/collaborations` | 4 | Multi-agent collaboration sessions |
| `/marketplace` | 4 | Agent capability marketplace |

## Kubernetes deployment

```yaml
# Minimal production pod spec additions
spec:
  containers:
    - name: aetheros
      livenessProbe:
        httpGet: { path: /health/live, port: 8765 }
        initialDelaySeconds: 5
        periodSeconds: 10
      readinessProbe:
        httpGet: { path: /health/ready, port: 8765 }
        initialDelaySeconds: 3
        periodSeconds: 5
      # Allow graceful drain of in-flight runs on SIGTERM (default drain: 30s)
  terminationGracePeriodSeconds: 35
  # Prometheus scraping
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/path: "/metrics"
    prometheus.io/port: "8765"
```

Add the alerting rules to Prometheus:
```yaml
# prometheus.yml
rule_files:
  - /path/to/aetheros/config/alerting/rules.yml
```

## Development

```bash
# Format Rust code
make fmt

# Lint Rust (clippy -D warnings)
make lint

# Run only Python tests
make test-py

# Run only Rust tests
make test-rust
```

Direct Rust test run:
```bash
cargo test -p aether-core
```

## Run the demo

Headless end-to-end governed run (no GUI):

```bash
python examples/incident_demo.py
```

Full desktop experience (control-plane API + React UI):

```bash
./scripts/run_desktop.sh      # starts the API, then the UI on http://localhost:5173
```

## License

Apache-2.0. See `LICENSE`.
