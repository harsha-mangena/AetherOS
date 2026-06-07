# AetherOS Architecture Overview

This document records the design reasoning behind AetherOS and the structure of the
codebase. It is updated phase by phase.

## Thesis

Enterprises adopting AI agents face an identity crisis (agents inherit broad human
or service credentials), a lack of enforced runtime controls (budgets and policies
are advisory), poor observability (logs without replayable evidence), and a trust
gap. AetherOS is the missing infrastructure layer: a trusted execution and
governance kernel that turns agents into first-class, accountable computational
citizens.

## Why hybrid (Tree of Thoughts)

Three branches were considered:

- **Pure Python** — fastest to build, weakest long-term security/performance moat.
- **Pure Rust** — excellent technically, significantly slower for complex agent
  logic and LLM orchestration.
- **Hybrid (chosen)** — Rust for the security- and integrity-critical core
  (identity, leases, evidence ledger, policy enforcement); Python + LangGraph for
  orchestration and agent logic; Tauri + React for a professional desktop UI.

The hybrid branch is the only one that gives both a defensible moat and a credible
9–10 week MVP.

## Core primitives (Phase 1)

Decomposed to their smallest units (Atom of Thoughts):

### AgentIdentity
`AgentIdentity = agent_id (UUIDv4) + display_name + created_at + Ed25519 keypair`.
The private signing key stays in Rust. Public callers get an `AgentDescriptor`
(agent_id, name, public key, fingerprint = first 16 bytes of SHA-256(pubkey)).

### CapabilityLease
`CapabilityLease = lease_id + subject_agent_id + issuer_agent_id + scopes (set) +
budget (currency + limit_minor + spent_minor) + issued_at + expires_at + revoked +
Ed25519 signature(issuer) over canonical(body)`.

The signature binds every field of the lease body, so widening scopes, raising the
budget, or extending expiry invalidates the lease. Authorization is a single check:
signature valid AND not revoked AND not expired AND scope granted AND budget
affordable. Budgets use integer minor units (cents) to avoid floating-point drift.

### EvidenceLedger
Append-only, hash-chained audit trail.
`entry_hash = SHA-256( prev_hash_bytes || canonical(content) )`, genesis prev_hash is
64 zero hex chars. Verification walks the chain; any edit, insertion, deletion, or
reorder is detected. The ledger is the replayable record of what agents planned,
accessed, changed, and spent.

### Canonical serialization
Both signing and hashing go through a deterministic canonical JSON form (recursively
sorted object keys, compact separators, deterministic string escaping). This is what
makes Rust and Python agree byte-for-byte, so a lease signed in Rust verifies in
Python and a ledger built in Python verifies in Rust.

### Cryptographic choices (revalidation)
- **Signatures: Ed25519** (`ed25519-dalek`) — fast, deterministic, widely deployed.
- **Hash: SHA-256** (`sha2`) — chosen over faster modern hashes because the evidence
  ledger is an enterprise audit artifact that benefits from a FIPS-friendly,
  broadly-audited primitive.

## Interop

PyO3 exposes the core as a native extension (`aetheros._aether_native`) wrapped by an
ergonomic Python package (`aetheros`) with Pydantic models. Errors map to Python
`ValueError`/`RuntimeError`; high-level wrappers raise `LeaseDenied` /
`LedgerIntegrityError`.

## Config-driven design

All tunable behavior lives in `config/default.yaml`, validated by Pydantic, and
overridable via `AETHER__SECTION__KEY` environment variables. Code reads typed config
objects; there are no magic constants embedded in logic.

## Orchestration (Phase 2)

The orchestration layer compiles natural-language intent into a governed, auditable
plan and executes it under the Rust core.

- Intent compiler runs a pluggable planner and produces a validated `ExecutionPlan`.
  Config-driven high-impact scope patterns are authoritative over the planner: a step
  touching a write/restart/deploy scope is forced high-impact even if the planner
  disagrees. An `intent.submitted` evidence event anchors the run.
- Planners are decoupled from any model: `RuleBasedPlanner` (deterministic, offline,
  drives the incident demo and all tests) and `LLMPlanner` (wraps an injectable
  completion callable, strictly validates JSON structured output before any step
  executes). The governed-execution core never depends on an LLM or network.
- Governance bridge (`GovernanceContext`) is the PyO3 seam: it issues a
  least-privilege lease scoped to exactly the plan's scopes, and every step passes
  through the Rust lease's `authorize` (signature + revocation + expiry + scope +
  budget) and, on success, charges the Rust-tracked budget and appends evidence.
  Python makes no authorization decision itself.
- Execution: a framework-agnostic `GovernedEngine` defines the canonical
  governed-execution semantics (approval gate, authorize, execute, charge, record).
  A LangGraph `StateGraph` wraps the same primitives, adding durable checkpointing
  and `interrupt`-based human-in-the-loop approval for high-impact steps. Keeping the
  engine framework-free is deliberate — the moat must not depend on a third-party
  runtime.

### Revalidation: signed budget limit vs runtime spend

A bug surfaced in Phase 2 testing: the original lease signed the entire budget
including `spent_minor`, so the signature failed to verify the instant any budget was
consumed. Fixed by splitting a signed `BudgetLimit` (currency + limit) inside the
lease body from runtime `spent_minor`/`revoked` state on the lease itself. The issuer
signs the limit; the holder tracks spend. A regression test
(`signature_still_verifies_after_spend`) locks this in.

## Governance & Hybrid Memory (Phase 3)

Governance moves from advisory to enforced, and memory becomes policy-mediated.

- Hybrid policy engine: the integrity-critical decision function lives in Rust
  (`policy.rs`) — given an ordered rule set and a fully-resolved request it computes
  allow/deny with deny-overrides and default-deny, matching scope/tool via a small
  dependency-free glob matcher, and gating rules by minimum earned-autonomy tier and
  cost ceilings. Rule authoring/loading from config is Python-side; the decision is
  not. Orchestration cannot bypass it.
- Earned autonomy: `autonomy.rs` owns each agent's tier (0..max). Consecutive
  successful governed runs promote at a configured threshold; any violation (a policy
  denial of an attempted action) demotes a tier and resets the streak. Tiers gate
  which actions policy will permit — a fresh agent cannot restart production infra
  until it has earned trust.
- Step authorization now requires BOTH the Rust policy engine AND the Rust lease to
  allow. Policy runs first (is this action class permitted for this tier?), then the
  lease (does this specific agent hold the scope, budget, and a valid grant?). A
  policy denial is recorded as an autonomy violation and emits `policy.denied`.
- Durable, policy-mediated memory (`durable_memory.py`): organizational records each
  carry a sensitivity scope. Every read/write is authorized two ways — the acting
  lease must grant the record's scope (least privilege) AND policy must allow the
  memory action — and every access emits evidence. Records are content-addressed with
  the same canonical SHA-256 as the ledger, so tampering is detectable on read.

## MCP + Sandbox (Phase 4)

Tool execution becomes MCP-native and sandbox-controlled, with the governance gate
strictly upstream of execution.

- MCP adapters (`mcp_adapter.py`): an `MCPAdapter` interface (`list_tools` /
  `call_tool`) the engine depends on. `MockMCPAdapter` exposes the incident toolset
  in-process for hermetic tests and the offline demo; `StdioMCPServerConfig` is the
  config seam for launching a real MCP server via the official SDK without changing
  callers. AetherOS governs MCP calls; it does not replace MCP.
- Egress proxy gateway (`gateway.py`): external, side-effecting tools must declare a
  destination that matches a configured glob allowlist; anything else raises
  `EgressDenied`. Internal/read-only tools bypass egress control but remain subject to
  the upstream policy + lease gate. Deny-by-default for undeclared external calls.
- Sandbox controller (`sandbox.py`): every governed tool call runs inside a
  `SandboxController`. `LocalSandbox` adds a wall-clock timeout guard, routes external
  calls through the gateway, and emits a content-addressed (canonical SHA-256)
  `ProvenanceRecord`. The backend is pluggable (native-process / E2B drop in via
  config). Authorization is NOT done here — the engine's policy+lease gate already ran.
- Engine integration: `GovernedEngine` executes step tools through the sandbox when one
  is configured, and threads the provenance id into the `tool.invoked` evidence entry,
  so any recorded result is tied to a verifiable execution record. A blocked egress or
  timeout surfaces as `tool.failed` evidence and halts the run.

All of this is config-driven (`sandbox:` section in `config/default.yaml`): backend,
timeout, per-tool destinations, and the egress allowlist. `build_local_sandbox` wires
the whole governed-execution stack from config alone.

Phase 4 success criterion met: agents can safely use real tools under governance —
every tool call is policy- and lease-authorized first, then executed in an
egress-controlled sandbox with provenance recorded in the tamper-evident ledger.

## Desktop UI + Control Plane (Phase 5)

The product gains a professional native desktop experience and a stable API that keeps
the governance moat entirely UI-agnostic.

- Control-plane API (`api.py`): a thin FastAPI surface over a resumable run service.
  Endpoints cover health, the active policy set, run creation, advance, resume (apply a
  human approval decision), and evidence retrieval. It is independently runnable and
  testable (uvicorn / httpx / curl), so the full stack is de-riskable headlessly before
  any GUI exists.
- Resumable run service (`run_service.py`): a UI-agnostic state machine layered over the
  framework-agnostic engine primitives (authorize → sandboxed execute → charge →
  record). A human approval gate spans multiple client requests, so the service executes
  step by step, pauses at high-impact steps (`awaiting_approval`), persists the paused
  position, and continues on `resume`. Every decision still flows through the Rust policy
  engine + capability lease and the tamper-evident ledger; the UI never re-implements
  governance.
- Desktop app (`ui/`): Tauri + React + TypeScript (Vite) with four surfaces — Intent
  Console (compile a goal into a governed plan), Execution Canvas (watch the governed
  run with live human approval gates), Evidence Ledger (verify + replay the hash chain),
  and Governance Admin (inspect the enforced policy set, autonomy tiers, budgets). The
  React app is fully typed against the API contract and builds under strict TypeScript.
- Thin shell: the Tauri crate (`ui/src-tauri/`) hosts the built React app and is excluded
  from the core Cargo workspace, so `cargo test` on the security core never pulls the
  webview/GUI toolchain. The desktop layer carries no security-critical logic.

The full stack was validated live over HTTP: an intent compiled to a five-step plan,
two human approval gates (infra restart, incident post), all steps executed in the
sandbox with provenance, and the tamper-evident ledger verified with every tool.invoked
entry carrying a provenance id — exactly what the React UI drives.

## Phased plan

1. **Foundations (Weeks 1–2, done):** Rust core, PyO3 bindings, Pydantic models,
   config, ephemeral memory, roundtrip + integration tests.
2. **Orchestration (Weeks 3–4, done):** intent compiler + pluggable planners, the
   governance bridge to the Rust core, a framework-agnostic governed execution
   engine, and a LangGraph StateGraph with human-in-the-loop approval checkpoints
   and per-node evidence emission.
3. **Governance & Memory (Weeks 5–6, done):** hybrid policy engine (critical parts in
   Rust), runtime budget enforcement, earned-autonomy tiers, policy-mediated durable
   memory.
4. **MCP + Sandbox (Week 7, done):** MCP client and config-driven adapters, all tool
   calls routed through the Rust governance gate then an egress-controlled sandbox
   with provenance, proxy gateway egress allowlist.
5. **UI + Demo (Weeks 8–10, done):** FastAPI control plane + resumable run service,
   Tauri + React desktop app with Intent Console, live Execution Canvas, Evidence
   Viewer, and Governance Admin; end-to-end Production Incident demo validated live.

## Phase 6: Hardening & Scale (post-MVP)

Phase 6 turns the validated MVP into a multi-tenant, enterprise-onboardable platform. The
guiding principle is the same as the core thesis: every new capability is an *enforced*
boundary or a *projection over evidence*, never advisory decoration, and nothing weakens
the Rust-owned control plane.

- **Multi-tenant workspace isolation (`tenancy.py`).** A `Tenant` is a hard isolation
  boundary, not a partitioning convenience. Every run, ledger, policy lookup, and
  analytics query is keyed by an immutable tenant id, and cross-tenant access is denied
  *by construction*: the run service resolves a run only within its tenant's namespace, so
  a run id from tenant A is indistinguishable from a non-existent id when queried as
  tenant B. The API returns an identical 404 in both cases, so the boundary never leaks
  existence. Proven by a negative-heavy suite (cross-tenant get/advance/resume/evidence
  all denied).

- **Enterprise identity / IdP-mapped onboarding (`identity_provider.py`).** Agents are
  onboarded from an existing OIDC issuer (Okta, Azure AD, any provider) rather than via
  ad-hoc credentials. The flow is verify-claims then map-claims then provision-agent, and
  it is default-deny: a tampered token is rejected and claims matching no mapping rule are
  refused. `IdentityProvider` is a protocol with a deterministic `MockOIDCProvider` for
  hermetic tests; a real discovery/JWKS provider drops in behind the same seam. Every
  onboarding emits evidence.

- **Analytics (`analytics.py`).** Per-tenant usage, spend, autonomy, and policy-violation
  metrics are a *pure projection over the evidence ledger* — never a separate mutable
  store that could drift from the audit trail. Each metric reconciles with scanned ledger
  entries, and the projection carries an integrity flag that is false if any of the
  tenant's run ledgers fail to verify. Exposed at `GET /analytics`, tenant-scoped by header.

- **Adaptive autonomy (`adaptive_autonomy.py`).** An `AutonomyAdvisor` reads an agent's
  evidence-derived behaviour window and recommends promote/demote/hold. The Rust core
  still *owns* tier state — the advisor can only advise; applying a recommendation routes
  through the Rust-backed `AutonomyTracker`, so even a future ML scorer can never forge a
  tier. The scorer is a swappable protocol (`AutonomyScorer`) with a deterministic,
  explainable `HeuristicScorer` default and a documented seam for an ML model. Bad
  behaviour drives demotion, shrinking blast radius — self-healing recorded as evidence.

- **Expanded sandbox backends (`sandbox_backends.py`).** The Phase 4 sandbox wrapper
  (timeout + egress + provenance) keeps its contract; Phase 6 factors out the *execution
  strategy* behind an `ExecutionBackend` protocol. The default `InProcessBackend` is
  explicit that it does not isolate (safety comes from the upstream policy/lease gate plus
  timeout and egress). `WasmStubBackend` and `FirecrackerStubBackend` carry the honest
  capability contract for stronger isolation but *refuse to execute* until a real runtime
  is configured — a backend that claimed isolation it did not provide would be a
  governance lie, so it can never be silently trusted. Backend selection is config-driven.

All Phase 6 work is Python-layer policy and projection above the unchanged Rust core: the
47 Rust tests and the full MVP Python suite continue to pass, with new tests covering the
five subsystems, the isolation boundary (negative tests), and the API. The React UI gains
a workspace switcher (tenant-scoped `X-Tenant-Id` on every call) and an Analytics surface
that renders the ledger-backed metrics with a live integrity badge.

## Phase 7: Constitutional Governance & Compliance

Phase 7 adds supreme, inviolable governance rules and cross-agent collaboration protocols
within the multi-tenant, analytics-aware platform from Phase 6.

- **Agent Constitutions.** Constitutional articles sit *above* policy in the governance
  hierarchy. Where policy answers "is this action permitted by the current rule set?",
  a constitution answers "does this action violate an inviolable principle that no policy
  or autonomy tier may override?" Articles use glob matchers on scope/tool, cost floors,
  and high-impact flags; verdicts are `Forbid` (absolute denial) or `RequireApproval`
  (mandatory human gate). Constitution evaluation is in the Rust core (`constitution.rs`)
  so it cannot be bypassed. Multi-layered governance: constitution (absolute) →
  policy (configurable) → autonomy tier (contextual) → lease (scoped).

- **Multi-Agent Collaboration (`multi_ledger.py`).** Agents can contribute entries to a
  shared, attributed ledger. Each entry carries the agent's signature, so the ledger is
  a verifiable history of who did what. Write access is gated by lease scope, so an agent
  without the right scope cannot pollute a shared ledger even if it has the run_id.
  Supports both exclusive (one writer) and collaborative (read-only others) topologies.

- **Compliance Attestation (`compliance.py`).** A run ledger is auditable and replayable;
  this module exports proofs that a run is compliant: every action was authorized by a
  valid lease, no policy denials occurred, high-impact steps had human approval. The
  attestation is deterministic and verifiable — an auditor (SOC2, ISO27001) can replay
  the evidence and re-check the rules. Exports a structured compliance report with
  findings and a pass/fail flag.

- **Agent Capability Marketplace (`marketplace.py`).** Agents publish reusable skills
  (workflows, tool adapters, reasoning patterns) as signed manifests. A manifest declares
  the scopes it needs, is signed by its publisher, and can be installed by an agent only
  if its lease already grants those scopes or if constitutional rules permit the requested
  upgrade. This ties together the supply chain (artifacts are signed), the governance
  layer (installs are gated), and the evidence ledger (every install is recorded).

All Phase 7 work builds on the Rust core and Phase 6 tenancy/analytics: constitutions are
evaluated in Rust, multi-ledgers are keyed by tenant, compliance is a projection over
evidence, and marketplace installs emit evidence. The 47 Rust tests and full Python suite
continue to pass, with new tests covering constitutional enforcement, multi-agent scenarios,
compliance report determinism, and marketplace signature validation.

## Phase 8: Merkle Transparency Logs

Phase 8 adds cryptographic proofs of evidence integrity. While the hash-chained evidence
ledger is tamper-evident to anyone holding the whole ledger, regulators, auditors, or peer
AetherOS instances should be able to verify a *single fact* — "entry N is included in the
log at tree root R" — without being shipped the entire ledger, and to verify it against a
short, signed commitment.

This is exactly what a Merkle transparency log (RFC 6962 / RFC 9162) provides.

- **Merkle Tree over Evidence (`transparency.rs`).** The evidence ledger entries are
  hashed as leaves (using domain-separated leaf hashing per RFC 6962), assembled into a
  Merkle tree, and the root is signed as a `SignedTreeHead` (timestamp + tree size +
  root hash + issuer signature). The tree is built incrementally so historical roots are
  preserved, enabling consistency proofs: "this old tree is a prefix of the new tree."

- **Inclusion Proofs.** Given an entry's index and the signed tree head, an auditor can
  verify the entry is in the tree using the inclusion proof (the minimal set of sibling
  hashes on the path from leaf to root). This is compact: O(log n) hashes for a ledger
  with n entries.

- **Consistency Proofs.** When a new signed tree head is published, any holder of the old
  STH can ask "is this new tree consistent with the old one?" The consistency proof
  provides the minimal set of hashes to verify that the new tree is the old tree with
  new entries appended. This prevents the log from silently rewriting history.

- **Research Net:** RFC 6962 "Certificate Transparency" (leaf/node domain separation,
  Merkle Tree Hash algorithm, inclusion and consistency proofs); RFC 9162 "CT 2.0"
  (signed tree heads as the auditable commitment); Crosby & Wallach "Efficient Data
  Structures for Tamper-Evident Logging" (USENIX 2009).

The transparency log is pure and side-effect-free (builds from leaf hashes, emits proofs,
verifies them). It reuses the identity and canonical modules so the same Ed25519 key signs
leases, constitutions, marketplace artifacts, and tree heads — a unified cryptographic
anchor. All 63 Rust tests pass (including 9 new transparency tests). Next phases can
integrate transparent logs with the evidence ledger API so auditors request inclusion
proofs on demand.

### Roadmap beyond Phase 8

- **Phase 9 — Persistent Storage & Integration:** move run ledgers from in-memory to
  SQLite/PostgreSQL, integrate transparent logs with the evidence API so auditors can
  request compact proofs on demand, implement ledger compression while preserving
  transparency.
- **Phase 10 — Platform & Ecosystem:** open-core plugin system, optional cloud-hosted
  control plane (SaaS), SDKs for custom agent builders, MCP tool-provider partnerships,
  production hardening (rate limiting, telemetry, key rotation ceremonies).
