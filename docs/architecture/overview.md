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

## Phased plan

1. **Foundations (Weeks 1–2, done):** Rust core, PyO3 bindings, Pydantic models,
   config, ephemeral memory, roundtrip + integration tests.
2. **Orchestration (Weeks 3–4):** LangGraph StateGraph calling the Rust core, intent
   compiler, human approval checkpoints, evidence emission at every node.
3. **Governance & Memory (Weeks 5–6):** hybrid policy engine (critical parts in
   Rust), budget tracking, earned-autonomy tiers, durable memory.
4. **MCP + Sandbox (Week 7):** MCP client and adapters in Python, all tool calls
   routed through the Rust governance layer, Rust-controlled sandbox, proxy gateway.
5. **UI + Demo + Hardening (Weeks 8–10):** Tauri + React desktop app, intent console,
   live execution canvas, admin surfaces, end-to-end Production Incident demo.
