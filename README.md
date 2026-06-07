# AetherOS

**Trusted Execution Kernel for Enterprise AI Agents** — a hybrid Rust + Python +
Tauri/React system that makes autonomous AI agents safe, observable, and governable.

AetherOS gives every agent a cryptographic identity, scoped capability leases,
runtime budget and policy enforcement, hybrid memory, and a tamper-evident evidence
ledger — sitting on top of existing systems through the Model Context Protocol (MCP).

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
ui/                     Tauri + React desktop app (Intent Console, Execution Canvas,
                        Evidence Viewer, Governance Admin)
examples/               End-to-end Production Incident demo
docs/                   Architecture and design docs
```

## Status

All eight phases are implemented and tested end to end:

1. Foundations — Rust core primitives, PyO3 bindings, Pydantic models, config, memory.
2. Orchestration — intent compiler, governed engine, LangGraph human-in-the-loop graph.
3. Governance & Memory — Rust-evaluated policy engine, runtime budgets, earned autonomy,
   policy-mediated durable memory.
4. MCP + Sandbox — MCP adapters, all tool calls routed through the Rust governance gate
   then an egress-controlled sandbox with provenance, proxy gateway.
5. Desktop UI + Control Plane — FastAPI control plane over a resumable run service, and a
   Tauri + React desktop app with four governance surfaces.
6. Hardening & Scale — Multi-tenant workspace isolation, enterprise IdP onboarding,
   analytics dashboard, adaptive autonomy, pluggable sandbox backends.
7. Constitutional Governance & Compliance — Inviolable agent constitutions in Rust,
   multi-agent collaboration with shared attributed ledgers, compliance attestation,
   agent capability marketplace with signed manifests.
8. Merkle Transparency Logs — RFC 6962/9162 inclusion and consistency proofs over the
   evidence ledger, signed tree heads, compact audit trails for regulators.

The full governed flow — intent → least-privilege plan → policy + lease authorization →
sandboxed execution with provenance → human approval gates → tamper-evident, replayable
evidence with cryptographic transparency proofs — is validated by 63 Rust tests and
125 Python tests, all green.

## Development

Prerequisites: Rust (stable), Python 3.10+, [`uv`](https://docs.astral.sh/uv/),
[`maturin`](https://www.maturin.rs/), and Node 20+ for the UI.

```bash
# Set up the Python environment and build the native extension
make setup        # create venv, install deps, build the Rust extension into Python
make test         # run Rust + Python test suites
make fmt          # format Rust and check Python
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
