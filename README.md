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
crates/aether-core      Rust core: identity, leases, evidence ledger, canonical hashing
bindings/aether-py      PyO3 bindings + Pydantic models (the `aetheros` package)
python/                 Orchestration layer (config, memory, LangGraph — later phases)
config/                 Config-driven defaults (zero-hardcoding)
ui/                     Tauri + React desktop app (Phase 5)
docs/                   Architecture and design docs
```

## Status

Phase 1 (Foundations) is complete: Rust core primitives with full test coverage,
PyO3 bindings usable from Python, Pydantic models, config system, and ephemeral
memory. See `docs/architecture/overview.md` and the per-phase notes.

## Development

Prerequisites: Rust (stable), Python 3.10+, [`uv`](https://docs.astral.sh/uv/),
and [`maturin`](https://www.maturin.rs/).

```bash
# Set up the Python environment and build the native extension
make setup        # create venv, install deps, build the Rust extension into Python
make test         # run Rust + Python test suites
make fmt          # format Rust and check Python
```

## License

Apache-2.0. See `LICENSE`.
