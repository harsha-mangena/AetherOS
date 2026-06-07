# AetherOS Desktop UI

Professional desktop interface for the AetherOS trusted execution kernel, built with
**Tauri + React + TypeScript (Vite)**. Four surfaces:

- **Intent Console** — submit a natural-language goal; it is compiled into a governed,
  least-privilege plan.
- **Execution Canvas** — watch the governed run step by step, with live human approval
  gates on high-impact actions.
- **Evidence Ledger** — verify and replay the tamper-evident, hash-chained audit trail.
- **Governance Admin** — inspect the enforced policy set, autonomy tiers, and budgets.

## Architecture

The UI is intentionally thin. It holds **no** security-critical logic. Everything flows
through the local control-plane API (FastAPI), which calls the governed engine — and the
engine calls the Rust `aether-core` crate (policy, leases, ledger) over PyO3. The desktop
layer only renders JSON snapshots and forwards human decisions.

```
React UI  →  /api (FastAPI control plane)  →  GovernedEngine + RunService
                                            →  aether-core (Rust: policy, lease, ledger)
```

## Run in development

Two processes. First the control-plane API:

```bash
# from repo root, with the Python venv active
uvicorn aetheros_orchestrator.api:app --port 8765
```

Then the UI (Vite proxies `/api` → `http://127.0.0.1:8765`):

```bash
cd ui
npm install
npm run dev        # http://localhost:5173
```

Or run the whole thing with one command from the repo root:

```bash
./scripts/run_desktop.sh
```

## Package as a native desktop app

The Tauri shell (`src-tauri/`) bundles the built React app into a native window. It is
excluded from the core Cargo workspace so `cargo test` on the security core never pulls
the GUI toolchain.

```bash
cd ui
npm run build              # type-check + bundle React → dist/
npm run tauri build        # requires the Tauri CLI + platform webview toolchain
```

## Build verification

`npm run build` runs `tsc` (strict mode) then `vite build`. The frontend is fully typed
against the API contract in `src/api.ts`.
