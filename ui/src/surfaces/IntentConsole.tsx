import { useState } from "react";
import { api, RunView } from "../api";

const SAMPLE = "Investigate the production incident in checkout and restore service";

export function IntentConsole({ onRun }: { onRun: (r: RunView) => void }) {
  const [intent, setIntent] = useState(SAMPLE);
  const [budget, setBudget] = useState(100000);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function submit() {
    setBusy(true);
    setErr(null);
    try {
      const run = await api.createRun(intent, budget);
      onRun(run);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <h2>Intent Console</h2>
      <p className="lead">
        Express a high-level goal. AetherOS compiles it into a governed, auditable plan —
        every step bound to a capability scope, budget slice, and the tamper-evident ledger.
      </p>

      <div className="card">
        <label className="muted" style={{ fontSize: 13 }}>
          Natural-language intent
        </label>
        <textarea value={intent} onChange={(e) => setIntent(e.target.value)} />
        <div className="row" style={{ marginTop: 14 }}>
          <div>
            <label className="muted" style={{ fontSize: 13, display: "block", marginBottom: 4 }}>
              Budget (minor units)
            </label>
            <input
              type="number"
              value={budget}
              min={0}
              style={{ width: 180 }}
              onChange={(e) => setBudget(Number(e.target.value))}
            />
          </div>
          <div className="spacer" />
          <button className="primary" disabled={busy || !intent.trim()} onClick={submit}>
            {busy ? "Compiling…" : "Compile & Govern"}
          </button>
        </div>
        {err && <div className="err">{err}</div>}
      </div>

      <div className="card">
        <div className="muted" style={{ fontSize: 13 }}>
          The compiler produces a least-privilege plan. High-impact steps (e.g. restarting
          production infrastructure) are gated behind a human approval checkpoint and require
          earned autonomy. Nothing executes without a signed capability lease.
        </div>
      </div>
    </div>
  );
}
