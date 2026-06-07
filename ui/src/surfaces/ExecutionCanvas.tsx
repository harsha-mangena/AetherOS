import { useState } from "react";
import { api, RunView } from "../api";

function StepRow({ step }: { step: RunView["plan"][number] }) {
  const gate = step.status === "awaiting_approval";
  return (
    <div className={`step ${gate ? "gate" : ""}`}>
      <span className={`pill ${step.status}`}>{step.status.replace("_", " ")}</span>
      <div className="desc">
        <div>
          {step.description}
          {step.high_impact && <span className="tag-high">HIGH-IMPACT</span>}
        </div>
        <div className="meta">
          {step.tool} · <code className="scope">{step.scope}</code> · {step.estimated_cost_minor} minor
        </div>
      </div>
    </div>
  );
}

export function ExecutionCanvas({
  run,
  setRun,
}: {
  run: RunView | null;
  setRun: (r: RunView) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  if (!run) {
    return (
      <div>
        <h2>Execution Canvas</h2>
        <p className="lead">Compile an intent in the Intent Console to start a governed run.</p>
      </div>
    );
  }

  async function act(fn: () => Promise<RunView>) {
    setBusy(true);
    setErr(null);
    try {
      setRun(await fn());
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const awaiting = run.status === "awaiting_approval";
  const terminal = run.status === "completed" || run.status === "halted";

  return (
    <div>
      <h2>Execution Canvas</h2>
      <p className="lead">{run.intent.text}</p>

      <div className="card">
        <div className="row">
          <span className={`pill ${run.status}`}>{run.status.replace("_", " ")}</span>
          <div className="kv" style={{ margin: 0 }}>
            <span className="k">agent</span>
            <span className="v">{run.agent_id.slice(0, 12)}…</span>
          </div>
          <div className="kv" style={{ margin: 0 }}>
            <span className="k">autonomy tier</span>
            <span className="v">{run.autonomy_tier}</span>
          </div>
          <div className="kv" style={{ margin: 0 }}>
            <span className="k">spent / remaining</span>
            <span className="v">
              {run.total_cost_minor} / {run.remaining_minor ?? "—"}
            </span>
          </div>
          <div className="spacer" />
          {run.status === "planned" && (
            <button className="primary" disabled={busy} onClick={() => act(() => api.advance(run.run_id))}>
              {busy ? "Running…" : "Run"}
            </button>
          )}
          {run.status === "running" && (
            <button className="primary" disabled={busy} onClick={() => act(() => api.advance(run.run_id))}>
              Continue
            </button>
          )}
        </div>
        {err && <div className="err">{err}</div>}
      </div>

      {awaiting && run.pending_step_id && (
        <div className="banner info">
          <div className="row">
            <strong>Approval required:</strong>
            <span>
              {run.plan.find((s) => s.step_id === run.pending_step_id)?.description}
            </span>
            <div className="spacer" />
            <button
              className="approve"
              disabled={busy}
              onClick={() => act(() => api.resume(run.run_id, run.pending_step_id!, true, "human:operator"))}
            >
              Approve
            </button>
            <button
              className="deny"
              disabled={busy}
              onClick={() => act(() => api.resume(run.run_id, run.pending_step_id!, false, "human:operator"))}
            >
              Deny
            </button>
          </div>
        </div>
      )}

      {terminal && (
        <div className={`banner ${run.status === "completed" ? "good" : "bad"}`}>
          Run {run.status}
          {run.denied_reason ? ` — ${run.denied_reason}` : ""}. Evidence ledger has{" "}
          {run.evidence_length} entries. See the Evidence Ledger tab to verify and replay.
        </div>
      )}

      <div className="card">
        {run.plan.map((s) => (
          <StepRow key={s.step_id} step={s} />
        ))}
      </div>
    </div>
  );
}
