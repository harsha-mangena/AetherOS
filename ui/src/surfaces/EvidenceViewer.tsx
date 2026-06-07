import { useEffect, useState } from "react";
import { api, EvidenceView, RunView } from "../api";

export function EvidenceViewer({ run }: { run: RunView | null }) {
  const [ev, setEv] = useState<EvidenceView | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    setEv(null);
    setErr(null);
    if (!run) return;
    api
      .evidence(run.run_id)
      .then(setEv)
      .catch((e) => setErr((e as Error).message));
  }, [run?.run_id, run?.evidence_length]);

  if (!run) {
    return (
      <div>
        <h2>Evidence Ledger</h2>
        <p className="lead">Run an intent to produce a tamper-evident, replayable audit trail.</p>
      </div>
    );
  }

  return (
    <div>
      <h2>Evidence Ledger</h2>
      <p className="lead">
        Append-only, hash-chained record of everything the agent planned, accessed, spent, and
        changed. Each entry's hash binds to the previous one, so any tampering breaks the chain.
      </p>

      {err && <div className="banner bad">{err}</div>}

      {ev && (
        <>
          <div className={`banner ${ev.verified ? "good" : "bad"}`}>
            Chain integrity: {ev.verified ? "VERIFIED" : "BROKEN"} · {ev.length} entries · head{" "}
            <span className="hash">{ev.head_hash?.slice(0, 24)}…</span>
          </div>
          <div className="card" style={{ padding: 0 }}>
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Event</th>
                  <th>Actor</th>
                  <th>Detail</th>
                  <th>Entry hash</th>
                </tr>
              </thead>
              <tbody>
                {ev.entries.map((e) => {
                  const prov = (e.payload as Record<string, unknown>).provenance_id as
                    | string
                    | undefined;
                  const step = (e.payload as Record<string, unknown>).step_id as string | undefined;
                  return (
                    <tr key={e.seq}>
                      <td className="mono">{e.seq}</td>
                      <td>{e.event_type}</td>
                      <td className="mono">{e.actor.slice(0, 16)}</td>
                      <td className="muted">
                        {step ? `${step} ` : ""}
                        {prov ? `prov=${prov.slice(0, 10)}…` : ""}
                      </td>
                      <td className="hash">{e.entry_hash.slice(0, 18)}…</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
