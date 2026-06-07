import { useEffect, useState } from "react";
import { ComplianceView, api } from "../api";

// Compliance export is a pure, deterministic projection over the tamper-evident ledger.
// It can never assert anything the chain does not prove: if any run ledger fails to verify,
// the whole tenant is marked non-attestable. Each finding maps a SOC2/GDPR control to the
// concrete evidence sequence numbers that support (or violate) it. This is the surface an
// auditor or CISO reads to confirm — from evidence, not prose — that governance held.
export function ComplianceSurface({ tenantId }: { tenantId: string }) {
  const [data, setData] = useState<ComplianceView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      setData(await api.compliance());
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tenantId]);

  return (
    <section className="surface">
      <div className="surface-head">
        <h2>Compliance — {tenantId}</h2>
        <button onClick={load} disabled={loading}>
          {loading ? "Refreshing…" : "Refresh"}
        </button>
      </div>

      <p className="muted">
        SOC2 + GDPR controls projected from the evidence ledger. A tenant is attestable only
        if every run ledger verifies, and compliant only if no control fails in any run.
      </p>

      {error && <div className="banner bad">{error}</div>}

      {data && (
        <>
          <div style={{ display: "flex", gap: 8, margin: "12px 0" }}>
            <span className={`pill ${data.attestable ? "completed" : "halted"}`}>
              {data.attestable ? "ATTESTABLE" : "NOT ATTESTABLE — ledger failed to verify"}
            </span>
            <span className={`pill ${data.compliant ? "completed" : "halted"}`}>
              {data.compliant ? "COMPLIANT" : "NON-COMPLIANT — a control failed"}
            </span>
            <span className="pill pending">{data.run_count} run(s)</span>
          </div>

          {data.run_count === 0 && (
            <div className="muted">
              No runs yet for this tenant — vacuously attestable and compliant.
            </div>
          )}

          {data.reports.map((rep) => (
            <div key={rep.run_id} className="report-card" style={{ marginTop: 16 }}>
              <h3 style={{ marginBottom: 4 }}>
                Run <span className="mono">{rep.run_id.slice(0, 12)}</span>
              </h3>
              <div className="muted" style={{ marginBottom: 8 }}>
                {rep.entry_count} ledger entries · head{" "}
                <span className="mono">{rep.ledger_head.slice(0, 12)}…</span> ·{" "}
                {rep.ledger_intact ? "intact" : "TAMPERED"}
              </div>
              <table className="table">
                <thead>
                  <tr>
                    <th>Framework</th>
                    <th>Control</th>
                    <th>Status</th>
                    <th>Finding</th>
                    <th>Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {rep.findings.map((f) => (
                    <tr key={`${f.framework}-${f.control_id}`}>
                      <td>{f.framework}</td>
                      <td className="mono">{f.control_id}</td>
                      <td>
                        <span className={`pill ${statusTone(f.status)}`}>{f.status}</span>
                      </td>
                      <td>
                        <div>{f.title}</div>
                        <div className="muted">{f.detail}</div>
                      </td>
                      <td className="mono">
                        {f.evidence_seqs.length
                          ? `#${f.evidence_seqs.join(", #")}`
                          : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
        </>
      )}
    </section>
  );
}

function statusTone(status: string): string {
  if (status === "pass") return "completed";
  if (status === "fail") return "halted";
  return "pending";
}
