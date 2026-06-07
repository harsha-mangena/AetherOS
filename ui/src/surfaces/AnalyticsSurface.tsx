import { useEffect, useState } from "react";
import { AnalyticsView, api } from "../api";

// Per-tenant analytics, projected from the evidence ledger. Every number here traces back
// to ledger entries the backend scanned, and the integrity badge reflects whether all of
// that tenant's run ledgers verified — so the dashboard can never drift from the audit trail.
export function AnalyticsSurface({ tenantId }: { tenantId: string }) {
  const [data, setData] = useState<AnalyticsView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      setData(await api.analytics());
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
        <h2>Analytics — {tenantId}</h2>
        <button onClick={load} disabled={loading}>
          {loading ? "Refreshing…" : "Refresh"}
        </button>
      </div>

      {error && <div className="banner bad">{error}</div>}
      {!data && !error && <div className="muted">No analytics yet.</div>}

      {data && (
        <>
          <div className="metric-grid">
            <Metric label="Runs" value={data.runs.total} />
            <Metric label="Completed" value={data.runs.completed} />
            <Metric
              label="Completion rate"
              value={`${Math.round(data.runs.completion_rate * 100)}%`}
            />
            <Metric label="Tool invocations" value={data.tools.invocations} />
            <Metric label="Tool failures" value={data.tools.failures} tone={data.tools.failures ? "bad" : "ok"} />
            <Metric
              label="Policy violations"
              value={data.governance.policy_violations}
              tone={data.governance.policy_violations ? "bad" : "ok"}
            />
            <Metric label="Approvals granted" value={data.governance.approvals_granted} />
            <Metric label="Approvals denied" value={data.governance.approvals_denied} />
            <Metric label="Autonomy promotions" value={data.governance.autonomy_promotions} />
            <Metric label="Total spend (minor)" value={data.spend.total_minor} />
          </div>

          <h3>Spend by tool</h3>
          {Object.keys(data.spend.by_tool).length === 0 ? (
            <div className="muted">No spend recorded.</div>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Tool</th>
                  <th>Invocations</th>
                  <th>Spend (minor)</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(data.spend.by_tool).map(([tool, spend]) => (
                  <tr key={tool}>
                    <td className="mono">{tool}</td>
                    <td>{data.tools.by_tool[tool] ?? 0}</td>
                    <td>{spend}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          <div style={{ marginTop: 16 }}>
            <span
              className={`pill ${data.integrity.all_ledgers_verified ? "completed" : "halted"}`}
            >
              {data.integrity.all_ledgers_verified
                ? `ledger-verified · ${data.integrity.evidence_entries_scanned} entries`
                : "INTEGRITY FAILURE — a ledger did not verify"}
            </span>
          </div>
        </>
      )}
    </section>
  );
}

function Metric({
  label,
  value,
  tone,
}: {
  label: string;
  value: string | number;
  tone?: "ok" | "bad";
}) {
  return (
    <div className="metric">
      <div className={`metric-value ${tone === "bad" ? "metric-bad" : ""}`}>{value}</div>
      <div className="metric-label">{label}</div>
    </div>
  );
}
