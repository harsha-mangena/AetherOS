import { useEffect, useState } from "react";
import { ConstitutionView, api } from "../api";

// The constitution is the *supreme* governance layer: a small set of inviolable articles
// evaluated in the Rust core above policy. Whatever policy or autonomy permits, a forbidding
// article still blocks — and a require_approval article still gates. This surface is a
// read-only window onto that supreme law so operators and auditors can see exactly which
// principles the kernel will enforce no matter what the policy or an agent requests.
export function ConstitutionSurface() {
  const [data, setData] = useState<ConstitutionView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      setData(await api.constitution());
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <section className="surface">
      <div className="surface-head">
        <h2>Constitution {data ? `· ${data.version}` : ""}</h2>
        <button onClick={load} disabled={loading}>
          {loading ? "Refreshing…" : "Refresh"}
        </button>
      </div>

      <p className="muted">
        Inviolable articles evaluated in the Rust core above policy. A forbidding article
        blocks any matching action regardless of policy, lease, or autonomy tier.
      </p>

      {error && <div className="banner bad">{error}</div>}
      {data && data.articles.length === 0 && (
        <div className="muted">No articles configured.</div>
      )}

      {data && data.articles.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th>Article</th>
              <th>Principle</th>
              <th>Verdict</th>
              <th>Matches</th>
            </tr>
          </thead>
          <tbody>
            {data.articles.map((a) => (
              <tr key={a.id}>
                <td className="mono">{a.id}</td>
                <td>{a.principle}</td>
                <td>
                  <span
                    className={`pill ${a.verdict === "forbid" ? "halted" : "pending"}`}
                  >
                    {a.verdict}
                  </span>
                </td>
                <td className="mono">{matchSummary(a)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function matchSummary(a: ConstitutionView["articles"][number]): string {
  const parts: string[] = [];
  if (a.scope) parts.push(`scope=${a.scope}`);
  if (a.tool) parts.push(`tool=${a.tool}`);
  if (a.high_impact_only) parts.push("high-impact");
  if (a.min_cost_minor != null) parts.push(`cost≥${a.min_cost_minor}`);
  return parts.length ? parts.join(" · ") : "any action";
}
