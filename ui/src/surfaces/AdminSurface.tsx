import { useEffect, useState } from "react";
import { api, PolicyView } from "../api";

export function AdminSurface() {
  const [pol, setPol] = useState<PolicyView | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    api
      .policy()
      .then(setPol)
      .catch((e) => setErr((e as Error).message));
  }, []);

  return (
    <div>
      <h2>Governance Admin</h2>
      <p className="lead">
        The enforced policy set, evaluated in the Rust core with deny-overrides and default-deny.
        Capability leases and earned-autonomy tiers gate what every agent may do at runtime.
      </p>

      {err && <div className="banner bad">{err}</div>}

      {pol && (
        <>
          <div className="card">
            <div className="kv">
              <span className="k">Default decision</span>
              <span className="v">{pol.default_allow ? "allow" : "deny (default-deny)"}</span>
            </div>
            <div className="kv">
              <span className="k">High-impact approval</span>
              <span className="v">{pol.require_approval_for_high_impact ? "required" : "off"}</span>
            </div>
            <div className="kv">
              <span className="k">Autonomy promotion threshold</span>
              <span className="v">{pol.autonomy.promotion_threshold} successful runs / tier</span>
            </div>
            <div className="kv">
              <span className="k">Max autonomy tier</span>
              <span className="v">{pol.autonomy.max_tier}</span>
            </div>
          </div>

          <div className="card" style={{ padding: 0 }}>
            <table>
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Effect</th>
                  <th>Scope</th>
                  <th>Min tier</th>
                  <th>Max cost</th>
                  <th>Priority</th>
                </tr>
              </thead>
              <tbody>
                {pol.rules.map((r) => (
                  <tr key={r.id}>
                    <td>{r.id}</td>
                    <td>
                      <span className={`pill ${r.effect === "deny" ? "halted" : "completed"}`}>
                        {r.effect}
                      </span>
                    </td>
                    <td>
                      <code className="scope">{r.scope ?? r.tool ?? "*"}</code>
                    </td>
                    <td className="mono">{r.min_autonomy_tier}</td>
                    <td className="mono">{r.max_cost_minor ?? "—"}</td>
                    <td className="mono">{r.priority}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
