import { useEffect, useState } from "react";
import { api, RunView } from "./api";
import { IntentConsole } from "./surfaces/IntentConsole";
import { ExecutionCanvas } from "./surfaces/ExecutionCanvas";
import { EvidenceViewer } from "./surfaces/EvidenceViewer";
import { AdminSurface } from "./surfaces/AdminSurface";

type Tab = "console" | "canvas" | "evidence" | "admin";

export default function App() {
  const [tab, setTab] = useState<Tab>("console");
  const [run, setRun] = useState<RunView | null>(null);
  const [online, setOnline] = useState<boolean | null>(null);

  useEffect(() => {
    api
      .health()
      .then(() => setOnline(true))
      .catch(() => setOnline(false));
  }, []);

  // When a run is created or advanced, jump to the canvas.
  function onRun(r: RunView) {
    setRun(r);
    setTab("canvas");
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <h1>AetherOS</h1>
          <div className="sub">Trusted Execution Kernel</div>
        </div>
        <nav className="nav">
          <button className={tab === "console" ? "active" : ""} onClick={() => setTab("console")}>
            Intent Console
          </button>
          <button className={tab === "canvas" ? "active" : ""} onClick={() => setTab("canvas")}>
            Execution Canvas
          </button>
          <button className={tab === "evidence" ? "active" : ""} onClick={() => setTab("evidence")}>
            Evidence Ledger
          </button>
          <button className={tab === "admin" ? "active" : ""} onClick={() => setTab("admin")}>
            Governance Admin
          </button>
        </nav>
        <div className="spacer" />
        <div style={{ padding: "0 20px", fontSize: 12 }}>
          <span className={`pill ${online ? "completed" : online === false ? "halted" : "pending"}`}>
            {online === null ? "connecting" : online ? "control plane online" : "backend offline"}
          </span>
        </div>
      </aside>

      <main className="main">
        {online === false && (
          <div className="banner bad">
            Control-plane API not reachable on /api. Start it with:{" "}
            <code className="mono">uvicorn aetheros_orchestrator.api:app --port 8765</code>
          </div>
        )}
        {tab === "console" && <IntentConsole onRun={onRun} />}
        {tab === "canvas" && <ExecutionCanvas run={run} setRun={setRun} />}
        {tab === "evidence" && <EvidenceViewer run={run} />}
        {tab === "admin" && <AdminSurface />}
      </main>
    </div>
  );
}
