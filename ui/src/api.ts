// Typed client for the AetherOS control-plane API.
//
// All calls go through the relative /api prefix, which Vite proxies to the local
// FastAPI backend in dev and Tauri serves in the packaged app. The governed-execution
// moat (Rust policy + lease + tamper-evident ledger) lives entirely behind this API;
// the UI only ever sees JSON snapshots.

export type RunStatus =
  | "planned"
  | "running"
  | "awaiting_approval"
  | "completed"
  | "halted";

export interface PlanStepView {
  step_id: string;
  description: string;
  tool: string;
  scope: string;
  estimated_cost_minor: number;
  high_impact: boolean;
  status: string;
}

export interface StepResultView {
  step_id: string;
  status: string;
  output: unknown;
  cost_minor: number;
  evidence_seq: number | null;
  detail: string | null;
}

export interface RunView {
  run_id: string;
  status: RunStatus;
  intent: { text: string; submitted_by: string; budget_minor: number };
  agent_id: string;
  autonomy_tier: number;
  lease_id: string | null;
  remaining_minor: number | null;
  total_cost_minor: number;
  pending_step_id: string | null;
  denied_reason: string | null;
  plan: PlanStepView[];
  results: StepResultView[];
  evidence_head: string | null;
  evidence_length: number;
  created_at: string;
}

export interface EvidenceEntry {
  seq: number;
  event_type: string;
  actor: string;
  timestamp: string;
  payload: Record<string, unknown>;
  entry_hash: string;
  prev_hash: string;
}

export interface EvidenceView {
  run_id: string;
  verified: boolean;
  head_hash: string;
  length: number;
  entries: EvidenceEntry[];
}

export interface PolicyRule {
  id: string;
  effect: string;
  scope: string | null;
  tool: string | null;
  min_autonomy_tier: number;
  max_cost_minor: number | null;
  priority: number;
}

export interface PolicyView {
  default_allow: boolean;
  require_approval_for_high_impact: boolean;
  autonomy: { promotion_threshold: number; max_tier: number };
  rules: PolicyRule[];
}

const BASE = "/api";

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    const detail = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(detail.detail || `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => req<{ status: string }>("/health"),
  policy: () => req<PolicyView>("/config/policy"),
  listRuns: () => req<{ runs: RunView[] }>("/runs"),
  createRun: (intent: string, budget_minor = 100000) =>
    req<RunView>("/runs", {
      method: "POST",
      body: JSON.stringify({ intent, budget_minor }),
    }),
  getRun: (id: string) => req<RunView>(`/runs/${id}`),
  advance: (id: string) =>
    req<RunView>(`/runs/${id}/advance`, { method: "POST" }),
  resume: (id: string, step_id: string, approved: boolean, approver = "human:operator") =>
    req<RunView>(`/runs/${id}/resume`, {
      method: "POST",
      body: JSON.stringify({ step_id, approved, approver }),
    }),
  evidence: (id: string) => req<EvidenceView>(`/runs/${id}/evidence`),
};
