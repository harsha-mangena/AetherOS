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

// ── Phase 6: multi-tenancy + analytics ──────────────────────────────────────

export interface TenantView {
  tenant_id: string;
  display_name: string;
  max_budget_minor: number | null;
  max_autonomy_tier: number | null;
  created_at: string;
}

export interface AnalyticsView {
  tenant_id: string;
  runs: { total: number; completed: number; halted: number; completion_rate: number };
  tools: { invocations: number; failures: number; by_tool: Record<string, number> };
  governance: {
    policy_violations: number;
    approvals_granted: number;
    approvals_denied: number;
    approval_rate: number;
    autonomy_promotions: number;
  };
  spend: { total_minor: number; by_tool: Record<string, number> };
  integrity: { evidence_entries_scanned: number; all_ledgers_verified: boolean };
}

// ── Phase 7: constitution (supreme governance) + compliance export ──────────

export interface ConstitutionArticle {
  id: string;
  principle: string;
  verdict: string;
  scope: string | null;
  tool: string | null;
  min_cost_minor: number | null;
  high_impact_only: boolean | null;
}

export interface ConstitutionView {
  version: string;
  articles: ConstitutionArticle[];
}

export interface ControlFinding {
  framework: string;
  control_id: string;
  title: string;
  status: "pass" | "fail" | "not_applicable";
  detail: string;
  evidence_seqs: number[];
}

export interface ComplianceReport {
  run_id: string;
  tenant_id: string;
  generated_at: string;
  ledger_intact: boolean;
  ledger_head: string;
  entry_count: number;
  attestable: boolean;
  compliant: boolean;
  findings: ControlFinding[];
}

export interface ComplianceView {
  tenant_id: string;
  run_count: number;
  attestable: boolean;
  compliant: boolean;
  reports: ComplianceReport[];
}

const BASE = "/api";

// The active tenant is held module-side and sent as X-Tenant-Id on every scoped call,
// so the same isolation boundary the backend enforces is reflected in the UI.
let ACTIVE_TENANT = "default";

export function setActiveTenant(tenantId: string): void {
  ACTIVE_TENANT = tenantId;
}

export function getActiveTenant(): string {
  return ACTIVE_TENANT;
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      "X-Tenant-Id": ACTIVE_TENANT,
    },
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
  listRuns: () => req<{ tenant_id?: string; runs: RunView[] }>("/runs"),
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
  // Phase 6
  listTenants: () => req<{ tenants: TenantView[] }>("/tenants"),
  createTenant: (display_name: string) =>
    req<TenantView>("/tenants", {
      method: "POST",
      body: JSON.stringify({ display_name }),
    }),
  analytics: () => req<AnalyticsView>("/analytics"),
  // Phase 7
  constitution: () => req<ConstitutionView>("/config/constitution"),
  compliance: () => req<ComplianceView>("/compliance"),
};
