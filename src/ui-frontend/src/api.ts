// Typed LaunchProof daemon client. The frontend is a control plane: every
// value here comes from daemon JSON/SSE — no verification logic lives in UI.

export type CheckStatus = 'PASS' | 'BLOCK' | 'WARN' | 'SKIPPED' | 'UNVERIFIED' | 'ERROR'
export type Verdict = 'READY' | 'BLOCKED'
export type Severity = 'critical' | 'major' | 'minor' | 'info'
export type VerificationClass = 'deterministic' | 'dynamic' | 'agentic'
export type AgentFindingLabel = 'Observed' | 'Derived' | 'Hypothesized' | 'Unable to verify'
export type PhaseStatus = 'pending' | 'running' | 'done' | 'skipped' | 'error'

export interface EvidenceRef {
  id: string
  category: string
  title: string
}

export interface CheckResult {
  id?: string
  checkId: string
  status: CheckStatus
  severity: Severity
  title: string
  category?: string
  verificationClass?: VerificationClass
  evidence: EvidenceRef[]
  affectedSurface?: string[]
  expected?: string
  observed?: string
  explanation?: string
  remediation?: string
  confidence?: string
  agentLabel?: AgentFindingLabel
  reason?: string
  reproduction?: { command?: string; steps?: string[] }
  phase?: string
}

export interface RunSummary {
  total: number
  pass: number
  block: number
  warn: number
  skipped: number
  unverified: number
  error: number
}

export interface PhaseState {
  id: string
  status: PhaseStatus
  startedAt?: string
  endedAt?: string
  note?: string
}

export interface RunRecord {
  id: string
  projectId: string
  projectPath: string
  profile: string
  status: 'pending' | 'running' | 'completed' | 'cancelled' | 'error'
  verdict?: Verdict
  strict: boolean
  createdAt: string
  startedAt?: string
  endedAt?: string
  recovered?: boolean
  phases: PhaseState[]
  summary?: RunSummary
  changeAnalysis?: {
    available: boolean
    activatedSurfaces: string[]
    activatedReasons: Record<string, string>
    files?: Array<{ path: string; change: string; surfaces: string[] }>
    reason?: string
  }
}

export interface RunEvent {
  type:
    | 'run.started' | 'run.finished' | 'run.cancelled' | 'run.error'
    | 'phase.started' | 'phase.finished' | 'check.started' | 'check.finished'
    | 'evidence.created' | 'log' | 'agent.finding'
  runId: string
  at: string
  phase?: string
  checkId?: string
  result?: CheckResult
  message?: string
  data?: Record<string, unknown>
}

export interface RunReport {
  run?: RunRecord
  runId?: string
  verdict?: Verdict
  summary?: RunSummary
  results: CheckResult[]
}

export interface ProjectRecord {
  id: string
  name: string
  path: string
  createdAt: string
  lastRunId?: string
}

export interface AgentCapabilities {
  id: 'codex' | 'claude' | 'script'
  available: boolean
  version?: string
  tools: string[]
  networkAccess: boolean
  streaming: boolean
  approvals: boolean
  gaps: string[]
}

export interface EvidenceRecord {
  id: string
  runId: string
  checkId: string
  category: string
  title: string
  data: Record<string, unknown>
  replay?: string
  createdAt: string
  sha256: string
  scrubbed: boolean
}

export interface FixTaskView {
  id: string
  checkId: string
  status: string
  instruction: string
  constraints?: string[]
  agentId?: string
}

async function json<T>(route: string, init?: RequestInit): Promise<T> {
  const res = await fetch(route, {
    ...init,
    headers: { 'content-type': 'application/json', ...(init?.headers ?? {}) },
  })
  const body = (await res.json().catch(() => ({}))) as T & { error?: string }
  if (!res.ok) throw new Error(body.error ?? `HTTP ${res.status}`)
  return body
}

export const api = {
  health: () => json<{ ok: boolean; version: string; runs: number; time: string }>('/health'),
  checks: () => json<{ checks: Array<{ id: string; title: string; severity: Severity; cls: VerificationClass; phase: string }> }>('/api/checks'),
  projects: () => json<{ projects: ProjectRecord[] }>('/api/projects'),
  addProject: (path: string, name?: string) =>
    json<{ project: ProjectRecord }>('/api/projects', { method: 'POST', body: JSON.stringify({ path, name }) }),
  runs: () => json<{ live: Array<{ id: string; status: string; verdict?: Verdict; profile: string }>; recent: string[] }>('/api/runs'),
  report: (runId: string) => json<RunReport>(`/api/runs/${runId}`),
  evidenceList: (runId: string) => json<{ evidence: EvidenceRecord[] }>(`/api/runs/${runId}/evidence`),
  evidenceOne: (runId: string, id: string) => json<{ evidence: EvidenceRecord }>(`/api/runs/${runId}/evidence?id=${encodeURIComponent(id)}`),
  agents: () => json<{ agents: AgentCapabilities[] }>('/api/agents'),
  verify: (path: string, profile: string, strict: boolean) =>
    json<{ run: RunRecord }>('/api/verify', { method: 'POST', body: JSON.stringify({ path, profile, strict }) }),
  cancel: (runId: string) => json<{ ok: boolean }>(`/api/runs/${runId}/cancel`, { method: 'POST', body: '{}' }),
  fix: (runId: string, checkId: string, agentId: string, approve: boolean) =>
    json<{ task: FixTaskView; approved: boolean; note: string; instruction?: string }>(`/api/runs/${runId}/fix`, {
      method: 'POST',
      body: JSON.stringify({ checkId, agentId, approve }),
    }),
}

export function openRunStream(runId: string, onEvent: (e: RunEvent) => void, onEnd?: () => void): () => void {
  const es = new EventSource(`/api/runs/${runId}/events`)
  es.onmessage = (m) => {
    try {
      const ev = JSON.parse(m.data) as RunEvent
      onEvent(ev)
      if (ev.type === 'run.finished' || ev.type === 'run.cancelled' || ev.type === 'run.error') {
        es.close()
        onEnd?.()
      }
    } catch { /* malformed frame: ignore, stream stays open */ }
  }
  es.onerror = () => {
    es.close()
    onEnd?.()
  }
  return () => es.close()
}
