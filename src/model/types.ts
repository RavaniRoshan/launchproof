export type CheckStatus = 'PASS' | 'BLOCK' | 'WARN' | 'SKIPPED' | 'UNVERIFIED' | 'ERROR';

export type Verdict = 'READY' | 'BLOCKED';

export type Severity = 'critical' | 'major' | 'minor' | 'info';

export type VerificationClass = 'deterministic' | 'dynamic' | 'agentic';

export type EvidenceCategory =
  | 'SOURCE'
  | 'BUILD'
  | 'STATIC_ANALYSIS'
  | 'RUNTIME'
  | 'BROWSER'
  | 'DATABASE'
  | 'NETWORK'
  | 'DEPLOYMENT'
  | 'AGENT'
  | 'USER_CONFIRMATION';

export type Confidence = 'verified' | 'high' | 'medium' | 'low' | 'agent_claim';

export type AgentFindingLabel = 'Observed' | 'Derived' | 'Hypothesized' | 'Unable to verify';

export type RunStatus = 'pending' | 'running' | 'completed' | 'cancelled' | 'error';

export type PhaseId =
  | 'discover'
  | 'understand'
  | 'static'
  | 'build'
  | 'runtime'
  | 'browser'
  | 'database'
  | 'api'
  | 'adversarial'
  | 'deployment'
  | 'regression'
  | 'decision'
  | 'report';

export const PHASE_ORDER: PhaseId[] = [
  'discover',
  'understand',
  'static',
  'build',
  'runtime',
  'browser',
  'database',
  'api',
  'adversarial',
  'deployment',
  'regression',
  'decision',
  'report',
];

export const ALL_STATUSES: CheckStatus[] = ['PASS', 'BLOCK', 'WARN', 'SKIPPED', 'UNVERIFIED', 'ERROR'];

export const CHECK_ID_RE = /^[A-Z][A-Z0-9]*-\d{3}$/;

export function isCheckId(value: string): boolean {
  return CHECK_ID_RE.test(value);
}

export function isBlockingStatus(status: CheckStatus): boolean {
  return status === 'BLOCK';
}

export function countsAsPass(status: CheckStatus): boolean {
  return status === 'PASS';
}
