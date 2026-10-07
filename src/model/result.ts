import type {
  AgentFindingLabel,
  CheckStatus,
  Confidence,
  EvidenceCategory,
  Severity,
  VerificationClass,
  Verdict,
} from './types.ts';

export interface EvidenceRef {
  id: string;
  category: EvidenceCategory;
  title: string;
}

export interface Reproduction {
  command?: string;
  steps?: string[];
}

export interface CheckResult {
  id: string;
  checkId: string;
  status: CheckStatus;
  severity: Severity;
  title: string;
  category: string;
  verificationClass: VerificationClass;
  evidence: EvidenceRef[];
  affectedSurface: string[];
  expected: string;
  observed: string;
  explanation: string;
  remediation: string;
  reproduction?: Reproduction;
  confidence: Confidence;
  agentLabel?: AgentFindingLabel;
  reason?: string;
  prerequisiteFailed?: string;
  agentFixable: boolean;
  durationMs: number;
  startedAt: string;
  endedAt: string;
  phase: string;
}

export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ValidationError';
  }
}

const STATUSES = new Set<CheckStatus>(['PASS', 'BLOCK', 'WARN', 'SKIPPED', 'UNVERIFIED', 'ERROR']);

/**
 * Result invariants (checklist X6, X7, X22):
 * - BLOCK/WARN must carry evidence
 * - SKIPPED/UNVERIFIED/ERROR must carry a reason and can never be PASS
 * - an agent claim can never be PASS
 * - agentic results must carry an Observed/Derived/Hypothesized/Unable-to-verify label
 */
export function validateResult(result: CheckResult): void {
  if (!STATUSES.has(result.status)) {
    throw new ValidationError(`unknown status: ${result.status}`);
  }
  if (result.status === 'BLOCK' || result.status === 'WARN') {
    if (result.evidence.length === 0) {
      throw new ValidationError(`${result.checkId} returned ${result.status} without evidence`);
    }
  }
  if (result.status === 'SKIPPED' || result.status === 'UNVERIFIED' || result.status === 'ERROR') {
    if (!result.reason || result.reason.trim().length === 0) {
      throw new ValidationError(`${result.checkId} returned ${result.status} without a reason`);
    }
  }
  if (result.confidence === 'agent_claim' && result.status === 'PASS') {
    throw new ValidationError(`${result.checkId}: agent claims can never produce PASS`);
  }
  if (result.verificationClass === 'agentic' && !result.agentLabel) {
    throw new ValidationError(`${result.checkId}: agentic results require an explicit label`);
  }
  if (result.status === 'PASS' && result.verificationClass !== 'agentic' && result.evidence.length === 0) {
    throw new ValidationError(`${result.checkId}: PASS must record how it was verified`);
  }
}

export interface RunSummary {
  total: number;
  pass: number;
  block: number;
  warn: number;
  skipped: number;
  unverified: number;
  error: number;
}

export function summarize(results: CheckResult[]): RunSummary {
  const summary: RunSummary = {
    total: results.length,
    pass: 0,
    block: 0,
    warn: 0,
    skipped: 0,
    unverified: 0,
    error: 0,
  };
  for (const r of results) {
    if (r.status === 'PASS') summary.pass += 1;
    else if (r.status === 'BLOCK') summary.block += 1;
    else if (r.status === 'WARN') summary.warn += 1;
    else if (r.status === 'SKIPPED') summary.skipped += 1;
    else if (r.status === 'UNVERIFIED') summary.unverified += 1;
    else if (r.status === 'ERROR') summary.error += 1;
  }
  return summary;
}

export interface DecisionOptions {
  strict?: boolean;
}

export function decideVerdict(results: CheckResult[], options: DecisionOptions = {}): Verdict {
  const blocking = results.some((r) => {
    if (r.status === 'BLOCK') return true;
    if (options.strict && (r.status === 'UNVERIFIED' || r.status === 'ERROR')) return true;
    return false;
  });
  return blocking ? 'BLOCKED' : 'READY';
}
