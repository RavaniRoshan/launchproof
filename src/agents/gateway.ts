/**
 * Agent Gateway: adapter boundary between LaunchProof and coding agents.
 *
 * Required operations: connect / discover_capabilities / start_session /
 * send_instruction / stream_events / interrupt / request_approval /
 * collect_result / close_session.
 *
 * The verification engine never sees agent-specific protocols — only this
 * normalized interface. No agent is a hard dependency of the engine.
 */

export type AgentId = 'codex' | 'claude' | 'script';

export interface AgentCapabilities {
  id: AgentId;
  available: boolean;
  version?: string;
  tools: string[];
  networkAccess: boolean;
  streaming: boolean;
  approvals: boolean;
  gaps: string[];
}

export interface AgentSession {
  id: string;
  agentId: AgentId;
  startedAt: string;
  context: VerifierContext;
}

export interface VerifierContext {
  checkId: string;
  launchContract: unknown;
  changeSummary?: string;
  relevantSource: Array<{ path: string; excerpt: string }>;
  evidence: Array<Record<string, unknown>>;
  objective: string;
  constraints: string[];
}

export interface AgentEvent {
  type: 'stdout' | 'stderr' | 'status' | 'approval_request' | 'done';
  at: string;
  message: string;
  data?: Record<string, unknown>;
}

export interface AgentResult {
  sessionId: string;
  exitCode: number | null;
  output: string;
  changedFiles: string[];
  durationMs: number;
}

export interface AgentAdapter {
  readonly id: AgentId;
  connect(): Promise<{ ok: boolean; detail: string }>;
  discoverCapabilities(): Promise<AgentCapabilities>;
  startSession(context: VerifierContext): Promise<AgentSession>;
  sendInstruction(session: AgentSession, instruction: string): Promise<void>;
  streamEvents(session: AgentSession, onEvent: (e: AgentEvent) => void): Promise<void>;
  interrupt(session: AgentSession): Promise<void>;
  requestApproval(session: AgentSession, action: string): Promise<boolean>;
  collectResult(session: AgentSession): Promise<AgentResult>;
  closeSession(session: AgentSession): Promise<void>;
}

export function buildVerifierInstruction(context: VerifierContext): string {
  return [
    `You are an INDEPENDENT verifier, not the builder. Do not trust prior claims.`,
    ``,
    `Objective: ${context.objective}`,
    ``,
    `Check under verification: ${context.checkId}`,
    ...(context.changeSummary ? [`Change summary: ${context.changeSummary}`, ``] : []),
    `Constraints:`,
    ...context.constraints.map((c) => `- ${c}`),
    ``,
    `Evidence so far:`,
    ...context.evidence.slice(0, 8).map((e) => `- ${JSON.stringify(e).slice(0, 300)}`),
    ``,
    `You must produce EVIDENCE for every conclusion. Distinguish:`,
    `Observed (you measured it) / Derived (computed from evidence) / Hypothesized (needs a test) / Unable to verify.`,
    `You may NOT mark a check PASS on the basis of reasoning alone.`,
  ].join('\n');
}

export function buildFixInstruction(opts: {
  checkId: string;
  title: string;
  evidence: string;
  surface: string;
  invariant: string;
}): string {
  return [
    `Fix ${opts.checkId} (${opts.title}).`,
    ``,
    `Evidence:`,
    opts.evidence,
    ``,
    `Affected surface: ${opts.surface}`,
    `Required invariant: ${opts.invariant}`,
    ``,
    `Constraints:`,
    `- Do not change unrelated functionality.`,
    `- Do not weaken existing security checks.`,
    `- Do not add new dependencies unless required.`,
    ``,
    `After modification:`,
    `1. run relevant tests`,
    `2. report the changed files`,
    `3. LaunchProof will independently re-run ${opts.checkId} — your statement that it is fixed is not evidence.`,
  ].join('\n');
}
