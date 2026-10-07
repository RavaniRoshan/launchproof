import { randomBytes } from 'node:crypto';
import type { CheckResult } from '../model/result.ts';
import type { FixTask } from '../model/state.ts';
import { newFixTaskId } from '../model/ids.ts';
import { adapterFor } from './adapters.ts';
import { buildFixInstruction } from './gateway.ts';
import type { AgentId } from './gateway.ts';

export interface FixRequest {
  checkId: string;
  result: CheckResult;
  evidenceText: string;
  agentId: AgentId;
}

export interface FixOutcome {
  task: FixTask;
  instruction: string;
  agentOutput?: string;
  note: string;
}

/**
 * Fix-and-reverify loop (P10):
 * 1. finding -> scoped fix instruction (never modifies source here)
 * 2. agent runs ONLY after explicit user approval
 * 3. caller must independently re-run the check (no "fixed" trust)
 */
export async function createFixTask(request: FixRequest, ctx: {
  runId: string;
  projectId: string;
  resultId: string;
}): Promise<FixTask> {
  const evidenceText = request.evidenceText.slice(0, 4000);
  const instruction = buildFixInstruction({
    checkId: request.checkId,
    title: request.result.title,
    evidence: evidenceText,
    surface: request.result.affectedSurface.join(', ') || 'unknown',
    invariant: request.result.expected,
  });
  const now = new Date().toISOString();
  const task: FixTask = {
    id: newFixTaskId(),
    runId: ctx.runId,
    projectId: ctx.projectId,
    checkId: request.checkId,
    resultId: ctx.resultId,
    agentId: request.agentId,
    status: 'pending_approval',
    instruction,
    constraints: [
      'Do not change unrelated functionality.',
      'Do not weaken existing security checks.',
      'Do not add new dependencies unless required.',
      'Source is modified only after explicit user approval.',
    ],
    createdAt: now,
    updatedAt: now,
  };
  return task;
}

export async function runFixTask(task: FixTask, opts: {
  approved: boolean;
  dryRun?: boolean;
}): Promise<FixOutcome> {
  if (!opts.approved) {
    return { task: { ...task, status: 'rejected', updatedAt: new Date().toISOString() }, instruction: task.instruction, note: 'fix rejected: source code is never modified without user approval' };
  }
  if (opts.dryRun) {
    return { task: { ...task, status: 'approved', updatedAt: new Date().toISOString() }, instruction: task.instruction, note: 'approved (dry-run): instruction ready; agent not invoked' };
  }
  const adapter = adapterFor((task.agentId ?? 'script') as AgentId);
  const caps = await adapter.discoverCapabilities();
  if (!caps.available) {
    return {
      task: { ...task, status: 'failed', error: caps.gaps.join('; ') || 'agent unavailable', updatedAt: new Date().toISOString() },
      instruction: task.instruction,
      note: `agent ${task.agentId} unavailable — apply the instruction manually, then re-run verification`,
    };
  }
  const session = await adapter.startSession({
    checkId: task.checkId,
    launchContract: {},
    relevantSource: [],
    evidence: [{ instruction: task.instruction.slice(0, 2000) }],
    objective: `Fix ${task.checkId} under the stated constraints`,
    constraints: task.constraints,
  });
  try {
    await adapter.sendInstruction(session, task.instruction);
    const events: string[] = [];
    await adapter.streamEvents(session, (e) => { events.push(`${e.type}: ${e.message.slice(0, 200)}`); });
    const result = await adapter.collectResult(session);
    void randomBytes;
    return {
      task: {
        ...task,
        status: 'completed',
        agentOutput: result.output.slice(0, 8000),
        changedFiles: result.changedFiles,
        updatedAt: new Date().toISOString(),
      },
      instruction: task.instruction,
      agentOutput: result.output.slice(0, 8000),
      note: `agent finished (exit ${String(result.exitCode)}). MUST re-run 'launchproof verify --only ${task.checkId}' independently; agent output is not evidence. Events: ${events.slice(0, 5).join(' | ')}`,
    };
  } finally {
    await adapter.closeSession(session).catch(() => undefined);
  }
}
