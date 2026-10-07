import path from 'node:path';
import { walkFiles, readText } from '../util/fs.ts';
import { newResultId } from '../model/ids.ts';
import { decideVerdict, summarize, validateResult, ValidationError } from '../model/result.ts';
import type { CheckResult } from '../model/result.ts';
import type { PhaseState, RunEvent, RunRecord, RunPlanEntry } from '../model/run.ts';
import type { LaunchContract } from '../model/contract.ts';
import type { ChangeAnalysis, NormalizedProject } from '../model/state.ts';
import { PHASE_ORDER } from '../model/types.ts';
import type { PhaseId } from '../model/types.ts';
import type { CheckDefinition, CheckContext, CheckOutcome } from '../checks/types.ts';
import type { CheckRegistry } from '../checks/registry.ts';
import type { EvidenceLedger } from '../evidence/ledger.ts';
import { selectChecks } from './selection.ts';
import type { ProfileId } from '../checks/types.ts';
import { generateReport } from './report.ts';

export interface RuntimeState {
  runtime?: import('../checks/types.ts').RuntimeHandle;
  browser?: import('../checks/types.ts').BrowserProvider;
}

export interface PhaseHook {
  phase: PhaseId;
  setup(io: {
    root: string;
    contract: LaunchContract;
    probes?: LaunchContract['probes'];
    scratchDir: string;
    signal: AbortSignal;
    log(message: string): void;
    capabilities: Set<string>;
    state: RuntimeState;
  }): Promise<void>;
  teardown(io: { state: RuntimeState; log(message: string): void }): Promise<void>;
}

export interface EngineOptions {
  run: RunRecord;
  root: string;
  contract: LaunchContract;
  project: NormalizedProject;
  changeAnalysis?: ChangeAnalysis;
  registry: CheckRegistry;
  ledger: EvidenceLedger;
  signal: AbortSignal;
  profile: ProfileId;
  only?: string[];
  strict: boolean;
  scratchDir: string;
  secrets?: string[];
  hooks?: PhaseHook[];
  emit(event: RunEvent): void;
  persistResults(results: CheckResult[]): Promise<void>;
  persistPhases(phases: PhaseState[]): Promise<void>;
}

export interface EngineOutcome {
  results: CheckResult[];
  verdict: 'READY' | 'BLOCKED';
  summary: ReturnType<typeof summarize>;
  phases: PhaseState[];
}

function now(): string {
  return new Date().toISOString();
}

export async function executeRun(options: EngineOptions): Promise<EngineOutcome> {
  const {
    run,
    root,
    contract,
    project,
    changeAnalysis,
    registry,
    ledger,
    signal,
    profile,
    only,
    strict,
    scratchDir,
    secrets = [],
    hooks = [],
    emit,
    persistResults,
    persistPhases,
  } = options;

  const { plan } = selectChecks(registry.all(), { profile, contract, changeAnalysis, only });
  const results: CheckResult[] = [];
  const capabilities = new Set<string>();
  const state: RuntimeState = {};
  const files = await walkFiles(root);
  const readCache = new Map<string, string | null>();

  const phases: PhaseState[] = PHASE_ORDER.map((id) => ({ id, status: 'pending' }));
  await persistPhases(phases);

  const hookByPhase = new Map(hooks.map((h) => [h.phase, h]));

  const read = async (rel: string): Promise<string | null> => {
    if (readCache.has(rel)) return readCache.get(rel) ?? null;
    const value = await readText(root, rel);
    readCache.set(rel, value);
    return value;
  };

  const checksById = new Map<string, CheckDefinition>(registry.all().map((c) => [c.id, c]));
  const planByPhase = new Map<PhaseId, RunPlanEntry[]>();
  for (const entry of plan) {
    const list = planByPhase.get(entry.phase) ?? [];
    list.push(entry);
    planByPhase.set(entry.phase, list);
  }

  const cancelled = () => signal.aborted;

  const makeResult = (
    check: CheckDefinition,
    outcome: CheckOutcome,
    evidence: CheckResult['evidence'],
    startedAt: string,
    durationMs: number,
    prerequisiteFailed?: string,
  ): CheckResult => {
    const base: CheckResult = {
      id: newResultId(check.id, run.id),
      checkId: check.id,
      status: outcome.status,
      severity: check.severity,
      title: check.title,
      category: check.category,
      verificationClass: check.cls,
      evidence,
      affectedSurface: outcome.affectedSurface ?? [],
      expected: check.invariant,
      observed: 'observed' in outcome ? outcome.observed : outcome.reason,
      explanation: check.summary,
      remediation: check.remediation,
      confidence: 'confidence' in outcome && outcome.confidence ? outcome.confidence : check.cls === 'agentic' ? 'agent_claim' : 'high',
      agentFixable: check.agentFixable,
      durationMs,
      startedAt,
      endedAt: now(),
      phase: check.phase,
    };
    if ('reproduction' in outcome && outcome.reproduction) base.reproduction = outcome.reproduction;
    if ('reason' in outcome && outcome.reason) base.reason = outcome.reason;
    if (prerequisiteFailed) base.prerequisiteFailed = prerequisiteFailed;
    if ('agentLabel' in outcome && outcome.agentLabel) base.agentLabel = outcome.agentLabel;
    return base;
  };

  for (const phaseId of PHASE_ORDER) {
    if (phaseId === 'decision' || phaseId === 'report') continue;
    const phaseState = phases.find((p) => p.id === phaseId);
    if (!phaseState) continue;
    const entries = planByPhase.get(phaseId) ?? [];

    if (cancelled()) {
      if (phaseState.status === 'pending') {
        phaseState.status = 'skipped';
        phaseState.note = 'cancelled';
      }
      continue;
    }

    if (entries.length === 0) {
      phaseState.status = 'skipped';
      phaseState.note = 'no checks selected';
      continue;
    }

    phaseState.status = 'running';
    phaseState.startedAt = now();
    emit({ type: 'phase.started', runId: run.id, at: now(), phase: phaseId });
    await persistPhases(phases);

    let phaseFailure: string | null = null;
    const hook = hookByPhase.get(phaseId);
    if (hook) {
      try {
        await hook.setup({
          root,
          contract,
          probes: contract.probes,
          scratchDir: path.join(scratchDir, `phase-${phaseId}`),
          signal,
          log: (message) => emit({ type: 'log', runId: run.id, at: now(), phase: phaseId, message }),
          capabilities,
          state,
        });
      } catch (error) {
        phaseFailure = error instanceof Error ? error.message : String(error);
        emit({ type: 'log', runId: run.id, at: now(), phase: phaseId, message: `phase setup failed: ${phaseFailure}` });
      }
    }

    for (const entry of entries) {
      const check = checksById.get(entry.checkId);
      if (!check) continue;
      if (cancelled()) break;
      const startedAt = now();
      emit({ type: 'check.started', runId: run.id, at: startedAt, phase: phaseId, checkId: check.id });

      let result: CheckResult;
      const missing = check.prerequisites.filter((p) => !capabilities.has(p));
      if (phaseFailure) {
        result = makeResult(
          check,
          { status: 'SKIPPED', reason: `phase ${phaseId} unavailable: ${phaseFailure}` },
          [],
          startedAt,
          0,
          `phase:${phaseId}`,
        );
      } else if (missing.length > 0) {
        result = makeResult(
          check,
          { status: 'SKIPPED', reason: `missing capability: ${missing.join(', ')}` },
          [],
          startedAt,
          0,
          missing.join(','),
        );
      } else {
        const evidenceIds: string[] = [];
        const ctx: CheckContext = {
          root,
          contract,
          project,
          changeAnalysis,
          files,
          read,
          evidence: async (input) => {
            const ref = await ledger.add(check.id, input);
            evidenceIds.push(ref.id);
            emit({ type: 'evidence.created', runId: run.id, at: now(), checkId: check.id, data: { evidenceId: ref.id } });
            return ref.id;
          },
          capabilities,
          probes: contract.probes,
          runtime: state.runtime,
          browser: state.browser,
          scratchDir,
          signal,
          log: (message) => emit({ type: 'log', runId: run.id, at: now(), phase: phaseId, checkId: check.id, message }),
          secrets,
        };
        try {
          const outcome = await check.run(ctx);
          const refs = evidenceIds.map((id) => {
            const record = ledger.get(id);
            return { id, category: record?.category ?? 'STATIC_ANALYSIS', title: record?.title ?? id };
          });
          result = makeResult(check, outcome, refs, startedAt, Date.now() - Date.parse(startedAt));
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          result = makeResult(
            check,
            { status: 'ERROR', reason: `check threw: ${message}` },
            evidenceIds.map((id) => ({ id, category: 'STATIC_ANALYSIS', title: id })),
            startedAt,
            Date.now() - Date.parse(startedAt),
          );
        }
      }

      try {
        validateResult(result);
      } catch (error) {
        const message = error instanceof ValidationError ? error.message : String(error);
        result = {
          ...result,
          status: 'ERROR',
          reason: `invalid check result: ${message}`,
          evidence: result.evidence,
        };
        if (result.status !== 'BLOCK' && result.status !== 'WARN') {
          result = { ...result, evidence: [] };
        }
      }

      results.push(result);
      emit({ type: 'check.finished', runId: run.id, at: now(), phase: phaseId, result });
      await persistResults(results);
    }

    if (hook && phaseId !== 'runtime') {
      try {
        await hook.teardown({ state, log: (m) => emit({ type: 'log', runId: run.id, at: now(), phase: phaseId, message: m }) });
      } catch (error) {
        emit({
          type: 'log',
          runId: run.id,
          at: now(),
          phase: phaseId,
          message: `teardown failed: ${error instanceof Error ? error.message : String(error)}`,
        });
      }
      if (phaseId === 'browser') state.browser = undefined;
    }

    phaseState.status = phaseState.status === 'running' ? (phaseFailure ? 'error' : 'done') : phaseState.status;
    phaseState.endedAt = now();
    if (phaseFailure) phaseState.note = phaseFailure;
    emit({ type: 'phase.finished', runId: run.id, at: now(), phase: phaseId });
    await persistPhases(phases);
  }

  for (const runtimeHook of hooks.filter((h) => h.phase === 'runtime')) {
    try {
      await runtimeHook.teardown({ state, log: (m) => emit({ type: 'log', runId: run.id, at: now(), phase: 'runtime', message: m }) });
    } catch (error) {
      emit({
        type: 'log',
        runId: run.id,
        at: now(),
        phase: 'runtime',
        message: `runtime teardown failed: ${error instanceof Error ? error.message : String(error)}`,
      });
    }
  }
  state.runtime = undefined;

  const decisionPhase = phases.find((p) => p.id === 'decision');
  if (decisionPhase) {
    decisionPhase.status = 'running';
    decisionPhase.startedAt = now();
    await persistPhases(phases);
    const verdict = decideVerdict(results, { strict });
    const summary = summarize(results);
    decisionPhase.status = 'done';
    decisionPhase.endedAt = now();
    decisionPhase.note = verdict;
    await persistPhases(phases);
    const reportPhase = phases.find((p) => p.id === 'report');
    if (reportPhase && !cancelled()) {
      reportPhase.status = 'running';
      reportPhase.startedAt = now();
      const report = generateReport({ run, results, summary, verdict, contract, project });
      emit({ type: 'log', runId: run.id, at: now(), phase: 'report', message: 'report generated' });
      reportPhase.status = 'done';
      reportPhase.endedAt = now();
      reportPhase.note = `report.md (${report.split('\n').length} lines)`;
      await persistPhases(phases);
      await import('node:fs/promises').then((fs) =>
        fs.writeFile(path.join(scratchDir, 'report.md'), report, 'utf8'),
      ).catch(() => undefined);
    }
    return { results, verdict, summary, phases };
  }

  return { results, verdict: decideVerdict(results, { strict }), summary: summarize(results), phases };
}
