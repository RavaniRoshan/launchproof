import type { ChangeAnalysis, NormalizedProject, ProjectRef } from './state.ts';
import type { LaunchContract } from './contract.ts';
import type { CheckResult, RunSummary } from './result.ts';
import type { PhaseId, RunStatus, Verdict } from './types.ts';

export interface PhaseState {
  id: PhaseId;
  status: 'pending' | 'running' | 'done' | 'skipped' | 'error';
  startedAt?: string;
  endedAt?: string;
  note?: string;
}

export interface RunPlanEntry {
  checkId: string;
  phase: PhaseId;
  selectedBy: string[];
}

export interface RunRecord {
  id: string;
  projectId: string;
  projectPath: string;
  profile: string;
  status: RunStatus;
  verdict?: Verdict;
  strict: boolean;
  createdAt: string;
  startedAt?: string;
  endedAt?: string;
  recovered?: boolean;
  cancelRequested?: boolean;
  error?: string;
  phases: PhaseState[];
  plan: RunPlanEntry[];
  summary?: RunSummary;
  changeAnalysis?: ChangeAnalysis;
  contractSnapshot?: LaunchContract;
  projectSnapshot?: NormalizedProject;
  project?: ProjectRef;
  activeCheck?: string;
  activePhase?: PhaseId;
}

export interface RunEvent {
  type:
    | 'run.started'
    | 'run.finished'
    | 'run.cancelled'
    | 'run.error'
    | 'phase.started'
    | 'phase.finished'
    | 'check.started'
    | 'check.finished'
    | 'evidence.created'
    | 'log'
    | 'agent.finding';
  runId: string;
  at: string;
  phase?: PhaseId;
  checkId?: string;
  result?: CheckResult;
  message?: string;
  data?: Record<string, unknown>;
}
