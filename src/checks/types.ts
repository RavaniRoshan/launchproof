import type { LaunchContract } from '../model/contract.ts';
import type { ChangeAnalysis, NormalizedProject } from '../model/state.ts';
import type { EvidenceCategory, PhaseId, Severity, VerificationClass, AgentFindingLabel } from '../model/types.ts';
import type { Confidence } from '../model/types.ts';

export type ProfileId = 'quick' | 'launch' | 'security' | 'agent-change' | 'stack' | 'custom';

export interface EvidenceInput {
  category: EvidenceCategory;
  title: string;
  data: Record<string, unknown>;
  replay?: string;
}

export interface RuntimeHandle {
  baseUrl: string;
  logs: string[];
  alive: boolean;
  fetch(path: string, init?: RequestInit): Promise<Response>;
  stop(): Promise<void>;
}

export interface BrowserSession {
  screenshot(name: string): Promise<string>;
  goto(url: string): Promise<void>;
  waitForNavigation(timeoutMs?: number): Promise<boolean>;
  content(): Promise<string>;
  evaluate<T>(fn: string): Promise<T>;
  setCookies(cookies: Array<Record<string, unknown>>): Promise<void>;
  getCookies(): Promise<Array<Record<string, unknown>>>;
  close(): Promise<void>;
}

export interface BrowserProvider {
  available(): boolean;
  newSession(): Promise<BrowserSession>;
}

export interface CheckContext {
  root: string;
  contract: LaunchContract;
  project: NormalizedProject;
  changeAnalysis?: ChangeAnalysis;
  files: string[];
  read(rel: string): Promise<string | null>;
  evidence(input: EvidenceInput): Promise<string>;
  capabilities: ReadonlySet<string>;
  probes?: LaunchContract['probes'];
  runtime?: RuntimeHandle;
  browser?: BrowserProvider;
  scratchDir: string;
  signal: AbortSignal;
  log(message: string): void;
  secrets: string[];
}

export type CheckOutcome =
  | {
      status: 'PASS' | 'BLOCK' | 'WARN';
      observed: string;
      affectedSurface?: string[];
      confidence?: Confidence;
      agentLabel?: AgentFindingLabel;
      reproduction?: { command?: string; steps?: string[] };
    }
  | {
      status: 'SKIPPED' | 'UNVERIFIED' | 'ERROR';
      reason: string;
      affectedSurface?: string[];
      agentLabel?: AgentFindingLabel;
    };

export interface CheckDefinition {
  id: string;
  title: string;
  category: string;
  cls: VerificationClass;
  phase: PhaseId;
  severity: Severity;
  summary: string;
  invariant: string;
  remediation: string;
  prerequisites: string[];
  surfaces: string[];
  requiredBy?: (contract: LaunchContract) => boolean;
  profiles: ProfileId[];
  agentFixable: boolean;
  applies(contract: LaunchContract): boolean;
  run(ctx: CheckContext): Promise<CheckOutcome>;
}
