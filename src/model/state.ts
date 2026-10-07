import type { AgentFindingLabel, EvidenceCategory } from './types.ts';

export interface EvidenceRecord {
  id: string;
  runId: string;
  checkId: string;
  category: EvidenceCategory;
  title: string;
  data: Record<string, unknown>;
  replay?: string;
  createdAt: string;
  sha256: string;
  scrubbed: boolean;
}

export interface ProjectRef {
  id: string;
  name: string;
  path: string;
  createdAt: string;
  lastRunId?: string;
}

export type DetectorState = 'detected' | 'probable' | 'unknown';

export interface DetectorHit {
  key: string;
  state: DetectorState;
  confidence: number;
  evidence: string[];
}

export interface NormalizedProject {
  id: string;
  name: string;
  path: string;
  languages: string[];
  framework: DetectorHit | null;
  database: DetectorHit[];
  auth: DetectorHit[];
  payments: DetectorHit[];
  deployment: DetectorHit[];
  ci: DetectorHit[];
  containers: DetectorHit[];
  riskSurfaces: string[];
  detectors: DetectorHit[];
  generatedAt: string;
}

export interface ChangedSurface {
  path: string;
  change: 'added' | 'modified' | 'deleted';
  surfaces: string[];
}

export interface ChangeAnalysis {
  base: string;
  files: ChangedSurface[];
  activatedSurfaces: string[];
  activatedReasons: Record<string, string>;
  available: boolean;
  reason?: string;
}

export interface AgentFinding {
  id: string;
  runId: string;
  label: AgentFindingLabel;
  hypothesis: string;
  investigation: string;
  evidenceIds: string[];
  surfaces: string[];
  suggestedCheckId?: string;
  createdAt: string;
}

export interface FixTask {
  id: string;
  runId: string;
  projectId: string;
  checkId: string;
  resultId: string;
  agentId?: string;
  status: 'draft' | 'pending_approval' | 'approved' | 'running' | 'completed' | 'rejected' | 'failed';
  instruction: string;
  constraints: string[];
  approval?: { approvedAt: string; by: string };
  agentOutput?: string;
  changedFiles?: string[];
  reverifyRunId?: string;
  createdAt: string;
  updatedAt: string;
  error?: string;
}
