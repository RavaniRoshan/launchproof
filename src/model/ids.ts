import { createHash, randomBytes } from 'node:crypto';

let seq = 0;

export function newRunId(): string {
  seq += 1;
  return `run_${Date.now().toString(36)}${seq.toString(36)}${randomBytes(3).toString('hex')}`;
}

export function newProjectId(name: string): string {
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 32) || 'project';
  const hash = createHash('sha256').update(name).digest('hex').slice(0, 6);
  return `${slug}-${hash}`;
}

export function newResultId(checkId: string, runId: string): string {
  const hash = createHash('sha256').update(`${runId}:${checkId}`).digest('hex').slice(0, 8);
  return `R-${hash}`;
}

export function newEvidenceId(runId: string, seqNo: number): string {
  return `E-${String(seqNo).padStart(4, '0')}`;
}

export function newFixTaskId(): string {
  return `fix_${Date.now().toString(36)}${randomBytes(3).toString('hex')}`;
}

export function sha256(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}
