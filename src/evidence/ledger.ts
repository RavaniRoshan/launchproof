import path from 'node:path';
import { newEvidenceId } from '../model/ids.ts';
import type { EvidenceRef } from '../model/result.ts';
import type { EvidenceRecord } from '../model/state.ts';
import { appendJsonLine, readJsonLines, writeJsonAtomic } from '../storage/paths.ts';
import type { EvidenceInput } from '../checks/types.ts';
import { scrubValue, containsRawSecret } from './scrub.ts';
import { sha256 } from '../model/ids.ts';

export class EvidenceLedger {
  private seq = 0;
  private readonly records = new Map<string, EvidenceRecord>();

  private readonly runId: string;
  private readonly dir: string;
  private readonly secrets: string[];

  constructor(runId: string, dir: string, secrets: string[] = []) {
    this.runId = runId;
    this.dir = dir;
    this.secrets = secrets;
  }

  static async open(runId: string, dir: string, secrets: string[] = []): Promise<EvidenceLedger> {
    const ledger = new EvidenceLedger(runId, dir, secrets);
    const existing = await readJsonLines<EvidenceRecord>(path.join(dir, 'ledger.jsonl'));
    for (const record of existing) {
      ledger.records.set(record.id, record);
      const n = Number(record.id.replace('E-', ''));
      if (Number.isFinite(n) && n > ledger.seq) ledger.seq = n;
    }
    return ledger;
  }

  async add(checkId: string, input: EvidenceInput): Promise<EvidenceRef> {
    this.seq += 1;
    const id = newEvidenceId(this.runId, this.seq);
    const scrubbedData = scrubValue(input.data, this.secrets) as Record<string, unknown>;
    const scrubbed = JSON.stringify(scrubbedData) !== JSON.stringify(input.data);
    const record: EvidenceRecord = {
      id,
      runId: this.runId,
      checkId,
      category: input.category,
      title: input.title,
      data: scrubbedData,
      replay: input.replay ? scrubValue(input.replay, this.secrets) as string : undefined,
      createdAt: new Date().toISOString(),
      sha256: sha256(JSON.stringify(scrubbedData)),
      scrubbed,
    };
    if (containsRawSecret(record, this.secrets)) {
      record.data = { warning: 'evidence redacted after secret detection', originalCategory: input.category };
      record.scrubbed = true;
    }
    this.records.set(id, record);
    await writeJsonAtomic(path.join(this.dir, `${id}.json`), record);
    await appendJsonLine(path.join(this.dir, 'ledger.jsonl'), record);
    return { id, category: record.category, title: record.title };
  }

  get(id: string): EvidenceRecord | undefined {
    return this.records.get(id);
  }

  list(): EvidenceRecord[] {
    return [...this.records.values()].sort((a, b) => a.id.localeCompare(b.id));
  }
}
