import path from 'node:path';
import { readText } from '../util/fs.ts';
import { emptyContract, validateContract } from '../model/contract.ts';
import type { LaunchContract } from '../model/contract.ts';
import type { NormalizedProject } from '../model/state.ts';
import YAML from 'yaml';

const hasKey = (hits: Array<{ key: string }>, key: string): boolean =>
  hits.some((h) => h.key.endsWith(`:${key}`));

export async function inferContract(project: NormalizedProject): Promise<LaunchContract> {
  const contract = emptyContract(project.name, project.path);
  contract.meta = { inferred: true, confirmed: false, probableFields: [], generatedAt: new Date().toISOString() };

  const first = (hits: Array<{ key: string; state: string }>): string | undefined =>
    hits.find((h) => h.state === 'detected')?.key.split(':')[1] ?? hits[0]?.key.split(':')[1];

  if (project.framework) contract.stack.framework = project.framework.key.split(':')[1];
  contract.stack.database = first(project.database);
  contract.stack.auth = first(project.auth);
  contract.stack.payments = first(project.payments);
  contract.stack.deployment = first(project.deployment);

  const surfaces = new Set(project.riskSurfaces);
  contract.surfaces.public_web = surfaces.has('public_web');
  contract.surfaces.api = surfaces.has('api');
  contract.surfaces.user_accounts = surfaces.has('authentication');
  contract.surfaces.payments = surfaces.has('payments');
  contract.surfaces.webhooks = surfaces.has('webhooks');
  contract.surfaces.file_storage = (await countMatches(project, /storage|s3|blob|uploadthing|multer/)) > 0;

  contract.required.authentication = contract.surfaces.user_accounts;
  contract.required.authorization = contract.surfaces.user_accounts;
  contract.required.database_isolation = contract.surfaces.user_accounts && Boolean(contract.stack.database);
  contract.required.webhook_signature_verification = contract.surfaces.webhooks;
  contract.required.secret_boundary = true;

  contract.risk.handles_personal_data = contract.surfaces.user_accounts;
  contract.risk.handles_payments = contract.surfaces.payments;
  contract.risk.public_internet = contract.surfaces.public_web;

  const probable: string[] = [];
  if (!contract.stack.framework) probable.push('stack.framework');
  if (contract.surfaces.file_storage) probable.push('surfaces.file_storage');
  contract.meta.probableFields = probable;

  return contract;
}

async function countMatches(project: NormalizedProject, pattern: RegExp): Promise<number> {
  const { walkFiles, readText: read } = await import('../util/fs.ts');
  const files = await walkFiles(project.path, { maxFiles: 400 });
  let count = 0;
  for (const file of files.slice(0, 300)) {
    if (!/\.(ts|tsx|js|jsx|mjs|json|ya?ml|toml)$/.test(file)) continue;
    const content = await read(project.path, file);
    if (content && pattern.test(content)) count += 1;
    if (count > 3) break;
  }
  return count;
}

export interface ContractFileResult {
  contract: LaunchContract;
  source: 'file' | 'inferred';
  validation: ReturnType<typeof validateContract>;
}

export async function loadContract(root: string, project: NormalizedProject): Promise<ContractFileResult> {
  for (const candidate of ['launchproof.yaml', 'launchproof.yml', '.launchproof/contract.yaml']) {
    const raw = await readText(root, candidate);
    if (raw) {
      try {
        const parsed = YAML.parse(raw) as LaunchContract;
        const validation = validateContract(parsed);
        if (validation.ok) {
          parsed.project.path = root;
          return { contract: parsed, source: 'file', validation };
        }
      } catch (error) {
        return {
          contract: await inferContract(project),
          source: 'inferred',
          validation: { ok: false, errors: [`failed to parse ${candidate}: ${String(error)}`], warnings: [] },
        };
      }
    }
  }
  const contract = await inferContract(project);
  return { contract, source: 'inferred', validation: validateContract(contract) };
}

export async function saveContract(root: string, contract: LaunchContract): Promise<string> {
  const { mkdir, writeFile } = await import('node:fs/promises');
  const target = path.join(root, '.launchproof');
  await mkdir(target, { recursive: true });
  const file = path.join(target, 'contract.yaml');
  await writeFile(file, YAML.stringify(contract), 'utf8');
  return file;
}
