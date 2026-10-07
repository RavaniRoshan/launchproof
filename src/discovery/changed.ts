import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { ChangeAnalysis, ChangedSurface } from '../model/state.ts';

const exec = promisify(execFile);

interface PathSurfaceRule {
  re: RegExp;
  surfaces: string[];
}

const RULES: PathSurfaceRule[] = [
  { re: /(migrations?|prisma|drizzle|schema|\.sql$)/i, surfaces: ['database'] },
  { re: /(auth|session|middleware|login|password|rbac|permission|guard|acl)/i, surfaces: ['authentication', 'authorization'] },
  { re: /(stripe|payment|billing|checkout|invoice)/i, surfaces: ['payments', 'webhooks'] },
  { re: /(webhook)/i, surfaces: ['webhooks'] },
  { re: /^\.github\/workflows\//, surfaces: ['ci'] },
  { re: /(dockerfile|docker-compose|vercel\.json|render\.ya?ml|railway|wrangler|fly\.toml|\.env)/i, surfaces: ['infrastructure'] },
  { re: /(secret|credential|\.pem$|id_rsa)/i, surfaces: ['secrets', 'secret_boundary'] },
  { re: /(api\/|routes\/|server\/|endpoint)/i, surfaces: ['api'] },
  { re: /(package\.json|package-lock\.json|pnpm-lock|yarn\.lock|requirements\.txt)/, surfaces: ['dependencies'] },
  { re: /(public\/|src\/app\/page|components\/|\.html$|\.css$)/i, surfaces: ['public_web', 'browser'] },
];

export function surfacesForPath(filePath: string): string[] {
  const surfaces = new Set<string>();
  for (const rule of RULES) {
    if (rule.re.test(filePath)) {
      for (const s of rule.surfaces) surfaces.add(s);
    }
  }
  return [...surfaces];
}

async function git(root: string, args: string[]): Promise<string | null> {
  try {
    const { stdout } = await exec('git', args, { cwd: root, maxBuffer: 1024 * 1024 * 4 });
    return stdout;
  } catch {
    return null;
  }
}

export async function analyzeChanges(root: string, base?: string): Promise<ChangeAnalysis> {
  const inside = await git(root, ['rev-parse', '--is-inside-work-tree']);
  if (inside?.trim() !== 'true') {
    return {
      base: base ?? 'none',
      files: [],
      activatedSurfaces: [],
      activatedReasons: {},
      available: false,
      reason: 'not a git repository',
    };
  }

  const collected = new Map<string, ChangedSurface['change']>();
  const baseRef = base ?? (await git(root, ['rev-parse', '--verify', 'HEAD']))?.trim();

  if (baseRef) {
    const diff = await git(root, ['diff', '--name-status', `${baseRef}...HEAD`]);
    if (diff) {
      for (const line of diff.split('\n')) {
        const [status, ...rest] = line.split('\t');
        if (!status || rest.length === 0) continue;
        const file = rest[rest.length - 1] ?? '';
        if (!file) continue;
        const change: ChangedSurface['change'] = status.startsWith('A')
          ? 'added'
          : status.startsWith('D')
            ? 'deleted'
            : 'modified';
        collected.set(file, change);
      }
    }
  }

  const working = await git(root, ['status', '--porcelain']);
  if (working) {
    for (const line of working.split('\n')) {
      if (line.trim().length === 0) continue;
      const status = line.slice(0, 2);
      const file = line.slice(3).trim();
      if (!file) continue;
      const change: ChangedSurface['change'] = status.includes('A')
        ? 'added'
        : status.includes('D')
          ? 'deleted'
          : 'modified';
      if (!collected.has(file)) collected.set(file, change);
    }
  }

  const files: ChangedSurface[] = [];
  const activatedReasons: Record<string, string> = {};
  for (const [filePath, change] of collected) {
    const surfaces = surfacesForPath(filePath);
    files.push({ path: filePath, change, surfaces });
    for (const surface of surfaces) {
      if (!activatedReasons[surface]) {
        activatedReasons[surface] = `changed file matched surface: ${filePath}`;
      }
    }
  }

  return {
    base: baseRef ?? 'working-tree',
    files,
    activatedSurfaces: Object.keys(activatedReasons),
    activatedReasons,
    available: true,
  };
}
