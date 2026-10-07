import path from 'node:path';
import { readText } from '../util/fs.ts';
import type { DetectorHit, DetectorState, NormalizedProject } from '../model/state.ts';

export interface DiscoveryInput {
  root: string;
  files: string[];
  read(rel: string): Promise<string | null>;
}

export interface RuleContext extends DiscoveryInput {
  has(rel: string): boolean;
  pkg: Record<string, unknown> | null;
  deps: Record<string, string>;
  scan(pattern: RegExp, limit?: number): Promise<string[]>;
}

export interface DetectorRule {
  key: string;
  category: 'framework' | 'language' | 'database' | 'auth' | 'payments' | 'deployment' | 'ci' | 'container';
  detect(ctx: RuleContext): Promise<DetectorHit | null>;
}

function hit(key: string, state: DetectorState, confidence: number, evidence: string[]): DetectorHit {
  return { key, state, confidence, evidence };
}

async function parseJson(ctx: RuleContext, rel: string): Promise<Record<string, unknown> | null> {
  const raw = await ctx.read(rel);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function matchFile(files: string[], re: RegExp): string[] {
  return files.filter((f) => re.test(f));
}

const rules: DetectorRule[] = [
  {
    key: 'nextjs',
    category: 'framework',
    async detect(ctx) {
      const config = matchFile(ctx.files, /(^|\/)next\.config\.(js|mjs|ts|cjs)$/);
      const dep = ctx.deps['next'];
      if (config.length) return hit('nextjs', 'detected', 0.95, config);
      if (dep) return hit('nextjs', 'detected', 0.8, [`package.json dependency next@${dep}`]);
      if (ctx.has('app/router.tsx') || matchFile(ctx.files, /(^|\/)app\/(layout|page)\.(tsx|jsx|js)$/).length) {
        return hit('nextjs', 'probable', 0.6, ['app router files present']);
      }
      return null;
    },
  },
  {
    key: 'react',
    category: 'framework',
    async detect(ctx) {
      if (ctx.deps['react']) return hit('react', 'detected', 0.9, [`package.json dependency react@${ctx.deps['react']}`]);
      return null;
    },
  },
  {
    key: 'vite',
    category: 'framework',
    async detect(ctx) {
      const config = matchFile(ctx.files, /(^|\/)vite\.config\.(js|ts|mjs)$/);
      if (config.length) return hit('vite', 'detected', 0.95, config);
      if (ctx.deps['vite']) return hit('vite', 'probable', 0.7, ['vite dependency without config file']);
      return null;
    },
  },
  {
    key: 'nuxt',
    category: 'framework',
    async detect(ctx) {
      const config = matchFile(ctx.files, /(^|\/)nuxt\.config\.(js|ts)$/);
      if (config.length) return hit('nuxt', 'detected', 0.95, config);
      if (ctx.deps['nuxt']) return hit('nuxt', 'detected', 0.85, ['nuxt dependency']);
      return null;
    },
  },
  {
    key: 'node',
    category: 'language',
    async detect(ctx) {
      if (!ctx.pkg) return null;
      const hasServer = matchFile(ctx.files, /(^|\/)(server|index|app)\.(js|ts|mjs)$/).length > 0;
      if (hasServer) return hit('node', 'detected', 0.8, ['server entry file']);
      return hit('node', 'probable', 0.6, ['package.json present']);
    },
  },
  {
    key: 'python',
    category: 'language',
    async detect(ctx) {
      const py = matchFile(ctx.files, /\.py$/);
      if (py.length > 0) return hit('python', 'detected', 0.9, py.slice(0, 3));
      if (ctx.has('requirements.txt') || ctx.has('pyproject.toml')) {
        return hit('python', 'detected', 0.85, ['python project manifest']);
      }
      return null;
    },
  },
  {
    key: 'supabase',
    category: 'database',
    async detect(ctx) {
      const markers: string[] = [];
      if (ctx.has('supabase/config.toml') || matchFile(ctx.files, /^supabase\//).length > 0) {
        markers.push('supabase/ directory');
      }
      if (ctx.deps['@supabase/supabase-js']) markers.push(`dependency @supabase/supabase-js@${ctx.deps['@supabase/supabase-js']}`);
      const used = await ctx.scan(/@supabase\/supabase-js|createClient\(/, 60);
      if (used.length) markers.push(`usage in ${used.slice(0, 2).join(', ')}`);
      if (markers.length === 0) return null;
      const state: DetectorState = used.length > 0 || ctx.has('supabase/config.toml') ? 'detected' : 'probable';
      return hit('supabase', state, state === 'detected' ? 0.92 : 0.7, markers);
    },
  },
  {
    key: 'postgresql',
    category: 'database',
    async detect(ctx) {
      const evidence: string[] = [];
      if (ctx.deps['pg']) evidence.push(`dependency pg@${ctx.deps['pg']}`);
      if (ctx.deps['postgres']) evidence.push(`dependency postgres@${ctx.deps['postgres']}`);
      const urls = await ctx.scan(/postgres(ql)?:\/\//, 30);
      if (urls.length) evidence.push(`connection string form in ${urls.slice(0, 2).join(', ')}`);
      if (matchFile(ctx.files, /(^|\/)(migrations|db)\/.*\.sql$/).length) evidence.push('sql migration files');
      if (evidence.length === 0) return null;
      const strong = ctx.deps['pg'] || ctx.deps['postgres'];
      return hit('postgresql', strong ? 'detected' : 'probable', strong ? 0.9 : 0.65, evidence);
    },
  },
  {
    key: 'mongodb',
    category: 'database',
    async detect(ctx) {
      const evidence: string[] = [];
      if (ctx.deps['mongodb']) evidence.push(`dependency mongodb@${ctx.deps['mongodb']}`);
      if (ctx.deps['mongoose']) evidence.push(`dependency mongoose@${ctx.deps['mongoose']}`);
      if (evidence.length === 0) return null;
      return hit('mongodb', 'detected', 0.9, evidence);
    },
  },
  {
    key: 'prisma',
    category: 'database',
    async detect(ctx) {
      if (ctx.has('prisma/schema.prisma')) return hit('prisma', 'detected', 0.97, ['prisma/schema.prisma']);
      if (ctx.deps['@prisma/client']) return hit('prisma', 'probable', 0.75, ['@prisma/client dependency']);
      return null;
    },
  },
  {
    key: 'drizzle',
    category: 'database',
    async detect(ctx) {
      const config = matchFile(ctx.files, /(^|\/)drizzle\.config\.(ts|js)$/);
      if (config.length) return hit('drizzle', 'detected', 0.95, config);
      if (ctx.deps['drizzle-orm']) return hit('drizzle', 'probable', 0.75, ['drizzle-orm dependency']);
      return null;
    },
  },
  {
    key: 'stripe',
    category: 'payments',
    async detect(ctx) {
      const evidence: string[] = [];
      if (ctx.deps['stripe']) evidence.push(`dependency stripe@${ctx.deps['stripe']}`);
      if (ctx.deps['@stripe/stripe-js']) evidence.push(`dependency @stripe/stripe-js@${ctx.deps['@stripe/stripe-js']}`);
      const used = await ctx.scan(/stripe\.com|stripe\.(checkout|webhooks)|constructEvent/, 60);
      if (used.length) evidence.push(`usage in ${used.slice(0, 2).join(', ')}`);
      if (evidence.length === 0) return null;
      const strong = used.length > 0 || Boolean(ctx.deps['stripe']);
      return hit('stripe', strong ? 'detected' : 'probable', strong ? 0.92 : 0.7, evidence);
    },
  },
  {
    key: 'clerk',
    category: 'auth',
    async detect(ctx) {
      const evidence: string[] = [];
      if (ctx.deps['@clerk/nextjs']) evidence.push('dependency @clerk/nextjs');
      if (ctx.deps['@clerk/clerk-react']) evidence.push('dependency @clerk/clerk-react');
      const used = await ctx.scan(/clerk\.com|@clerk\//, 40);
      if (used.length) evidence.push(`usage in ${used.slice(0, 2).join(', ')}`);
      if (evidence.length === 0) return null;
      return hit('clerk', used.length ? 'detected' : 'probable', used.length ? 0.92 : 0.7, evidence);
    },
  },
  {
    key: 'authjs',
    category: 'auth',
    async detect(ctx) {
      const evidence: string[] = [];
      if (ctx.deps['next-auth']) evidence.push(`dependency next-auth@${ctx.deps['next-auth']}`);
      if (ctx.deps['@auth/core']) evidence.push('dependency @auth/core');
      const used = await ctx.scan(/NextAuth|getServerSession|auth\(\)/, 40);
      if (used.length) evidence.push(`usage in ${used.slice(0, 2).join(', ')}`);
      if (evidence.length === 0) return null;
      return hit('authjs', used.length ? 'detected' : 'probable', used.length ? 0.9 : 0.7, evidence);
    },
  },
  {
    key: 'firebase',
    category: 'auth',
    async detect(ctx) {
      if (ctx.has('firebase.json') && ctx.deps['firebase']) {
        return hit('firebase', 'detected', 0.95, ['firebase.json', `dependency firebase@${ctx.deps['firebase']}`]);
      }
      if (ctx.deps['firebase']) return hit('firebase', 'probable', 0.7, ['firebase dependency']);
      return null;
    },
  },
  {
    key: 'custom-auth',
    category: 'auth',
    async detect(ctx) {
      const used = await ctx.scan(/(?:bcrypt|argon2|jsonwebtoken|jose|createHmac\(['"]sha)/, 60);
      if (used.length === 0) return null;
      return hit('custom-auth', 'probable', 0.72, [`credential/session primitives in ${used.slice(0, 3).join(', ')}`]);
    },
  },
  {
    key: 'vercel',
    category: 'deployment',
    async detect(ctx) {
      if (ctx.has('vercel.json')) return hit('vercel', 'detected', 0.95, ['vercel.json']);
      if (ctx.deps['vercel']) return hit('vercel', 'probable', 0.65, ['vercel dependency']);
      return null;
    },
  },
  {
    key: 'railway',
    category: 'deployment',
    async detect(ctx) {
      if (matchFile(ctx.files, /(^|\/)railway\.(json|toml|yaml)$/).length) {
        return hit('railway', 'detected', 0.9, matchFile(ctx.files, /railway\./));
      }
      return null;
    },
  },
  {
    key: 'render',
    category: 'deployment',
    async detect(ctx) {
      if (matchFile(ctx.files, /(^|\/)render\.ya?ml$/).length) {
        return hit('render', 'detected', 0.9, matchFile(ctx.files, /render\.ya?ml$/));
      }
      return null;
    },
  },
  {
    key: 'cloudflare',
    category: 'deployment',
    async detect(ctx) {
      if (ctx.has('wrangler.toml') || ctx.has('wrangler.jsonc')) {
        return hit('cloudflare', 'detected', 0.95, ['wrangler config']);
      }
      return null;
    },
  },
  {
    key: 'aws',
    category: 'deployment',
    async detect(ctx) {
      const infra = matchFile(ctx.files, /(^|\/)(template|sam|cloudformation)\.(yaml|yml|json)$/);
      const awsRefs = await ctx.scan(/AWS::|aws-sdk|serverless\.yml/, 30);
      if (infra.length === 0 && awsRefs.length === 0) return null;
      return hit('aws', infra.length ? 'detected' : 'probable', infra.length ? 0.9 : 0.65, [
        ...infra.slice(0, 2),
        ...awsRefs.slice(0, 2),
      ]);
    },
  },
  {
    key: 'docker',
    category: 'container',
    async detect(ctx) {
      const files = matchFile(ctx.files, /(^|\/)(Dockerfile|docker-compose\.(yml|yaml))$/);
      if (files.length === 0) return null;
      return hit('docker', 'detected', 0.95, files);
    },
  },
  {
    key: 'github-actions',
    category: 'ci',
    async detect(ctx) {
      const files = matchFile(ctx.files, /^\.github\/workflows\/.*\.ya?ml$/);
      if (files.length === 0) return null;
      return hit('github-actions', 'detected', 0.97, files);
    },
  },
];

function deriveSurfaces(project: NormalizedProject): string[] {
  const surfaces = new Set<string>(['secrets', 'dependencies', 'repository', 'observability', 'api']);
  if (project.auth.length > 0) {
    surfaces.add('authentication');
    surfaces.add('authorization');
  }
  if (project.database.length > 0) surfaces.add('database');
  if (project.payments.length > 0) {
    surfaces.add('payments');
    surfaces.add('webhooks');
  }
  if (project.ci.length > 0) surfaces.add('ci');
  if (project.deployment.length > 0 || project.containers.length > 0) surfaces.add('infrastructure');
  if (project.framework) {
    surfaces.add('public_web');
    surfaces.add('browser');
  }
  return [...surfaces];
}

export async function discoverProject(input: {
  id: string;
  name: string;
  root: string;
  files?: string[];
}): Promise<{ project: NormalizedProject; files: string[] }> {
  const files = input.files ?? (await (async () => {
    const { walkFiles } = await import('../util/fs.ts');
    return walkFiles(input.root);
  })());

  const pkgRaw = await readText(input.root, 'package.json');
  let pkg: Record<string, unknown> | null = null;
  try {
    pkg = pkgRaw ? (JSON.parse(pkgRaw) as Record<string, unknown>) : null;
  } catch {
    pkg = null;
  }
  const deps: Record<string, string> = {};
  for (const group of ['dependencies', 'devDependencies']) {
    const section = pkg?.[group];
    if (section && typeof section === 'object') {
      for (const [k, v] of Object.entries(section as Record<string, string>)) deps[k] = String(v);
    }
  }

  const scanCache = new Map<number, string[]>();
  const ctx: RuleContext = {
    root: input.root,
    files,
    read: (rel) => readText(input.root, rel),
    has: (rel) => files.includes(rel),
    pkg,
    deps,
    scan: async (pattern, limit = 50) => {
      const key = pattern.source.length;
      if (scanCache.has(key)) return (scanCache.get(key) ?? []).slice(0, limit);
      const hits: string[] = [];
      const candidates = files.filter((f) => /\.(jsx?|tsx?|mjs|cjs|sql|ya?ml|json|env|toml)$/.test(f) || /\.env/.test(f));
      for (const file of candidates.slice(0, 600)) {
        const content = await readText(input.root, file);
        if (content && pattern.test(content)) {
          hits.push(file);
          if (hits.length >= 100) break;
        }
      }
      scanCache.set(key, hits);
      return hits.slice(0, limit);
    },
  };

  const hits: DetectorHit[] = [];
  for (const rule of rules) {
    try {
      const result = await rule.detect(ctx);
      if (result) hits.push({ ...result, key: `${rule.category}:${result.key}` });
    } catch {
      // detector failure is non-fatal; state stays unknown
    }
  }

  const pick = (category: string) => hits.filter((h) => h.key.startsWith(`${category}:`));
  const languages = [
    ...(files.some((f) => /\.tsx?$/.test(f)) ? ['typescript'] : []),
    ...(files.some((f) => /\.jsx?$|\.mjs$|\.cjs$/.test(f)) ? ['javascript'] : []),
    ...(files.some((f) => f.endsWith('.py')) ? ['python'] : []),
  ];

  const project: NormalizedProject = {
    id: input.id,
    name: input.name,
    path: input.root,
    languages,
    framework: pick('framework')[0] ?? null,
    database: pick('database'),
    auth: pick('auth'),
    payments: pick('payments'),
    deployment: pick('deployment'),
    ci: pick('ci'),
    containers: pick('container'),
    riskSurfaces: [],
    detectors: hits,
    generatedAt: new Date().toISOString(),
  };

  const surfaces = deriveSurfaces(project);
  project.riskSurfaces = surfaces;

  return { project, files };
}
