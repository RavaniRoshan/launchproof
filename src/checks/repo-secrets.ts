import type { CheckDefinition } from './types.ts';
import { findSecretsInContent, redactLine } from './shared.ts';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const exec = promisify(execFile);

const SENSITIVE_FILE_RE =
  /(^|\/)(\.env|\.env\.[a-z]+|id_rsa|id_ed25519|[\w.-]*\.pem|[\w.-]*\.p12|[\w.-]*\.key|credentials\.json|service[-_]?account[\w.-]*\.json|[\w.-]*\.pfx)$/i;
const ENV_EXAMPLE_RE = /\.env\.(example|sample|template)|\.env\.dist$/i;

async function trackedFiles(root: string): Promise<string[] | null> {
  try {
    const { stdout } = await exec('git', ['ls-files'], { cwd: root, maxBuffer: 8 * 1024 * 1024 });
    return stdout.split('\n').filter((l) => l.trim().length > 0);
  } catch {
    return null;
  }
}

export function repoChecks(): CheckDefinition[] {
  const repo001: CheckDefinition = {
    id: 'REPO-001',
    title: 'Sensitive file tracked in repository',
    category: 'repository',
    cls: 'deterministic',
    phase: 'static',
    severity: 'critical',
    summary:
      'Credential-bearing files (private keys, .env with live values, credential JSON) must not live in the repository tree where they leak through clones, CI logs, bundles and history.',
    invariant: 'No file containing credentials or private keys exists in the tracked repository tree.',
    remediation:
      'Delete the file from the repository, rotate every credential it contained, add the path to .gitignore, and load values from the environment or a secret manager instead.',
    prerequisites: [],
    surfaces: ['repository', 'secrets'],
    profiles: ['quick', 'launch', 'security', 'agent-change', 'stack'],
    agentFixable: true,
    applies: () => true,
    async run(ctx) {
      const matches: Array<{ file: string; tracked: boolean | null; reasons: string[] }> = [];
      for (const rel of ctx.files) {
        if (!SENSITIVE_FILE_RE.test(rel)) continue;
        if (ENV_EXAMPLE_RE.test(rel)) continue;
        const reasons: string[] = [];
        if (/\.env(\.|$)/i.test(rel)) reasons.push('environment file with potential secrets');
        if (/\.(pem|p12|pfx|key)$/i.test(rel)) reasons.push('key material file');
        if (/id_rsa|id_ed25519/.test(rel)) reasons.push('SSH private key');
        if (/credentials\.json|service[-_]?account/i.test(rel)) reasons.push('cloud credential file');
        matches.push({ file: rel, tracked: null, reasons });
      }

      const tracked = await trackedFiles(ctx.root);
      if (tracked) {
        const trackedSet = new Set(tracked);
        for (const m of matches) m.tracked = trackedSet.has(m.file);
      }

      const detail = matches.map((m) => ({
        file: m.file,
        tracked: m.tracked === null ? 'unknown (not a git repository)' : m.tracked ? 'tracked' : 'present but untracked',
        reasons: m.reasons,
      }));

      if (matches.length === 0) {
        await ctx.evidence({
          category: 'SOURCE',
          title: 'No sensitive files found in repository tree',
          data: { filesScanned: ctx.files.length, pattern: SENSITIVE_FILE_RE.source },
        });
        return { status: 'PASS', observed: `scanned ${ctx.files.length} files; no sensitive files present` };
      }

      const blocking = matches.filter((m) => m.tracked !== false);
      await ctx.evidence({
        category: 'SOURCE',
        title: 'Sensitive files present in repository',
        data: { files: detail },
      });
      if (blocking.length === 0) {
        return {
          status: 'WARN',
          observed: `${matches.length} sensitive file(s) present but untracked: ${matches.map((m) => m.file).join(', ')}`,
          affectedSurface: matches.map((m) => m.file),
        };
      }
      return {
        status: 'BLOCK',
        observed: `${blocking.length} sensitive file(s) present/tracked: ${blocking.map((m) => m.file).join(', ')}`,
        affectedSurface: blocking.map((m) => m.file),
        reproduction: { command: `ls -la ${blocking.map((m) => `"${m.file}"`).join(' ')}` },
      };
    },
  };

  const repo002: CheckDefinition = {
    id: 'REPO-002',
    title: 'Package lifecycle install scripts present',
    category: 'repository',
    cls: 'deterministic',
    phase: 'static',
    severity: 'minor',
    summary:
      'preinstall/postinstall scripts execute arbitrary code on every developer and CI machine at install time, so any dependency compromise or unexpected script becomes a supply-chain execution point.',
    invariant: 'Dependency installation does not execute project-defined lifecycle scripts.',
    remediation:
      'Remove install lifecycle scripts, or document and pin them explicitly and review them on every dependency change.',
    prerequisites: [],
    surfaces: ['dependencies', 'repository'],
    profiles: ['quick', 'launch', 'security', 'agent-change', 'stack'],
    agentFixable: true,
    applies: () => true,
    async run(ctx) {
      const raw = await ctx.read('package.json');
      if (!raw) {
        await ctx.evidence({ category: 'SOURCE', title: 'No package.json', data: {} });
        return { status: 'UNVERIFIED', reason: 'package.json not found' };
      }
      let pkg: Record<string, unknown> = {};
      try {
        pkg = JSON.parse(raw) as Record<string, unknown>;
      } catch {
        return { status: 'ERROR', reason: 'package.json is not valid JSON' };
      }
      const scripts = (pkg.scripts ?? {}) as Record<string, string>;
      const lifecycle = ['preinstall', 'install', 'postinstall'].filter((k) => Boolean(scripts[k]));
      if (lifecycle.length === 0) {
        await ctx.evidence({
          category: 'SOURCE',
          title: 'No install lifecycle scripts',
          data: { file: 'package.json', checked: ['preinstall', 'install', 'postinstall'] },
        });
        return { status: 'PASS', observed: 'no install lifecycle scripts declared' };
      }
      await ctx.evidence({
        category: 'SOURCE',
        title: 'Install lifecycle scripts declared',
        data: {
          file: 'package.json',
          scripts: Object.fromEntries(lifecycle.map((k) => [k, scripts[k] ?? ''])),
        },
      });
      return {
        status: 'WARN',
        observed: `install lifecycle scripts present: ${lifecycle.join(', ')}`,
        affectedSurface: ['package.json'],
      };
    },
  };

  return [repo001, repo002];
}

export function secretChecks(): CheckDefinition[] {
  const secret001: CheckDefinition = {
    id: 'SECRET-001',
    title: 'Server-only credential present in client-served files',
    category: 'secrets',
    cls: 'deterministic',
    phase: 'static',
    severity: 'critical',
    summary:
      'Anything under public/, dist/, .next/static/ or build output is delivered to every browser. A server credential there is readable by anyone who opens devtools.',
    invariant: 'No credential is present in files served to the browser.',
    remediation:
      'Remove the credential, rotate it, and move server-side calls behind an API route or server runtime that reads the value from a server-only environment variable.',
    prerequisites: [],
    surfaces: ['secrets', 'secret_boundary'],
    profiles: ['quick', 'launch', 'security', 'agent-change', 'stack'],
    agentFixable: true,
    applies: () => true,
    async run(ctx) {
      const clientFiles = ctx.files.filter(
        (f) => /(^|\/)(public|dist|out|build|www|client|static)\/|\.next\/static\//.test(f),
      );
      const findings: Array<{ file: string; matches: ReturnType<typeof findSecretsInContent> }> = [];
      let scanned = 0;
      for (const file of clientFiles.slice(0, 400)) {
        if (/\.(map|lock|woff2?|png|jpg|jpeg|gif|svg|ico|mp4|wasm)$/i.test(file)) continue;
        const content = await ctx.read(file);
        if (!content || content.length > 1_500_000) continue;
        scanned += 1;
        const matches = findSecretsInContent(content);
        if (matches.length > 0) findings.push({ file, matches });
      }

      if (findings.length === 0) {
        await ctx.evidence({
          category: 'SOURCE',
          title: 'Client-served files scanned for credentials',
          data: { clientFiles: clientFiles.length, scanned, patternCount: 7 },
        });
        return {
          status: 'PASS',
          observed: `scanned ${scanned} client-served file(s); no credential patterns matched`,
        };
      }

      await ctx.evidence({
        category: 'SOURCE',
        title: 'Credential found in client-served files',
        data: {
          findings: findings.map((f) => ({
            file: f.file,
            matches: f.matches.map((m) => ({ label: m.label, line: m.line, snippet: redactLine(m.snippet) })),
          })),
        },
        replay: 'open the listed files and search for the matched line',
      });
      return {
        status: 'BLOCK',
        observed: findings
          .map((f) => `${f.file}:${f.matches[0]?.line} (${f.matches[0]?.label})`)
          .join('; '),
        affectedSurface: findings.map((f) => f.file),
        reproduction: { command: `grep -nE "(sk_live|AKIA|ghp_|BEGIN.*PRIVATE)" ${findings[0]?.file ?? 'public/**'}` },
      };
    },
  };

  const secret002: CheckDefinition = {
    id: 'SECRET-002',
    title: 'Hardcoded credential in source',
    category: 'secrets',
    cls: 'deterministic',
    phase: 'static',
    severity: 'critical',
    summary:
      'Literal credentials in source leak through repositories, forks, caches and any build artifact that ships the file.',
    invariant: 'No credential literal appears in project source files.',
    remediation: 'Remove the literal, rotate the credential, and read it from an environment variable or secret manager at runtime.',
    prerequisites: [],
    surfaces: ['secrets', 'secret_boundary'],
    profiles: ['quick', 'launch', 'security', 'agent-change', 'stack'],
    agentFixable: true,
    applies: () => true,
    async run(ctx) {
      const findings: Array<{ file: string; matches: ReturnType<typeof findSecretsInContent> }> = [];
      let scanned = 0;
      for (const file of ctx.files) {
        if (!/\.(ts|tsx|js|jsx|mjs|cjs|py|rb|php|go|java|json|ya?ml|toml)$/.test(file)) continue;
        if (/(^|\/)(test|tests|__tests__|fixtures|study)\//.test(file)) continue;
        if (/(^|\/)(package-lock|pnpm-lock|yarn\.lock)/.test(file)) continue;
        const content = await ctx.read(file);
        if (!content || content.length > 1_000_000) continue;
        scanned += 1;
        const matches = findSecretsInContent(content, { allowSecretNamedEnv: true });
        if (matches.length > 0) findings.push({ file, matches });
      }

      if (findings.length === 0) {
        await ctx.evidence({
          category: 'SOURCE',
          title: 'Source scanned for hardcoded credentials',
          data: { scanned },
        });
        return { status: 'PASS', observed: `scanned ${scanned} source file(s); no credential literals matched` };
      }

      await ctx.evidence({
        category: 'SOURCE',
        title: 'Hardcoded credentials detected',
        data: {
          findings: findings.map((f) => ({
            file: f.file,
            matches: f.matches.map((m) => ({ label: m.label, line: m.line, snippet: redactLine(m.snippet) })),
          })),
        },
      });
      return {
        status: 'BLOCK',
        observed: findings
          .slice(0, 8)
          .map((f) => `${f.file}:${f.matches[0]?.line}`)
          .join('; '),
        affectedSurface: findings.map((f) => f.file),
      };
    },
  };

  const env005: CheckDefinition = {
    id: 'ENV-005',
    title: 'Secret exposed through public environment configuration',
    category: 'secrets',
    cls: 'deterministic',
    phase: 'static',
    severity: 'critical',
    summary:
      'Framework public-variable prefixes (NEXT_PUBLIC_, VITE_, REACT_APP_, PUBLIC_) are inlined into the client bundle at build time, so any secret-shaped value there becomes public.',
    invariant: 'No secret-shaped value is declared through a public environment variable.',
    remediation:
      'Rename the variable without the public prefix and read it only in server code, then rotate the exposed value.',
    prerequisites: [],
    surfaces: ['secrets', 'secret_boundary'],
    profiles: ['quick', 'launch', 'security', 'agent-change', 'stack'],
    agentFixable: true,
    applies: () => true,
    async run(ctx) {
      const publicPrefix = /(?:^|\s)(NEXT_PUBLIC_[A-Z0-9_]+|VITE_[A-Z0-9_]+|REACT_APP_[A-Z0-9_]+|PUBLIC_[A-Z0-9_]+)\s*=/;
      const secretName = /(SECRET|PRIVATE_KEY|PASSWORD|API_KEY|TOKEN|CREDENTIAL)/i;
      const findings: Array<{ file: string; line: number; key: string; reason: string }> = [];

      for (const file of ctx.files) {
        if (!/\.env(\.[a-z.]+)?$/i.test(file) && !/(\.env|env)\.(js|ts|json)$/.test(file)) continue;
        const content = await ctx.read(file);
        if (!content) continue;
        content.split('\n').forEach((lineText, index) => {
          const prefixMatch = publicPrefix.exec(lineText);
          if (!prefixMatch) return;
          const key = prefixMatch[1] ?? '';
          const [, value] = /=\s*"?([^"\n#]+)"?/.exec(lineText) ?? [];
          const secretish = secretName.test(key) || (value ? findSecretsInContent(`${key}=${value}`).length > 0 : false);
          if (secretish) {
            findings.push({
              file,
              line: index + 1,
              key,
              reason: secretName.test(key) ? 'public variable name contains secret marker' : 'public variable value matches credential pattern',
            });
          }
        });
      }

      if (findings.length === 0) {
        await ctx.evidence({
          category: 'SOURCE',
          title: 'Public env variables checked',
          data: { scannedEnvFiles: ctx.files.filter((f) => /\.env/i.test(f)).length },
        });
        return { status: 'PASS', observed: 'no secret-shaped public environment variables found' };
      }

      await ctx.evidence({ category: 'SOURCE', title: 'Secret in public env configuration', data: { findings } });
      return {
        status: 'BLOCK',
        observed: findings.map((f) => `${f.file}:${f.line} ${f.key}`).join('; '),
        affectedSurface: findings.map((f) => f.file),
      };
    },
  };

  return [secret001, secret002, env005];
}
