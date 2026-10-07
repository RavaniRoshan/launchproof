import YAML from 'yaml';
import type { CheckDefinition, CheckOutcome } from './types.ts';
import { findSecretsInContent, logCalls, redactLine, stripStringLiterals } from './shared.ts';
import { readText } from '../util/fs.ts';

async function workflowFiles(root: string, files: string[]): Promise<Array<{ path: string; text: string; doc: unknown }>> {
  const out: Array<{ path: string; text: string; doc: unknown }> = [];
  for (const file of files) {
    if (!/^\.github\/workflows\/[^/]+\.(ya?ml)$/.test(file)) continue;
    const text = await readText(root, file);
    if (!text) continue;
    let doc: unknown = null;
    try {
      doc = YAML.parse(text);
    } catch {
      doc = null;
    }
    out.push({ path: file, text, doc });
  }
  return out;
}

interface PermissionNode {
  path: string;
  permissions: Record<string, string> | string | null;
}

function collectPermissions(doc: unknown, fallbackText: string): PermissionNode[] {
  const nodes: PermissionNode[] = [];
  if (doc && typeof doc === 'object') {
    const top = doc as Record<string, unknown>;
    if (top.permissions !== undefined) {
      nodes.push({ path: '<workflow>', permissions: (typeof top.permissions === 'string' ? top.permissions : top.permissions) as Record<string, string> | string });
    }
    const jobs = top.jobs as Record<string, Record<string, unknown>> | undefined;
    if (jobs) {
      for (const [name, job] of Object.entries(jobs)) {
        if (job && typeof job === 'object' && job.permissions !== undefined) {
          nodes.push({ path: `jobs.${name}`, permissions: (typeof job.permissions === 'string' ? job.permissions : job.permissions) as Record<string, string> | string });
        }
      }
    }
  }
  if (nodes.length === 0 && /^\s*permissions\s*:/m.test(fallbackText)) {
    const block = /^\s*permissions\s*:\s*(write-all|read-all|\{\})/m.exec(fallbackText);
    if (block) nodes.push({ path: '<workflow:text>', permissions: block[1] ?? '' });
  }
  return nodes;
}

export function ciChecks(): CheckDefinition[] {
  const ci007: CheckDefinition = {
    id: 'CI-007',
    title: 'Workflow permissions exceed policy',
    category: 'ci',
    cls: 'deterministic',
    phase: 'deployment',
    severity: 'major',
    summary:
      'A workflow with write-all or broad write permissions can push code, create releases or modify secrets if any step is compromised; least privilege keeps blast radius small.',
    invariant: 'Workflow token permissions stay within the configured least-privilege policy.',
    remediation:
      'Replace blanket permissions with an explicit minimal map (for example `contents: read`) at workflow or job level, scoped to the steps that need it.',
    prerequisites: [],
    surfaces: ['ci'],
    profiles: ['launch', 'security', 'agent-change', 'stack'],
    agentFixable: true,
    applies: () => true,
    async run(ctx): Promise<CheckOutcome> {
      const workflows = await workflowFiles(ctx.root, ctx.files);
      if (workflows.length === 0) {
        await ctx.evidence({ category: 'DEPLOYMENT', title: 'No GitHub workflows found', data: {} });
        return { status: 'UNVERIFIED', reason: 'no GitHub Actions workflows found' };
      }

      const allowed = ctx.contract.policy?.allowedWorkflowPermissions ?? [];
      const nodes: PermissionNode[] = [];
      for (const w of workflows) nodes.push(...collectPermissions(w.doc, w.text).map((n) => ({ ...n, path: `${w.path}:${n.path}` })));

      const violations: Array<{ path: string; permissions: unknown; reason: string }> = [];
      for (const node of nodes) {
        if (node.permissions === 'write-all') {
          violations.push({ path: node.path, permissions: node.permissions, reason: 'write-all grants every scope' });
          continue;
        }
        if (node.permissions && typeof node.permissions === 'object') {
          for (const [scope, level] of Object.entries(node.permissions)) {
            if (level !== 'write') continue;
            const explicitAllowed = allowed.includes(`${scope}: write`) || allowed.includes('*: write') || allowed.includes('*');
            if (explicitAllowed) continue;
            violations.push({ path: node.path, permissions: { [scope]: level }, reason: 'write scope not in allowedWorkflowPermissions' });
          }
        }
      }

      await ctx.evidence({
        category: 'DEPLOYMENT',
        title: 'Workflow permission audit',
        data: {
          workflows: workflows.map((w) => w.path),
          declared: nodes.map((n) => ({ path: n.path, permissions: n.permissions })),
          allowedPolicy: allowed,
          violations,
        },
        replay: 'grep -n "permissions" .github/workflows/*',
      });

      if (violations.length === 0) {
        return { status: 'PASS', observed: `${workflows.length} workflow(s), ${nodes.length} permission block(s) within policy` };
      }
      const blocking = violations.filter((v) => v.reason.includes('write-all'));
      return {
        status: blocking.length > 0 ? 'BLOCK' : 'WARN',
        observed: violations.map((v) => `${v.path}: ${v.reason}`).join('; '),
        affectedSurface: violations.map((v) => v.path),
        confidence: 'high',
      };
    },
  };

  const ci008: CheckDefinition = {
    id: 'CI-008',
    title: 'Untrusted event data interpolated into run:',
    category: 'ci',
    cls: 'deterministic',
    phase: 'deployment',
    severity: 'critical',
    summary:
      'Titles, bodies and branch names from issues, PRs and comments are attacker-controlled; interpolating them into shell run blocks allows command injection with the workflow token.',
    invariant: 'Attacker-controlled event fields never appear inside workflow run blocks.',
    remediation:
      'Pass untrusted values through `env:` variables and quote them in the script (`"$TITLE"`), or avoid them entirely.',
    prerequisites: [],
    surfaces: ['ci'],
    profiles: ['launch', 'security', 'agent-change', 'stack'],
    agentFixable: true,
    applies: () => true,
    async run(ctx): Promise<CheckOutcome> {
      const workflows = await workflowFiles(ctx.root, ctx.files);
      if (workflows.length === 0) {
        await ctx.evidence({ category: 'DEPLOYMENT', title: 'No GitHub workflows found', data: {} });
        return { status: 'UNVERIFIED', reason: 'no GitHub workflows found' };
      }
      const untrusted =
        /\$\{\{\s*github\.(?:head_ref|event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.(?:ref|repo\.full_name|label|body))|comment\.body|review\.body|discussion\.(?:title|body)|head_commit\.message|commits\[[^\]]+\]\.message|workflow_run\.head_branch))[^}]*\}\}/g;

      const findings: Array<{ file: string; line: number; match: string }> = [];
      for (const w of workflows) {
        w.text.split('\n').forEach((line, index) => {
          const m = untrusted.exec(line);
          untrusted.lastIndex = 0;
          if (m) findings.push({ file: w.path, line: index + 1, match: m[0].replace(/\s+/g, ' ') });
        });
      }

      await ctx.evidence({
        category: 'DEPLOYMENT',
        title: 'Untrusted interpolation scan',
        data: { workflows: workflows.map((w) => w.path), findings, pattern: untrusted.source.slice(0, 200) },
        replay: 'grep -nE "github.event.(issue|pull_request|comment|head_commit)" .github/workflows/*',
      });
      if (findings.length === 0) {
        return { status: 'PASS', observed: `${workflows.length} workflow(s) contain no untrusted event interpolation in run blocks` };
      }
      return {
        status: 'BLOCK',
        observed: findings.map((f) => `${f.file}:${f.line} ${f.match}`).join('; '),
        affectedSurface: findings.map((f) => f.file),
        reproduction: { command: `sed -n '${findings[0]?.line}p' ${findings[0]?.file}` },
      };
    },
  };

  const ci009: CheckDefinition = {
    id: 'CI-009',
    title: 'pull_request_target with untrusted checkout',
    category: 'ci',
    cls: 'deterministic',
    phase: 'deployment',
    severity: 'critical',
    summary:
      '`pull_request_target` runs with write access to the base repository while a checkout of the PR head executes attacker-controlled code, which is the classic GitHub Actions privilege-escalation path.',
    invariant: 'Workflows triggered by pull_request_target never check out or execute pull-request head code.',
    remediation:
      'Switch the trigger to `pull_request` for code-building jobs, or keep `pull_request_target` only for read-only labeling/comment jobs without head checkout.',
    prerequisites: [],
    surfaces: ['ci'],
    profiles: ['launch', 'security', 'agent-change', 'stack'],
    agentFixable: false,
    applies: () => true,
    async run(ctx): Promise<CheckOutcome> {
      const workflows = await workflowFiles(ctx.root, ctx.files);
      if (workflows.length === 0) {
        await ctx.evidence({ category: 'DEPLOYMENT', title: 'No GitHub workflows found', data: {} });
        return { status: 'UNVERIFIED', reason: 'no GitHub workflows found' };
      }

      const withTarget = workflows.filter((w) => /pull_request_target/.test(w.text));
      const headCheckout = /actions\/checkout[\s\S]{0,400}?ref\s*:\s*\$\{\{\s*github\.event\.pull_request\.head/;

      const dangerous = withTarget.filter((w) => headCheckout.test(w.text));
      await ctx.evidence({
        category: 'DEPLOYMENT',
        title: 'pull_request_target audit',
        data: {
          workflowsUsingTarget: withTarget.map((w) => w.path),
          headCheckoutFound: dangerous.map((w) => w.path),
        },
        replay: 'grep -n "pull_request_target\\|pull_request.head" .github/workflows/*',
      });

      if (dangerous.length > 0) {
        return {
          status: 'BLOCK',
          observed: `${dangerous.length} workflow(s) use pull_request_target and check out the PR head: ${dangerous.map((d) => d.path).join(', ')}`,
          affectedSurface: dangerous.map((d) => d.path),
        };
      }
      if (withTarget.length > 0) {
        return {
          status: 'WARN',
          observed: `pull_request_target used without head checkout (verify no other untrusted code path): ${withTarget.map((w) => w.path).join(', ')}`,
          affectedSurface: withTarget.map((w) => w.path),
          confidence: 'medium',
        };
      }
      return { status: 'PASS', observed: `no pull_request_target triggers in ${workflows.length} workflow(s)` };
    },
  };

  return [ci007, ci008, ci009];
}

export function infraChecks(): CheckDefinition[] {
  const inf001: CheckDefinition = {
    id: 'INFRA-001',
    title: 'Container runs as root',
    category: 'infrastructure',
    cls: 'deterministic',
    phase: 'deployment',
    severity: 'major',
    summary:
      'A container without a USER directive runs as root inside and outside the namespace, so any escape or file-write bug becomes a root compromise.',
    invariant: 'Container images switch to a non-root user before the final stage.',
    remediation: 'Add `USER <non-root>` (after creating the user) in the final Dockerfile stage.',
    prerequisites: [],
    surfaces: ['containers', 'infrastructure'],
    profiles: ['launch', 'security', 'agent-change', 'stack'],
    agentFixable: true,
    applies: () => true,
    async run(ctx): Promise<CheckOutcome> {
      const dockerfiles = ctx.files.filter((f) => /(^|\/)Dockerfile[^/]*$/i.test(f));
      if (dockerfiles.length === 0) {
        await ctx.evidence({ category: 'DEPLOYMENT', title: 'No Dockerfile found', data: {} });
        return { status: 'UNVERIFIED', reason: 'no Dockerfile found' };
      }
      const findings: Array<{ file: string; userLines: number[] }> = [];
      for (const file of dockerfiles) {
        const text = await ctx.read(file);
        if (!text) continue;
        const userLines = text
          .split('\n')
          .map((l, i) => (/^\s*USER\s+\S+/i.test(l) && !l.trim().startsWith('#') ? i + 1 : 0))
          .filter((n) => n > 0);
        if (userLines.length === 0) findings.push({ file, userLines });
      }
      await ctx.evidence({ category: 'DEPLOYMENT', title: 'Dockerfile USER directive audit', data: { dockerfiles, withoutUser: findings.map((f) => f.file) } });
      if (findings.length === 0) {
        return { status: 'PASS', observed: `all ${dockerfiles.length} Dockerfile(s) declare a USER` };
      }
      return {
        status: 'WARN',
        observed: `no USER directive in: ${findings.map((f) => f.file).join(', ')}`,
        affectedSurface: findings.map((f) => f.file),
      };
    },
  };

  const inf002: CheckDefinition = {
    id: 'INFRA-002',
    title: 'Cloud credential embedded in infrastructure config',
    category: 'infrastructure',
    cls: 'deterministic',
    phase: 'deployment',
    severity: 'critical',
    summary:
      'Compose files, deploy manifests and edge configs are copied to servers and CI; a credential inside them leaks with the repository and every environment it deploys to.',
    invariant: 'Infrastructure configuration references secrets by environment variable, never by literal value.',
    remediation: 'Replace the literal with `${VAR}` / an env_file entry supplied by the platform secret store, then rotate the credential.',
    prerequisites: [],
    surfaces: ['infrastructure', 'secrets', 'secret_boundary'],
    profiles: ['launch', 'security', 'agent-change', 'stack'],
    agentFixable: false,
    applies: () => true,
    async run(ctx): Promise<CheckOutcome> {
      const infraRe = /(^|\/)(docker-compose[^/]*\.ya?ml|compose\.ya?ml|Dockerfile[^/]*|wrangler\.toml|render\.ya?ml|fly\.toml|k8s\/.*\.ya?ml|kubernetes\/.*\.ya?ml|\.docker\/config\.json)$/i;
      const infraFiles = ctx.files.filter((f) => infraRe.test(f));
      const findings: Array<{ file: string; line: number; label: string; snippet: string }> = [];

      for (const file of infraFiles) {
        const content = await ctx.read(file);
        if (!content) continue;
        for (const m of findSecretsInContent(content)) {
          findings.push({ file, line: m.line, label: m.label, snippet: redactLine(m.snippet) });
        }
        content.split('\n').forEach((line, index) => {
          const cred = /\b(AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|SERVICE_ROLE(?:_KEY)?|SUPABASE_SERVICE_ROLE|PRIVATE_KEY|DATABASE_URL|POSTGRES_PASSWORD|DB_PASSWORD)\b\s*[:=]\s*["']?([A-Za-z0-9_./+=-]{8,})["']?/i.exec(line);
          if (cred && !/\$\{|\$[A-Z_]|process\.env|env_file|<[^>]+>|secrets\./i.test(cred[2] ?? '')) {
            if (!findings.some((f) => f.file === file && f.line === index + 1)) {
              findings.push({ file, line: index + 1, label: 'literal credential in infra config', snippet: redactLine(line.trim()) });
            }
          }
        });
      }

      await ctx.evidence({
        category: 'DEPLOYMENT',
        title: 'Infrastructure credential scan',
        data: { files: infraFiles, findings },
      });
      if (infraFiles.length === 0) {
        return { status: 'UNVERIFIED', reason: 'no infrastructure config files found to scan' };
      }
      if (findings.length === 0) {
        return { status: 'PASS', observed: `scanned ${infraFiles.length} infra file(s); no embedded credentials` };
      }
      return {
        status: 'BLOCK',
        observed: findings.map((f) => `${f.file}:${f.line} (${f.label})`).join('; '),
        affectedSurface: findings.map((f) => f.file),
      };
    },
  };

  return [inf001, inf002];
}

export function observabilityChecks(): CheckDefinition[] {
  const obs001: CheckDefinition = {
    id: 'OBS-001',
    title: 'Sensitive value written to logs',
    category: 'observability',
    cls: 'deterministic',
    phase: 'static',
    severity: 'major',
    summary:
      'Logging passwords, tokens or keys puts them in log aggregators, CI output and crash reports, multiplying the places a leak can happen.',
    invariant: 'Log statements never print password, token, secret or key values.',
    remediation:
      'Remove the value from the log call or log a safe projection (id, length, last-4) instead; scrub existing log history and rotate exposed credentials.',
    prerequisites: [],
    surfaces: ['observability', 'secrets'],
    profiles: ['quick', 'launch', 'security', 'agent-change', 'stack'],
    agentFixable: true,
    applies: () => true,
    async run(ctx): Promise<CheckOutcome> {
      const SENSITIVE = /\b(?:password|passwd|secret|token|apiKey|api_key|access_token|refresh_token|authorization|credentials|private_key|service_role)\b/i;
      const findings: Array<{ file: string; line: number; snippet: string }> = [];
      let scanned = 0;

      for (const file of ctx.files) {
        if (!/\.(ts|tsx|js|jsx|mjs|cjs|py|rb|go|java)$/.test(file)) continue;
        if (/(^|\/)(test|tests|__tests__|fixtures|study)\//.test(file)) continue;
        const content = await ctx.read(file);
        if (!content || !/console\.|logger\.|log\./.test(content)) continue;
        scanned += 1;
        for (const call of logCalls(content)) {
          const codeOnly = stripStringLiterals(call.args);
          if (SENSITIVE.test(codeOnly)) {
            findings.push({ file, line: call.line, snippet: redactLine(call.args.trim().slice(0, 160)) });
          }
        }
      }

      await ctx.evidence({
        category: 'SOURCE',
        title: 'Log statement scan',
        data: { filesScanned: scanned, findings },
        replay: 'grep -nE "console\\.(log|info|error).*password|token|secret" -r src',
      });
      if (findings.length === 0) {
        return { status: 'PASS', observed: `scanned ${scanned} source file(s); no sensitive values logged` };
      }
      return {
        status: 'WARN',
        observed: findings.map((f) => `${f.file}:${f.line}`).join('; '),
        affectedSurface: findings.map((f) => f.file),
        confidence: 'medium',
      };
    },
  };

  return [obs001];
}
