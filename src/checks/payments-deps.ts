import type { CheckDefinition, CheckOutcome } from './types.ts';
import { redactLine, versionBelow } from './shared.ts';

export function paymentChecks(): CheckDefinition[] {
  const pay004: CheckDefinition = {
    id: 'PAY-004',
    title: 'Webhook handler without signature verification',
    category: 'payments',
    cls: 'deterministic',
    phase: 'static',
    severity: 'critical',
    summary:
      'A webhook endpoint that trusts the request body without verifying the provider signature lets anyone forge events and trigger paid or privileged side effects.',
    invariant: 'Every webhook handler verifies the provider signature before acting on the payload.',
    remediation:
      'Verify the signature with the provider SDK (for example `stripe.webhooks.constructEvent` with the signing secret) and reject requests that fail verification with 400.',
    prerequisites: [],
    surfaces: ['webhooks', 'payments'],
    profiles: ['launch', 'security', 'agent-change', 'stack'],
    agentFixable: false,
    applies: (contract) => contract.surfaces.webhooks || contract.surfaces.payments,
    async run(ctx): Promise<CheckOutcome> {
      const VERIFY_MARKERS = /constructEvent|verifyWebhookSignature|verifySignature|verify_webhook|validateSignature|signingSecret|whsec_|hmac\.createVerify|timingSafeEqual|nacl\.sign\.detached\.verify/i;
      const webhookSignal = /webhook/i;
      const candidates: Array<{ file: string; verified: boolean; marker: string | null }> = [];

      for (const file of ctx.files) {
        if (!/\.(ts|tsx|js|jsx|mjs|cjs|py|rb|go)$/.test(file)) continue;
        const isWebhookPath = /webhook|hook\//i.test(file);
        const content = await ctx.read(file);
        if (!content) continue;
        if (!isWebhookPath && !/webhooks?\s*[/(]|\/webhook|stripe\.webhooks|handler.*webhook/i.test(content)) continue;
        if (!webhookSignal.test(content)) continue;
        const verify = VERIFY_MARKERS.exec(content);
        candidates.push({ file, verified: Boolean(verify), marker: verify?.[0] ?? null });
      }

      if (candidates.length === 0) {
        await ctx.evidence({ category: 'SOURCE', title: 'No webhook handlers discovered', data: { surfaces: { webhooks: ctx.contract.surfaces.webhooks, payments: ctx.contract.surfaces.payments } } });
        return { status: 'UNVERIFIED', reason: 'contract declares webhooks but no webhook handler file was discovered' };
      }

      const unverified = candidates.filter((c) => !c.verified);
      await ctx.evidence({
        category: 'STATIC_ANALYSIS',
        title: 'Webhook signature verification scan',
        data: {
          checkedMarkers: ['constructEvent', 'verifyWebhookSignature', 'verifySignature', 'hmac', 'timingSafeEqual', 'whsec_'],
          handlers: candidates.map((c) => ({ file: c.file, verified: c.verified, marker: c.marker })),
        },
        replay: `grep -nE "constructEvent|verifySignature|hmac" ${candidates[0]?.file ?? 'webhook*'}`,
      });

      if (unverified.length > 0) {
        return {
          status: 'BLOCK',
          observed: `${unverified.length} webhook handler(s) without signature verification: ${unverified.map((u) => u.file).join(', ')}`,
          affectedSurface: unverified.map((u) => u.file),
        };
      }
      return { status: 'PASS', observed: `${candidates.length} webhook handler(s) verify the provider signature (${candidates.map((c) => c.marker).join(', ')})` };
    },
  };

  const pay005: CheckDefinition = {
    id: 'PAY-005',
    title: 'Charge amount taken from client input',
    category: 'payments',
    cls: 'deterministic',
    phase: 'static',
    severity: 'critical',
    summary:
      'When the server builds a charge from a request-supplied amount, the payer decides the price; the amount must come from a server-side price lookup.',
    invariant: 'Checkout amounts are derived from server-side catalog data, never from request input.',
    remediation:
      'Look up the price by product/price id in server code (or use Price data from your catalog) and reject any client-supplied amount field.',
    prerequisites: [],
    surfaces: ['payments', 'api'],
    profiles: ['launch', 'security', 'agent-change', 'stack'],
    agentFixable: false,
    applies: (contract) => contract.surfaces.payments || contract.risk.handles_payments,
    async run(ctx): Promise<CheckOutcome> {
      const CLIENT_AMOUNT = /\b(?:req\.body|request\.body|body|payload|params|query|data)\s*[.\[]["']?amount["']?\b|\bamount\s*[=:]\s*(?:req|request|body|payload|params|query|data)\b/i;
      const SERVER_PRICE_LOOKUP = /price[s]?\.(?:retrieve|find|lookup)|getPrice|products\.find|catalog|priceId/i;
      const stripeSignal = /stripe|checkout|payment_intent|createPaymentIntent|charge/i;

      const findings: Array<{ file: string; line: number; snippet: string }> = [];
      let candidates = 0;

      for (const file of ctx.files) {
        if (!/\.(ts|tsx|js|jsx|mjs|cjs|py|rb)$/.test(file)) continue;
        const content = await ctx.read(file);
        if (!content || !stripeSignal.test(content)) continue;
        if (!CLIENT_AMOUNT.test(content)) continue;
        candidates += 1;
        if (SERVER_PRICE_LOOKUP.test(content)) continue;
        const lineNo = content.split('\n').findIndex((l) => CLIENT_AMOUNT.test(l)) + 1;
        const snippet = content.split('\n')[lineNo - 1] ?? '';
        findings.push({ file, line: lineNo, snippet: redactLine(snippet.trim().slice(0, 200)) });
      }

      if (candidates === 0) {
        await ctx.evidence({ category: 'SOURCE', title: 'No client-supplied amount in payment code', data: { paymentFiles: ctx.files.filter((f) => /pay|stripe|checkout|billing/i.test(f)).length } });
        return { status: 'PASS', observed: 'no payment code reads an amount from request input' };
      }

      await ctx.evidence({
        category: 'STATIC_ANALYSIS',
        title: 'Client-controlled amount scan',
        data: { checkedForServerPriceLookup: true, findings },
        replay: `grep -nE "body\\.amount|amount:.*body" ${findings[0]?.file ?? 'src/**'}`,
      });
      if (findings.length === 0) {
        return { status: 'PASS', observed: `${candidates} payment file(s) with request amounts all perform a server-side price lookup` };
      }
      return {
        status: 'BLOCK',
        observed: findings.map((f) => `${f.file}:${f.line}`).join('; '),
        affectedSurface: findings.map((f) => f.file),
        confidence: 'medium',
      };
    },
  };

  return [pay004, pay005];
}

const DISALLOWED: Array<{ name: string; below: string; note: string }> = [
  { name: 'lodash', below: '4.17.21', note: 'prototype pollution fixed in 4.17.21 (CVE-2020-8203, CVE-2021-23337)' },
  { name: 'minimist', below: '1.2.6', note: 'prototype pollution fixed in 1.2.6 (CVE-2021-44906)' },
  { name: 'axios', below: '0.21.1', note: 'SSRF fixed in 0.21.1 (CVE-2020-28168)' },
  { name: 'jsonwebtoken', below: '9.0.0', note: 'unrestricted key type / insecure validation fixed in 9.0.0 (CVE-2022-23529)' },
  { name: 'node-fetch', below: '2.6.1', note: 'redirect leak fixed in 2.6.1 (CVE-2022-0235)' },
  { name: 'semver', below: '7.5.2', note: 'ReDoS fixed in 7.5.2 (CVE-2022-25883)' },
];

interface PkgLike {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  scripts?: Record<string, string>;
}

function allDeps(pkg: PkgLike): Array<{ name: string; range: string; kind: string }> {
  const out: Array<{ name: string; range: string; kind: string }> = [];
  for (const kind of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'] as const) {
    const deps = pkg[kind] ?? {};
    for (const [name, range] of Object.entries(deps)) out.push({ name, range, kind });
  }
  return out;
}

async function readPkg(ctx: { read(rel: string): Promise<string | null> }): Promise<PkgLike | null> {
  const raw = await ctx.read('package.json');
  if (!raw) return null;
  try {
    return JSON.parse(raw) as PkgLike;
  } catch {
    return null;
  }
}

export function dependencyChecks(): CheckDefinition[] {
  const dep006: CheckDefinition = {
    id: 'DEP-006',
    title: 'Disallowed dependency version',
    category: 'dependencies',
    cls: 'deterministic',
    phase: 'build',
    severity: 'critical',
    summary:
      'Dependencies pinned below a known-vulnerable fix version reintroduce a documented CVE into the build; the lockfile makes it deterministic.',
    invariant: 'No dependency is installed at a version below its documented security fix.',
    remediation: 'Bump each flagged dependency to at least the fix version and re-run install so the lockfile records it.',
    prerequisites: [],
    surfaces: ['dependencies'],
    profiles: ['quick', 'launch', 'security', 'agent-change', 'stack'],
    agentFixable: true,
    applies: () => true,
    async run(ctx): Promise<CheckOutcome> {
      const pkg = await readPkg(ctx);
      if (!pkg) {
        await ctx.evidence({ category: 'BUILD', title: 'No package.json', data: {} });
        return { status: 'UNVERIFIED', reason: 'no package.json found; dependency policy not applicable' };
      }

      const custom = ctx.contract.policy?.disallowedDependencies ?? {};
      const rules: Array<{ name: string; below: string; note: string }> = [
        ...DISALLOWED,
        ...Object.entries(custom).map(([name, below]) => ({ name, below, note: 'contract policy' })),
      ];

      const findings: Array<{ name: string; installed: string; rule: string; note: string; kind: string }> = [];
      const deps = allDeps(pkg);
      for (const dep of deps) {
        for (const rule of rules) {
          if (rule.name !== dep.name) continue;
          const exact = /^[~^]?[\d.]+$/.test(dep.range.trim());
          if (!exact) continue;
          if (versionBelow(dep.range, rule.below)) {
            findings.push({ name: dep.name, installed: dep.range, rule: `<${rule.below}`, note: rule.note, kind: dep.kind });
          }
        }
      }

      await ctx.evidence({
        category: 'BUILD',
        title: 'Dependency version policy scan',
        data: { rules: rules.map((r) => `${r.name} <${r.below}`), dependenciesChecked: deps.length, findings },
        replay: 'pnpm why <package> && grep the lockfile entry',
      });
      if (findings.length === 0) {
        return { status: 'PASS', observed: `${deps.length} dependency version(s) checked against ${rules.length} rule(s)` };
      }
      return {
        status: 'BLOCK',
        observed: findings.map((f) => `${f.name}@${f.installed} (<${f.rule.replace('<', '')}: ${f.note})`).join('; '),
        affectedSurface: findings.map((f) => f.name),
      };
    },
  };

  const dep007: CheckDefinition = {
    id: 'DEP-007',
    title: 'Dependency lockfile missing',
    category: 'dependencies',
    cls: 'deterministic',
    phase: 'build',
    severity: 'major',
    summary:
      'Without a committed lockfile every install resolves fresh versions, so CI, teammates and future audits can silently run different dependency trees.',
    invariant: 'A lockfile is committed alongside package.json so installs are reproducible.',
    remediation: 'Run the package manager install once and commit the generated lockfile (package-lock.json, pnpm-lock.yaml or yarn.lock).',
    prerequisites: [],
    surfaces: ['dependencies', 'ci'],
    profiles: ['quick', 'launch', 'agent-change', 'stack'],
    agentFixable: true,
    applies: () => true,
    async run(ctx): Promise<CheckOutcome> {
      const pkg = await readPkg(ctx);
      if (!pkg) {
        await ctx.evidence({ category: 'BUILD', title: 'No package.json', data: {} });
        return { status: 'UNVERIFIED', reason: 'no package.json found' };
      }
      const deps = allDeps(pkg);
      const lockfiles = ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lockb', 'npm-shrinkwrap.json'];
      const present: string[] = [];
      for (const l of lockfiles) {
        if (await ctx.read(l)) present.push(l);
      }
      if (deps.length === 0) {
        await ctx.evidence({ category: 'BUILD', title: 'No dependencies declared', data: { lockfiles: present } });
        return { status: 'PASS', observed: 'no dependencies declared' };
      }
      await ctx.evidence({ category: 'BUILD', title: 'Lockfile presence', data: { dependencies: deps.length, checked: lockfiles, present } });
      if (present.length === 0) {
        return {
          status: 'WARN',
          observed: `${deps.length} dependencies declared but no lockfile committed`,
          affectedSurface: ['package.json'],
        };
      }
      return { status: 'PASS', observed: `lockfile present: ${present.join(', ')}` };
    },
  };

  return [dep006, dep007];
}
