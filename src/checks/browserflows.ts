import type { CheckDefinition, CheckContext, CheckOutcome, BrowserProvider, BrowserSession } from './types.ts';
import type { ProbeIdentity } from '../model/contract.ts';
import { IdentitySession, loginAs } from '../api/client.ts';

function gateBrowser(ctx: CheckContext): { error: CheckOutcome } | { baseUrl: string; browser: BrowserProvider } {
  if (ctx.contract.environment === 'production') {
    return { error: { status: 'SKIPPED', reason: 'contract environment is production; browser probes refuse to run' } };
  }
  if (!ctx.browser || !ctx.browser.available()) {
    return { error: { status: 'UNVERIFIED', reason: 'browser runtime unavailable (Playwright/Chromium not installed)' } };
  }
  const baseUrl = ctx.probes?.baseUrl ?? ctx.runtime?.baseUrl;
  if (!baseUrl) {
    return { error: { status: 'UNVERIFIED', reason: 'no baseUrl: declare probes.baseUrl or start the runtime lab' } };
  }
  if (!ctx.probes?.browser) {
    return { error: { status: 'UNVERIFIED', reason: 'no browser probe plan (contract probes.browser) available' } };
  }
  return { baseUrl: baseUrl.replace(/\/$/, ''), browser: ctx.browser };
}

function looksLikeLogin(finalUrl: string, content: string): boolean {
  return /login|signin|sign-in|auth(?:\/|%2F)(?:login|signin)|\blogin\b/i.test(finalUrl) || /<input[^>]+type=["']password["']/i.test(content);
}

async function browserLogin(
  browser: BrowserProvider,
  baseUrl: string,
  identity: ProbeIdentity,
  login: NonNullable<NonNullable<NonNullable<import('../model/contract.ts').ProbePlan['browser']>['login']>> | undefined,
): Promise<BrowserSession> {
  const session = await browser.newSession();
  if (login?.path && login.userSelector) {
    await session.goto(`${baseUrl}${login.path}`);
    const body = identity.login?.body ?? {};
    const entries = Object.entries(body);
    const userValue = (entries.find(([k]) => /email|user|login|phone/i.test(k)) ?? entries[0])?.[1];
    const passValue = (entries.find(([k]) => /pass/i.test(k)) ?? entries[1])?.[1];
    const navigation = session.waitForNavigation(8000);
    await session.evaluate<void>(`(() => {
      const set = (sel, val) => { const el = document.querySelector(sel); if (el && val !== undefined) { el.value = String(val); el.dispatchEvent(new Event('input', {bubbles:true})); } };
      set(${JSON.stringify(login.userSelector)}, ${JSON.stringify(userValue === undefined ? '' : String(userValue))});
      set(${JSON.stringify(login.passSelector ?? 'input[type="password"]')}, ${JSON.stringify(passValue === undefined ? '' : String(passValue))});
      const btn = document.querySelector(${JSON.stringify(login.submitSelector ?? 'button[type="submit"], input[type="submit"]')});
      if (btn) btn.click();
      return true;
    })()`);
    await navigation;
    return session;
  }

  const api: IdentitySession = await loginAs(
    { baseUrl, logs: [], alive: true, fetch: (p, i) => fetch(new URL(p, baseUrl), i), stop: async () => undefined },
    identity,
  );
  const cookies = api.cookies.map((pair) => {
    const [name, ...rest] = pair.split('=');
    return { name: name ?? '', value: rest.join('='), url: baseUrl, path: '/' };
  });
  if (cookies.length > 0) await session.setCookies(cookies);
  return session;
}

export function browserFlowChecks(): CheckDefinition[] {
  const b101: CheckDefinition = {
    id: 'BROWSER-101',
    title: 'Protected page reachable in browser without auth',
    category: 'authentication',
    cls: 'dynamic',
    phase: 'browser',
    severity: 'critical',
    summary:
      'Client-side route guards only hide links; if a protected page still renders for an anonymous visitor, the data behind it is one devtools request away.',
    invariant: 'Protected pages redirect anonymous visitors to login instead of rendering.',
    remediation: 'Enforce the guard server-side (middleware or server component session check) so the protected render never happens without a session.',
    prerequisites: [],
    surfaces: ['public_web', 'authentication', 'user_accounts'],
    profiles: ['launch', 'security', 'stack'],
    agentFixable: false,
    applies: (contract) => contract.surfaces.public_web || contract.surfaces.user_accounts,
    async run(ctx): Promise<CheckOutcome> {
      const g = gateBrowser(ctx);
      if ('error' in g) return g.error;
      const paths = ctx.probes?.browser?.protectedPaths ?? [];
      if (paths.length === 0) return { status: 'UNVERIFIED', reason: 'no protectedPaths declared in probes.browser' };

      const records: Array<Record<string, unknown>> = [];
      const violations: Array<string> = [];
      const session = await g.browser.newSession();
      try {
        for (const path of paths) {
          await session.goto(`${g.baseUrl}${path}`);
          const content = await session.content();
          const finalUrl = await session.evaluate<string>('location.href');
          const redirected = looksLikeLogin(finalUrl, content);
          const shot = await session.screenshot(`browser-101-${path.replace(/[^\w]+/g, '_')}`);
          records.push({ path, finalUrl, redirectedToLogin: redirected, screenshot: shot, contentBytes: content.length });
          if (!redirected) violations.push(path);
        }
      } finally {
        await session.close().catch(() => undefined);
      }

      await ctx.evidence({
        category: 'BROWSER',
        title: 'Anonymous browser navigation of protected pages',
        data: { baseUrl: g.baseUrl, records },
        replay: `open ${paths.map((p) => `${g.baseUrl}${p}`).join(', ')} in a private window`,
      });
      if (violations.length > 0) {
        return {
          status: 'BLOCK',
          observed: `rendered without login: ${violations.join(', ')}`,
          affectedSurface: violations,
          confidence: 'verified',
        };
      }
      return { status: 'PASS', observed: `all ${paths.length} protected page(s) redirected anonymous visitors to login`, confidence: 'verified' };
    },
  };

  const b102: CheckDefinition = {
    id: 'BROWSER-102',
    title: 'Cross-user resource visible in browser UI',
    category: 'authorization',
    cls: 'dynamic',
    phase: 'browser',
    severity: 'critical',
    summary: 'If a signed-in user can open another user’s record in the UI, the interface leaks tenant data even when the API looks guarded.',
    invariant: 'The UI never renders a resource owned by a different user for the current session.',
    remediation: 'Return 403/404 from the loader/server component for foreign records and stop prefetching them client-side.',
    prerequisites: [],
    surfaces: ['public_web', 'authorization', 'user_accounts'],
    profiles: ['launch', 'security', 'stack'],
    agentFixable: false,
    applies: (contract) => contract.surfaces.user_accounts || contract.surfaces.public_web,
    async run(ctx): Promise<CheckOutcome> {
      const g = gateBrowser(ctx);
      if ('error' in g) return g.error;
      const targets = ctx.probes?.browser?.crossUserPaths ?? [];
      if (targets.length === 0) return { status: 'UNVERIFIED', reason: 'no crossUserPaths declared in probes.browser' };

      const identities = ctx.probes?.identities ?? [];
      const records: Array<Record<string, unknown>> = [];
      const violations: Array<string> = [];

      for (const target of targets) {
        const intruder = identities.find((i) => i.id !== target.owner && i.login);
        if (!intruder) return { status: 'UNVERIFIED', reason: `need a second login identity besides owner ${target.owner}` };
        const session = await browserLogin(g.browser, g.baseUrl, intruder, ctx.probes?.browser?.login);
        try {
          await session.goto(`${g.baseUrl}${target.path}`);
          const content = await session.content();
          const finalUrl = await session.evaluate<string>('location.href');
          const denied = looksLikeLogin(finalUrl, content) || /\b403\b|forbidden|not\s+found|access\s+denied/i.test(content.slice(0, 4000));
          const shot = await session.screenshot(`browser-102-${target.path.replace(/[^\w]+/g, '_')}`);
          records.push({ path: target.path, viewer: intruder.id, owner: target.owner, finalUrl, denied, screenshot: shot });
          if (!denied) violations.push(`${target.path} (viewer ${intruder.id})`);
        } finally {
          await session.close().catch(() => undefined);
        }
      }

      await ctx.evidence({ category: 'BROWSER', title: 'Cross-user UI navigation', data: { baseUrl: g.baseUrl, records }, replay: `sign in as a non-owner and open ${targets.map((t) => t.path).join(', ')}` });
      if (violations.length > 0) {
        return { status: 'BLOCK', observed: `foreign resource rendered: ${violations.join(', ')}`, affectedSurface: targets.map((t) => t.path), confidence: 'verified' };
      }
      return { status: 'PASS', observed: `${targets.length} cross-user page(s) denied for the viewing identity`, confidence: 'verified' };
    },
  };

  const b103: CheckDefinition = {
    id: 'BROWSER-103',
    title: 'Browser session persists after logout',
    category: 'authentication',
    cls: 'dynamic',
    phase: 'browser',
    severity: 'critical',
    summary: 'A logout that only clears local state leaves the cookie session usable; anyone with the browser profile keeps access.',
    invariant: 'After logout the browser can no longer render protected pages.',
    remediation: 'Delete the server-side session on logout and clear cookie + storage material; verify with a hard reload.',
    prerequisites: [],
    surfaces: ['authentication', 'user_accounts', 'public_web'],
    profiles: ['launch', 'security', 'stack'],
    agentFixable: false,
    applies: (contract) => contract.surfaces.user_accounts || contract.required.authentication,
    async run(ctx): Promise<CheckOutcome> {
      const g = gateBrowser(ctx);
      if ('error' in g) return g.error;
      const browserPlan = ctx.probes?.browser;
      const logoutPath = browserPlan?.logoutPath ?? ctx.probes?.session?.logout;
      const target = browserPlan?.protectedPaths?.[0];
      const identity = (ctx.probes?.identities ?? []).find((i) => i.login);
      if (!logoutPath || !target || !identity) {
        return { status: 'UNVERIFIED', reason: 'browser probe plan needs logoutPath, one protectedPath and a login identity' };
      }

      const session = await browserLogin(g.browser, g.baseUrl, identity, browserPlan?.login);
      const record: Record<string, unknown> = { identity: identity.id, target, logoutPath };
      try {
        await session.goto(`${g.baseUrl}${target}`);
        const beforeContent = await session.content();
        const beforeUrl = await session.evaluate<string>('location.href');
        const beforeRendered = !looksLikeLogin(beforeUrl, beforeContent);
        record.before = { finalUrl: beforeUrl, rendered: beforeRendered, screenshot: await session.screenshot('browser-103-before-logout') };
        if (!beforeRendered) {
          await ctx.evidence({ category: 'BROWSER', title: 'Pre-logout page not rendered', data: record });
          return { status: 'UNVERIFIED', reason: `identity could not view ${target} before logout` };
        }

        await session.goto(`${g.baseUrl}${logoutPath}`);
        await session.goto(`${g.baseUrl}${target}`);
        const afterContent = await session.content();
        const afterUrl = await session.evaluate<string>('location.href');
        const afterRendered = !looksLikeLogin(afterUrl, afterContent);
        record.after = { finalUrl: afterUrl, rendered: afterRendered, screenshot: await session.screenshot('browser-103-after-logout') };
      } finally {
        await session.close().catch(() => undefined);
      }

      await ctx.evidence({ category: 'BROWSER', title: 'Post-logout browser revisit', data: record, replay: `sign in, log out at ${g.baseUrl}${logoutPath}, then hard-reload ${g.baseUrl}${target}` });
      if ((record.after as { rendered?: boolean })?.rendered) {
        return { status: 'BLOCK', observed: `${target} still rendered after logout`, affectedSurface: [target], confidence: 'verified' };
      }
      return { status: 'PASS', observed: `${target} requires login again after logout`, confidence: 'verified' };
    },
  };

  return [b101, b102, b103];
}
