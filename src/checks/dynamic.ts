import type { CheckDefinition, CheckContext, CheckOutcome } from './types.ts';
import type { ProbeEndpoint, ProbeIdentity } from '../model/contract.ts';
import { IdentitySession, callEndpoint, defaultGuard, loginAs, responseExcerpt, runtimeUnavailableReason } from '../api/client.ts';

function gate(ctx: CheckContext): CheckOutcome | null {
  if (ctx.contract.environment === 'production') {
    return { status: 'SKIPPED', reason: 'contract environment is production; dynamic probes refuse to run' };
  }
  const reason = runtimeUnavailableReason(ctx);
  if (reason) return { status: 'UNVERIFIED', reason };
  return null;
}

async function sessionsFor(ctx: CheckContext): Promise<Map<string, IdentitySession>> {
  const map = new Map<string, IdentitySession>();
  const identities: ProbeIdentity[] = ctx.probes?.identities ?? [];
  for (const identity of identities) {
    map.set(identity.id, await loginAs(ctx.runtime!, identity));
  }
  return map;
}

function curlFor(endpoint: ProbeEndpoint, auth: boolean): string {
  const method = (endpoint.method || 'GET').toUpperCase();
  const parts = [`curl -i -X ${method} "${endpoint.path}"`];
  if (auth) parts.push('-H "Cookie: <session>"');
  if (endpoint.body) parts.push(`-d '${JSON.stringify(endpoint.body).slice(0, 200)}'`);
  return parts.join(' ');
}

function noEndpoints(kind: string): CheckOutcome {
  return { status: 'UNVERIFIED', reason: `no ${kind} declared in the probe plan` };
}

export function dynamicChecks(): CheckDefinition[] {
  const auth101: CheckDefinition = {
    id: 'AUTH-101',
    title: 'Cross-user resource access (IDOR)',
    category: 'authorization',
    cls: 'dynamic',
    phase: 'api',
    severity: 'critical',
    summary:
      'If identity A can fetch a resource owned by identity B, every tenant boundary in the product is decorative; this is the classic IDOR failure.',
    invariant: 'A session can only read resources it owns; cross-user reads fail with 401/403/404.',
    remediation: 'Scope every record lookup by the authenticated subject (`where id = ? and ownerId = session.userId`) and return 404 for foreign records.',
    prerequisites: [],
    surfaces: ['api', 'authorization', 'user_accounts'],
    profiles: ['launch', 'security', 'stack'],
    agentFixable: false,
    applies: (contract) => contract.required.authorization || contract.surfaces.user_accounts,
    async run(ctx): Promise<CheckOutcome> {
      const g = gate(ctx);
      if (g) return g;
      const targets = (ctx.probes?.endpoints ?? []).filter((e) => e.ownedBy);
      if (targets.length === 0) return noEndpoints('owned-resource endpoints (set ownedBy)');
      const sessions = await sessionsFor(ctx);

      const requests: Array<Record<string, unknown>> = [];
      const violations: Array<Record<string, unknown>> = [];

      for (const endpoint of targets) {
        for (const identity of ctx.probes?.identities ?? []) {
          if (identity.id === endpoint.ownedBy) continue;
          const session = sessions.get(identity.id) ?? null;
          const res = await callEndpoint(ctx.runtime!, endpoint, session);
          const ok = res.status >= 200 && res.status < 300;
          requests.push({
            identity: identity.id,
            role: `requesting resource owned by ${endpoint.ownedBy}`,
            request: { method: endpoint.method, path: endpoint.path },
            response: responseExcerpt(res),
            verdict: ok ? 'READ OTHER TENANT DATA' : 'denied',
          });
          if (ok) violations.push({ identity: identity.id, endpoint: endpoint.id, path: endpoint.path, status: res.status });
        }
      }

      await ctx.evidence({
        category: 'RUNTIME',
        title: 'Cross-user resource probe',
        data: { requests },
        replay: curlFor(targets[0]!, true),
      });

      if (violations.length > 0) {
        return {
          status: 'BLOCK',
          observed: violations.map((v) => `${String(v.identity)} read ${String(v.path)} (HTTP ${String(v.status)})`).join('; '),
          affectedSurface: targets.map((t) => t.path),
          confidence: 'verified',
        };
      }
      return {
        status: 'PASS',
        observed: `${requests.length} cross-user request(s) denied by the server`,
        confidence: 'verified',
      };
    },
  };

  const auth102: CheckDefinition = {
    id: 'AUTH-102',
    title: 'Admin endpoint reachable without authentication',
    category: 'authentication',
    cls: 'dynamic',
    phase: 'api',
    severity: 'critical',
    summary: 'An admin route that answers anonymous requests with data or actions hands the control plane to anyone who can reach the URL.',
    invariant: 'Admin endpoints reject anonymous requests with 401/403/404.',
    remediation: 'Require an authenticated admin session (and role check) before any handler logic runs; return 401/403 otherwise.',
    prerequisites: [],
    surfaces: ['api', 'authorization'],
    profiles: ['launch', 'security', 'stack'],
    agentFixable: false,
    applies: (contract) => contract.surfaces.api || contract.required.authorization,
    async run(ctx): Promise<CheckOutcome> {
      const g = gate(ctx);
      if (g) return g;
      const targets = (ctx.probes?.endpoints ?? []).filter((e) => e.purpose === 'admin');
      if (targets.length === 0) return noEndpoints('admin endpoints (purpose: admin)');

      const requests: Array<Record<string, unknown>> = [];
      const violations: Array<Record<string, unknown>> = [];
      for (const endpoint of targets) {
        const res = await callEndpoint(ctx.runtime!, endpoint, null, { forceNoAuth: true });
        const guard = defaultGuard(endpoint.expectUnauthenticated);
        const safe = guard.includes(res.status);
        requests.push({ request: { method: endpoint.method, path: endpoint.path }, response: responseExcerpt(res), verdict: safe ? 'rejected' : 'ACCEPTED ANONYMOUSLY' });
        if (!safe) violations.push({ endpoint: endpoint.id, path: endpoint.path, status: res.status });
      }

      await ctx.evidence({ category: 'RUNTIME', title: 'Anonymous admin probe', data: { requests, expectedStatuses: targets.map((t) => ({ path: t.path, expect: defaultGuard(t.expectUnauthenticated) })) }, replay: curlFor(targets[0]!, false) });

      if (violations.length > 0) {
        return {
          status: 'BLOCK',
          observed: violations.map((v) => `${String(v.path)} answered anonymous request with HTTP ${String(v.status)}`).join('; '),
          affectedSurface: targets.map((t) => t.path),
          confidence: 'verified',
        };
      }
      return { status: 'PASS', observed: `all ${targets.length} admin endpoint(s) rejected anonymous requests`, confidence: 'verified' };
    },
  };

  const auth103: CheckDefinition = {
    id: 'AUTH-103',
    title: 'Session persists after logout',
    category: 'authentication',
    cls: 'dynamic',
    phase: 'browser',
    severity: 'critical',
    summary:
      'Replaying a pre-logout session against a protected resource after logout tells you whether logout actually revokes the session or just hides it in the UI.',
    invariant: 'Credentials captured before logout are rejected after logout.',
    remediation:
      'Invalidate the session server-side on logout (session store delete / token denylist) and clear all cookie and token material client-side.',
    prerequisites: [],
    surfaces: ['authentication', 'user_accounts'],
    profiles: ['launch', 'security', 'stack'],
    agentFixable: false,
    applies: (contract) => contract.surfaces.user_accounts || contract.required.authentication,
    async run(ctx): Promise<CheckOutcome> {
      const g = gate(ctx);
      if (g) return g;
      const logoutPath = ctx.probes?.session?.logout;
      const identity = (ctx.probes?.identities ?? []).find((i) => i.login);
      const resource = (ctx.probes?.endpoints ?? []).find((e) => e.purpose === 'resource');
      const recheck = ctx.probes?.session?.recheckPath ?? resource?.path;
      if (!logoutPath || !identity || !recheck) {
        return { status: 'UNVERIFIED', reason: 'probe plan needs session.logout, a login identity and a recheck path to test logout invalidation' };
      }

      const session = await loginAs(ctx.runtime!, identity);
      const before = await callEndpoint(ctx.runtime!, { id: '__recheck', method: 'GET', path: recheck, purpose: 'resource' }, session);
      if (before.status >= 400) {
        await ctx.evidence({ category: 'RUNTIME', title: 'Pre-logout request failed', data: { identity: identity.id, response: responseExcerpt(before) } });
        return { status: 'UNVERIFIED', reason: `login session could not read ${recheck} before logout (HTTP ${before.status})` };
      }

      const capturedHeaders = session.header();
      await callEndpoint(ctx.runtime!, { id: '__logout', method: 'POST', path: logoutPath, purpose: 'session' }, session);

      const res = await ctx.runtime!.fetch(recheck, { method: 'GET', headers: { accept: 'application/json', ...capturedHeaders } });
      const text = await res.clone().text().catch(() => '');
      const replayStillValid = res.status >= 200 && res.status < 300;

      await ctx.evidence({
        category: 'RUNTIME',
        title: 'Post-logout session replay',
        data: {
          identity: identity.id,
          loginPath: identity.login?.path,
          logoutPath,
          recheckPath: recheck,
          preLogout: responseExcerpt(before),
          postLogout: { status: res.status, statusText: res.statusText, bodyPreview: text.slice(0, 400) },
          method: 'replayed captured Cookie/Authorization headers without re-login',
        },
        replay: `curl -i -H "Cookie: <pre-logout session>" "${recheck}"`,
      });

      if (replayStillValid) {
        return {
          status: 'BLOCK',
          observed: `session replayed ${recheck} with HTTP ${res.status} after logout`,
          affectedSurface: [recheck],
          confidence: 'verified',
        };
      }
      return { status: 'PASS', observed: `pre-logout credentials rejected after logout (HTTP ${res.status})`, confidence: 'verified' };
    },
  };

  const api104: CheckDefinition = {
    id: 'API-104',
    title: 'Resource endpoint serves data without authentication',
    category: 'authentication',
    cls: 'dynamic',
    phase: 'api',
    severity: 'critical',
    summary: 'A resource route that returns data to anonymous callers exposes every record the route can reach.',
    invariant: 'Resource endpoints reject anonymous requests with the expected auth status codes.',
    remediation: 'Enforce authentication at the middleware/handler entry and return 401 before touching data.',
    prerequisites: [],
    surfaces: ['api', 'authentication'],
    profiles: ['quick', 'launch', 'security', 'stack'],
    agentFixable: false,
    applies: (contract) => contract.surfaces.api,
    async run(ctx): Promise<CheckOutcome> {
      const g = gate(ctx);
      if (g) return g;
      const targets = (ctx.probes?.endpoints ?? []).filter((e) => e.purpose === 'resource');
      if (targets.length === 0) return noEndpoints('resource endpoints (purpose: resource)');

      const requests: Array<Record<string, unknown>> = [];
      const violations: Array<Record<string, unknown>> = [];
      for (const endpoint of targets) {
        const res = await callEndpoint(ctx.runtime!, endpoint, null, { forceNoAuth: true });
        const guard = defaultGuard(endpoint.expectUnauthenticated);
        const safe = guard.includes(res.status);
        requests.push({ request: { method: endpoint.method, path: endpoint.path }, response: responseExcerpt(res), verdict: safe ? 'rejected' : 'SERVED ANONYMOUSLY' });
        if (!safe) violations.push({ endpoint: endpoint.id, path: endpoint.path, status: res.status });
      }

      await ctx.evidence({ category: 'RUNTIME', title: 'Anonymous resource probe', data: { requests, expectedStatuses: targets.map((t) => ({ path: t.path, expect: defaultGuard(t.expectUnauthenticated) })) }, replay: curlFor(targets[0]!, false) });

      if (violations.length > 0) {
        return {
          status: 'BLOCK',
          observed: violations.map((v) => `${String(v.path)} served anonymous request with HTTP ${String(v.status)}`).join('; '),
          affectedSurface: targets.map((t) => t.path),
          confidence: 'verified',
        };
      }
      return { status: 'PASS', observed: `all ${targets.length} resource endpoint(s) rejected anonymous requests`, confidence: 'verified' };
    },
  };

  const api105: CheckDefinition = {
    id: 'API-105',
    title: 'Malformed input produces server error',
    category: 'api',
    cls: 'dynamic',
    phase: 'api',
    severity: 'major',
    summary: 'A 500 on malformed input means the handler trusts the client shape; in production that is an availability and information-disclosure problem.',
    invariant: 'Malformed request bodies are rejected with 4xx, never 5xx.',
    remediation: 'Validate and parse the body defensively at the boundary (schema validation) and return 400 with a generic message.',
    prerequisites: [],
    surfaces: ['api'],
    profiles: ['launch', 'security', 'stack'],
    agentFixable: false,
    applies: (contract) => contract.surfaces.api,
    async run(ctx): Promise<CheckOutcome> {
      const g = gate(ctx);
      if (g) return g;
      const targets = (ctx.probes?.endpoints ?? []).filter((e) => e.purpose !== 'webhook' && ['POST', 'PUT', 'PATCH'].includes((e.method || 'GET').toUpperCase()));
      if (targets.length === 0) return noEndpoints('POST/PUT/PATCH endpoints (excluding webhooks)');

      const sessions = await sessionsFor(ctx);
      const defaultSession = sessions.values().next().value ?? null;
      const requests: Array<Record<string, unknown>> = [];
      const failures: Array<Record<string, unknown>> = [];

      for (const endpoint of targets) {
        const res = await callEndpoint(ctx.runtime!, endpoint, defaultSession, { bodyOverride: '{"' });
        const record = { request: { method: endpoint.method, path: endpoint.path, body: '{" (truncated JSON)' }, response: responseExcerpt(res) };
        requests.push(record);
        if (res.status >= 500) failures.push({ ...record, problem: '5xx on malformed JSON' });
        else if (res.status < 400) failures.push({ ...record, problem: 'malformed JSON accepted with 2xx' });
      }

      await ctx.evidence({ category: 'RUNTIME', title: 'Malformed input probe', data: { requests }, replay: `curl -i -X POST -H "content-type: application/json" -d '{"' "${targets[0]?.path}"` });

      if (failures.length === 0) {
        return { status: 'PASS', observed: `${targets.length} endpoint(s) rejected malformed input with 4xx`, confidence: 'verified' };
      }
      return {
        status: 'WARN',
        observed: failures.map((f) => `${String((f.request as { path?: string }).path)} → ${String(f.problem)}`).join('; '),
        affectedSurface: targets.map((t) => t.path),
        confidence: 'verified',
      };
    },
  };

  const pay106: CheckDefinition = {
    id: 'PAY-106',
    title: 'Webhook accepts unsigned payload / replays',
    category: 'payments',
    cls: 'dynamic',
    phase: 'api',
    severity: 'critical',
    summary: 'If the endpoint processes events without a valid provider signature, anyone can forge purchases, refunds or privilege changes; replay doubles the damage.',
    invariant: 'Unsigned webhook payloads are rejected, and duplicate deliveries are handled idempotently.',
    remediation: 'Verify the provider signature (reject 400 on failure) and deduplicate on the provider event id.',
    prerequisites: [],
    surfaces: ['webhooks', 'payments'],
    profiles: ['launch', 'security', 'stack'],
    agentFixable: false,
    applies: (contract) => contract.surfaces.webhooks || contract.surfaces.payments,
    async run(ctx): Promise<CheckOutcome> {
      const g = gate(ctx);
      if (g) return g;
      const targets = (ctx.probes?.endpoints ?? []).filter((e) => e.purpose === 'webhook');
      if (targets.length === 0) return noEndpoints('webhook endpoints (purpose: webhook)');

      const attempts: Array<Record<string, unknown>> = [];
      const accepted: Array<Record<string, unknown>> = [];

      for (const endpoint of targets) {
        const payload = endpoint.body ? JSON.stringify(endpoint.body) : JSON.stringify({ id: 'evt_launchproof_test', type: 'test.event', data: {} });
        const first = await callEndpoint(ctx.runtime!, endpoint, null, { forceNoAuth: true, bodyOverride: payload });
        const second = await callEndpoint(ctx.runtime!, endpoint, null, { forceNoAuth: true, bodyOverride: payload });
        attempts.push({
          path: endpoint.path,
          first: responseExcerpt(first),
          second: responseExcerpt(second),
          signatureHeadersSent: false,
          duplicateDeliveryAccepted: second.status >= 200 && second.status < 300,
        });
        if (first.status >= 200 && first.status < 300) {
          accepted.push({ path: endpoint.path, status: first.status, replay: second.status });
        }
      }

      await ctx.evidence({
        category: 'NETWORK',
        title: 'Unsigned webhook probe',
        data: { attempts, note: 'no provider signature header was sent on either attempt' },
        replay: `curl -i -X POST -H "content-type: application/json" -d '{}' "${targets[0]?.path}"`,
      });

      if (accepted.length > 0) {
        return {
          status: 'BLOCK',
          observed: accepted.map((a) => `${String(a.path)} accepted unsigned payload (HTTP ${String(a.status)}; duplicate HTTP ${String(a.replay)})`).join('; '),
          affectedSurface: targets.map((t) => t.path),
          confidence: 'verified',
        };
      }
      return { status: 'PASS', observed: `all ${targets.length} webhook endpoint(s) rejected unsigned payloads`, confidence: 'verified' };
    },
  };

  const flow109: CheckDefinition = {
    id: 'FLOW-109',
    title: 'Critical user flow completes',
    category: 'flows',
    cls: 'dynamic',
    phase: 'runtime',
    severity: 'critical',
    summary: 'The flows the contract declares as launch-critical must actually run end-to-end against the running build, not just in a demo script.',
    invariant: 'Every declared critical flow completes all steps with non-4xx/5xx responses.',
    remediation: 'Fix the first failing step; read the response evidence for the status and body that broke the flow.',
    prerequisites: [],
    surfaces: ['api', 'user_accounts', 'public_web'],
    profiles: ['quick', 'launch', 'stack'],
    agentFixable: false,
    applies: (contract) => Boolean(contract.probes?.flows?.length),
    async run(ctx): Promise<CheckOutcome> {
      const g = gate(ctx);
      if (g) return g;
      const flows = ctx.probes?.flows ?? [];
      if (flows.length === 0) return noEndpoints('flows (probe plan "flows")');

      const sessions = await sessionsFor(ctx);
      const endpointById = new Map((ctx.probes?.endpoints ?? []).map((e) => [e.id, e]));
      const records: Array<Record<string, unknown>> = [];
      const failures: Array<Record<string, unknown>> = [];

      for (const flow of flows) {
        const session = sessions.get(flow.identity) ?? null;
        const steps: Array<Record<string, unknown>> = [];
        let failed = false;
        for (const stepId of flow.steps) {
          const endpoint = endpointById.get(stepId);
          if (!endpoint) {
            steps.push({ step: stepId, error: 'endpoint id not found in probe plan' });
            failures.push({ flow: flow.id, step: stepId, problem: 'unknown endpoint id' });
            failed = true;
            break;
          }
          const res = await callEndpoint(ctx.runtime!, endpoint, session);
          const ok = res.status < 400;
          steps.push({ step: stepId, request: { method: endpoint.method, path: endpoint.path }, status: res.status, verdict: ok ? 'ok' : 'failed' });
          if (!ok) {
            failures.push({ flow: flow.id, step: stepId, path: endpoint.path, status: res.status, problem: `HTTP ${res.status}` });
            failed = true;
            break;
          }
        }
        records.push({ flow: flow.id, identity: flow.identity, steps, result: failed ? 'failed' : 'completed' });
      }

      await ctx.evidence({ category: 'RUNTIME', title: 'Critical flow execution', data: { records }, replay: `re-run: launchproof verify --flows ${flows.map((f) => f.id).join(',')}` });

      if (failures.length > 0) {
        return {
          status: 'BLOCK',
          observed: failures.map((f) => `${String(f.flow)}: step ${String(f.step)} → ${String(f.problem)}`).join('; '),
          affectedSurface: flows.map((f) => f.id),
          confidence: 'verified',
        };
      }
      return { status: 'PASS', observed: `${flows.length} critical flow(s) completed end-to-end`, confidence: 'verified' };
    },
  };

  return [auth101, auth102, auth103, api104, api105, pay106, flow109];
}
