import type { CheckDefinition, CheckContext, CheckOutcome } from './types.ts';
import { buildHypotheses } from '../adversarial/planner.ts';
import { IdentitySession, callEndpoint, defaultGuard, loginAs, responseExcerpt } from '../api/client.ts';

interface AttemptRecord {
  hypothesis: string;
  vector: string;
  request: Record<string, unknown>;
  response: Record<string, unknown>;
  result: 'attack-succeeded' | 'refuted' | 'not-attempted';
  note?: string;
}

export function agenticChecks(): CheckDefinition[] {
  const adv001: CheckDefinition = {
    id: 'ADV-001',
    title: 'Adversarial hypothesis sweep',
    category: 'adversarial',
    cls: 'agentic',
    phase: 'adversarial',
    severity: 'critical',
    summary:
      'Generates attacker hypotheses from the contract and discovery, then attempts each one against the running build with deterministic probes; every conclusion carries an Observed/Derived/Hypothesized/Unable-to-verify label.',
    invariant: 'No generated attack hypothesis succeeds against the launch candidate.',
    remediation: 'Fix the first succeeded hypothesis using its evidence, then re-run verify.',
    prerequisites: [],
    surfaces: ['api', 'authorization', 'authentication', 'payments', 'webhooks', 'user_accounts'],
    profiles: ['launch', 'security', 'stack'],
    agentFixable: false,
    applies: (contract) => contract.surfaces.api || contract.surfaces.user_accounts || contract.surfaces.webhooks || contract.surfaces.public_web,
    async run(ctx: CheckContext): Promise<CheckOutcome> {
      const hypotheses = buildHypotheses(ctx.contract, ctx.project);
      await ctx.evidence({
        category: 'AGENT',
        title: 'Generated attack hypotheses',
        data: {
          count: hypotheses.length,
          hypotheses: hypotheses.map((h) => ({
            id: h.id,
            vector: h.vector,
            hypothesis: h.hypothesis,
            howToTest: h.howToTest,
            probeRequirement: h.probeRequirement,
          })),
          generation: 'deterministic template planner (offline); LLM expansion is opt-in',
        },
      });

      const probeBacked = hypotheses.filter((h) => h.fallback === 'probe');
      const canAttempt = Boolean(ctx.runtime?.alive) && Boolean(ctx.probes?.endpoints?.length) && ctx.contract.environment !== 'production';

      if (!canAttempt) {
        const unattempted = hypotheses.map((h) => h.id);
        return {
          status: 'UNVERIFIED',
          reason: ctx.contract.environment === 'production'
            ? 'environment is production; adversarial execution refused'
            : `runtime or probe plan unavailable; ${unattempted.length} hypotheses remain untested`,
          affectedSurface: probeBacked.map((h) => h.surfaces).flat(),
          agentLabel: 'Unable to verify',
        };
      }

      const attempts: AttemptRecord[] = [];
      const sessions = new Map<string, IdentitySession>();
      for (const identity of ctx.probes?.identities ?? []) {
        sessions.set(identity.id, await loginAs(ctx.runtime!, identity));
      }
      const endpoints = ctx.probes?.endpoints ?? [];
      const anySession = sessions.values().next().value ?? null;

      for (const h of probeBacked) {
        if (h.vector === 'idor') {
          const owned = endpoints.filter((e) => e.ownedBy);
          if (owned.length === 0) {
            attempts.push({ hypothesis: h.hypothesis, vector: h.vector, request: {}, response: {}, result: 'not-attempted', note: 'no ownedBy endpoints declared' });
            continue;
          }
          for (const endpoint of owned) {
            for (const identity of ctx.probes?.identities ?? []) {
              if (identity.id === endpoint.ownedBy) continue;
              const res = await callEndpoint(ctx.runtime!, endpoint, sessions.get(identity.id) ?? null);
              const succeeded = res.status >= 200 && res.status < 300;
              attempts.push({
                hypothesis: h.hypothesis,
                vector: h.vector,
                request: { identity: identity.id, method: endpoint.method, path: endpoint.path, owner: endpoint.ownedBy },
                response: responseExcerpt(res),
                result: succeeded ? 'attack-succeeded' : 'refuted',
              });
            }
          }
          continue;
        }

        if (h.vector === 'anon_admin') {
          const admins = endpoints.filter((e) => e.purpose === 'admin');
          if (admins.length === 0) {
            attempts.push({ hypothesis: h.hypothesis, vector: h.vector, request: {}, response: {}, result: 'not-attempted', note: 'no admin endpoints declared' });
            continue;
          }
          for (const endpoint of admins) {
            const res = await callEndpoint(ctx.runtime!, endpoint, null, { forceNoAuth: true });
            const guard = defaultGuard(endpoint.expectUnauthenticated);
            attempts.push({
              hypothesis: h.hypothesis,
              vector: h.vector,
              request: { method: endpoint.method, path: endpoint.path, auth: 'none' },
              response: responseExcerpt(res),
              result: guard.includes(res.status) ? 'refuted' : 'attack-succeeded',
            });
          }
          continue;
        }

        if (h.vector === 'logout_reuse') {
          const logoutPath = ctx.probes?.session?.logout;
          const identity = (ctx.probes?.identities ?? []).find((i) => i.login);
          const recheck = ctx.probes?.session?.recheckPath ?? endpoints.find((e) => e.purpose === 'resource')?.path;
          if (!logoutPath || !identity || !recheck) {
            attempts.push({ hypothesis: h.hypothesis, vector: h.vector, request: {}, response: {}, result: 'not-attempted', note: 'session.logout or recheck path missing' });
            continue;
          }
          const session = sessions.get(identity.id);
          const before = await callEndpoint(ctx.runtime!, { id: '__recheck', method: 'GET', path: recheck, purpose: 'resource' }, session ?? null);
          if (before.status >= 400) {
            attempts.push({ hypothesis: h.hypothesis, vector: h.vector, request: { path: recheck }, response: responseExcerpt(before), result: 'not-attempted', note: 'login session could not read resource before logout' });
            continue;
          }
          const captured = session?.header() ?? {};
          await callEndpoint(ctx.runtime!, { id: '__logout', method: 'POST', path: logoutPath, purpose: 'session' }, session ?? null);
          const res = await ctx.runtime!.fetch(recheck, { method: 'GET', headers: { accept: 'application/json', ...captured } });
          const succeeded = res.status >= 200 && res.status < 300;
          attempts.push({
            hypothesis: h.hypothesis,
            vector: h.vector,
            request: { replay: 'captured pre-logout credentials', path: recheck },
            response: { status: res.status },
            result: succeeded ? 'attack-succeeded' : 'refuted',
          });
          continue;
        }

        if (h.vector === 'unsigned_webhook') {
          const hooks = endpoints.filter((e) => e.purpose === 'webhook');
          if (hooks.length === 0) {
            attempts.push({ hypothesis: h.hypothesis, vector: h.vector, request: {}, response: {}, result: 'not-attempted', note: 'no webhook endpoints declared' });
            continue;
          }
          for (const endpoint of hooks) {
            const payload = endpoint.body ? JSON.stringify(endpoint.body) : JSON.stringify({ id: 'evt_adv_probe', type: 'test.event' });
            const res = await callEndpoint(ctx.runtime!, endpoint, null, { forceNoAuth: true, bodyOverride: payload });
            attempts.push({
              hypothesis: h.hypothesis,
              vector: h.vector,
              request: { method: endpoint.method, path: endpoint.path, signature: 'none' },
              response: responseExcerpt(res),
              result: res.status >= 200 && res.status < 300 ? 'attack-succeeded' : 'refuted',
            });
          }
          continue;
        }

        if (h.vector === 'malformed_input') {
          const writes = endpoints.filter((e) => ['POST', 'PUT', 'PATCH'].includes((e.method || 'GET').toUpperCase()) && e.purpose !== 'webhook');
          if (writes.length === 0) {
            attempts.push({ hypothesis: h.hypothesis, vector: h.vector, request: {}, response: {}, result: 'not-attempted', note: 'no write endpoints declared' });
            continue;
          }
          for (const endpoint of writes) {
            const res = await callEndpoint(ctx.runtime!, endpoint, anySession, { bodyOverride: '{"' });
            attempts.push({
              hypothesis: h.hypothesis,
              vector: h.vector,
              request: { method: endpoint.method, path: endpoint.path, body: '{"' },
              response: responseExcerpt(res),
              result: res.status >= 500 ? 'attack-succeeded' : 'refuted',
              note: res.status < 400 ? 'malformed body accepted' : undefined,
            });
          }
          continue;
        }

        attempts.push({ hypothesis: h.hypothesis, vector: h.vector, request: {}, response: {}, result: 'not-attempted', note: 'no probe mapping for this vector' });
      }

      const succeeded = attempts.filter((a) => a.result === 'attack-succeeded');
      const notAttempted = attempts.filter((a) => a.result === 'not-attempted');
      const refuted = attempts.filter((a) => a.result === 'refuted');

      await ctx.evidence({
        category: 'AGENT',
        title: 'Adversarial attempts',
        data: { attempts, summary: { succeeded: succeeded.length, refuted: refuted.length, notAttempted: notAttempted.length } },
        replay: 're-run: launchproof verify --only ADV-001',
      });

      if (succeeded.length > 0) {
        return {
          status: 'BLOCK',
          observed: succeeded.map((a) => `${a.vector}: ${a.request.path ?? a.request.identity ?? 'attack'} → HTTP ${(a.response as { status?: number }).status}`).join('; '),
          affectedSurface: [...new Set(succeeded.flatMap((a) => hypotheses.find((h) => h.vector === a.vector)?.surfaces ?? []))],
          confidence: 'verified',
          agentLabel: 'Observed',
          reproduction: { steps: succeeded.map((a) => JSON.stringify(a.request)).slice(0, 5) },
        };
      }

      if (refuted.length === 0 && notAttempted.length > 0) {
        return {
          status: 'UNVERIFIED',
          reason: `no hypothesis could be executed: ${notAttempted.map((n) => n.note ?? n.vector).join('; ')}`,
          agentLabel: 'Unable to verify',
        };
      }

      return {
        status: 'PASS',
        observed: `${refuted.length} attack attempt(s) refuted by the server${notAttempted.length > 0 ? `; ${notAttempted.length} not attempted (${notAttempted.map((n) => n.vector).join(', ')})` : ''}`,
        confidence: notAttempted.length > 0 ? 'medium' : 'verified',
        agentLabel: 'Observed',
      };
    },
  };

  return [adv001];
}
