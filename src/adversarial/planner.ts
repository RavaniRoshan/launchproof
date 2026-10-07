import type { LaunchContract } from '../model/contract.ts';
import type { NormalizedProject } from '../model/state.ts';

export type AttackVector = 'idor' | 'anon_admin' | 'logout_reuse' | 'unsigned_webhook' | 'amount_tamper' | 'malformed_input' | 'static_only';

export interface Hypothesis {
  id: string;
  vector: AttackVector;
  hypothesis: string;
  howToTest: string;
  surfaces: string[];
  probeRequirement: string;
  fallback: 'probe' | 'static';
}

export function buildHypotheses(contract: LaunchContract, project: NormalizedProject): Hypothesis[] {
  const list: Hypothesis[] = [];

  if (contract.surfaces.user_accounts || contract.required.authorization) {
    list.push({
      id: 'H-IDOR',
      vector: 'idor',
      hypothesis: "A signed-in user can read or modify another user's record by changing the id in the request",
      howToTest: 'Log in as identity A, request a resource owned by identity B, observe the status and body',
      surfaces: ['api', 'authorization', 'user_accounts'],
      probeRequirement: 'probes.endpoints with ownedBy + two login identities',
      fallback: 'probe',
    });
    list.push({
      id: 'H-ADMIN',
      vector: 'anon_admin',
      hypothesis: 'An admin/privileged endpoint answers anonymous requests with data or actions',
      howToTest: 'Call each purpose:admin endpoint with no credentials',
      surfaces: ['api', 'authorization'],
      probeRequirement: 'probes.endpoints with purpose: admin',
      fallback: 'probe',
    });
    list.push({
      id: 'H-LOGOUT',
      vector: 'logout_reuse',
      hypothesis: 'Credentials captured before logout still work after logout',
      howToTest: 'Log in, snapshot cookies/token, call logout, replay the snapshot',
      surfaces: ['authentication', 'user_accounts'],
      probeRequirement: 'probes.session.logout + a recheck path',
      fallback: 'probe',
    });
  }

  if (contract.surfaces.payments || contract.risk.handles_payments) {
    list.push({
      id: 'H-AMOUNT',
      vector: 'amount_tamper',
      hypothesis: 'The charge amount can be supplied or altered by the client',
      howToTest: 'Inspect checkout/charge construction for request-derived amount; if callable, submit a low amount',
      surfaces: ['payments', 'api'],
      probeRequirement: 'static read of payment handlers (dynamic call optional)',
      fallback: 'static',
    });
  }

  if (contract.surfaces.webhooks) {
    list.push({
      id: 'H-WEBHOOK',
      vector: 'unsigned_webhook',
      hypothesis: 'The webhook endpoint processes an unsigned payload and accepts a duplicate delivery',
      howToTest: 'POST an unsigned event twice without provider signature headers',
      surfaces: ['webhooks', 'payments'],
      probeRequirement: 'probes.endpoints with purpose: webhook',
      fallback: 'probe',
    });
  }

  if (contract.surfaces.api) {
    list.push({
      id: 'H-MALFORMED',
      vector: 'malformed_input',
      hypothesis: 'Malformed JSON input produces a 500 instead of a 400',
      howToTest: 'POST truncated JSON to each write endpoint with a valid session',
      surfaces: ['api'],
      probeRequirement: 'POST/PUT/PATCH endpoints in the probe plan',
      fallback: 'probe',
    });
  }

  if (project.framework || project.database.length > 0) {
    list.push({
      id: 'H-STATIC-SECRET',
      vector: 'static_only',
      hypothesis: 'A live credential is committed or bundled where an attacker can fetch it',
      howToTest: 'Pattern scan of repository and client-served output (deterministic checks SECRET-001/002)',
      surfaces: ['secrets', 'secret_boundary'],
      probeRequirement: 'none (static)',
      fallback: 'static',
    });
  }

  return list;
}
