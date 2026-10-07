import type { CheckDefinition } from './types.ts';
import { repoChecks, secretChecks } from './repo-secrets.ts';
import { authChecks } from './auth.ts';
import { databaseChecks } from './database.ts';
import { paymentChecks, dependencyChecks } from './payments-deps.ts';
import { ciChecks, infraChecks, observabilityChecks } from './ci-infra.ts';
import { webChecks } from './web.ts';
import { dynamicChecks } from './dynamic.ts';
import { browserFlowChecks } from './browserflows.ts';
import { agenticChecks } from './agentic.ts';

export function buildChecks(): CheckDefinition[] {
  return [
    ...repoChecks(),
    ...secretChecks(),
    ...authChecks(),
    ...databaseChecks(),
    ...paymentChecks(),
    ...dependencyChecks(),
    ...ciChecks(),
    ...infraChecks(),
    ...observabilityChecks(),
    ...webChecks(),
    ...dynamicChecks(),
    ...browserFlowChecks(),
    ...agenticChecks(),
  ];
}
