import type { LaunchContract } from '../model/contract.ts';
import type { ChangeAnalysis } from '../model/state.ts';
import type { RunPlanEntry } from '../model/run.ts';
import type { CheckDefinition, ProfileId } from '../checks/types.ts';

export interface SelectionInput {
  profile: ProfileId;
  contract: LaunchContract;
  changeAnalysis?: ChangeAnalysis;
  only?: string[];
}

export interface SelectionResult {
  plan: RunPlanEntry[];
  excluded: Array<{ checkId: string; why: string }>;
}

const PROFILE_BASE: Record<ProfileId, string[]> = {
  quick: ['quick'],
  launch: ['quick', 'launch', 'security'],
  security: ['quick', 'security'],
  'agent-change': ['quick', 'agent-change'],
  stack: ['quick', 'launch', 'stack'],
  custom: ['quick', 'launch', 'security', 'stack', 'agent-change'],
};

const SURFACE_TO_CONTRACT: Record<string, (c: LaunchContract) => boolean> = {
  payments: (c) => c.surfaces.payments || c.risk.handles_payments,
  webhooks: (c) => c.surfaces.webhooks || c.surfaces.payments,
  authentication: (c) => c.surfaces.user_accounts || c.required.authentication,
  authorization: (c) => c.required.authorization || c.surfaces.user_accounts,
  database: (c) => c.required.database_isolation || Boolean(c.stack.database),
  secret_boundary: (c) => c.required.secret_boundary,
  api: (c) => c.surfaces.api,
  public_web: (c) => c.surfaces.public_web,
  ci: () => true,
  repository: () => true,
  dependencies: () => true,
  infrastructure: () => true,
  observability: () => true,
  browser: (c) => c.surfaces.public_web || c.surfaces.user_accounts,
};

export function surfaceActive(surface: string, contract: LaunchContract): boolean {
  const fn = SURFACE_TO_CONTRACT[surface];
  return fn ? fn(contract) : true;
}

export function selectChecks(checks: CheckDefinition[], input: SelectionInput): SelectionResult {
  const plan: RunPlanEntry[] = [];
  const excluded: Array<{ checkId: string; why: string }> = [];
  const base = PROFILE_BASE[input.profile] ?? ['quick'];
  const changedSurfaces = new Set(input.changeAnalysis?.activatedSurfaces ?? []);

  for (const check of checks) {
    if (input.only && input.only.length > 0) {
      if (!input.only.includes(check.id)) {
        excluded.push({ checkId: check.id, why: 'not requested' });
        continue;
      }
    }
    if (!check.applies(input.contract)) {
      excluded.push({ checkId: check.id, why: 'not applicable to launch contract' });
      continue;
    }
    const selectedBy: string[] = [];
    if (check.profiles.some((p) => base.includes(p))) selectedBy.push(`profile:${input.profile}`);
    for (const surface of check.surfaces) {
      if (changedSurfaces.has(surface)) {
        selectedBy.push(`change:${surface}`);
        break;
      }
    }
    if (!selectedBy.some((s) => s.startsWith('change:')) && check.requiredBy?.(input.contract)) {
      selectedBy.push('contract:required');
    }
    if (selectedBy.length === 0) {
      excluded.push({ checkId: check.id, why: 'not selected by profile, change analysis, or contract' });
      continue;
    }
    plan.push({ checkId: check.id, phase: check.phase, selectedBy });
  }

  plan.sort((a, b) => a.phase.localeCompare(b.phase) || a.checkId.localeCompare(b.checkId));
  return { plan, excluded };
}
