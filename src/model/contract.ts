export interface ContractStack {
  framework?: string;
  database?: string;
  auth?: string;
  payments?: string;
  deployment?: string;
}

export interface ContractSurfaces {
  public_web: boolean;
  api: boolean;
  user_accounts: boolean;
  payments: boolean;
  webhooks: boolean;
  file_storage: boolean;
}

export interface ContractRequired {
  authentication: boolean;
  authorization: boolean;
  database_isolation: boolean;
  webhook_signature_verification: boolean;
  secret_boundary: boolean;
}

export interface ContractRisk {
  handles_personal_data: boolean;
  handles_payments: boolean;
  public_internet: boolean;
}

export interface ProbeIdentity {
  id: string;
  label: string;
  login?: { path: string; body: Record<string, unknown>; method?: string };
  headers?: Record<string, string>;
}

export interface ProbeEndpoint {
  id: string;
  method: string;
  path: string;
  purpose: 'resource' | 'admin' | 'webhook' | 'session' | 'other';
  ownedBy?: string;
  expectUnauthenticated?: number[];
  expectForbidden?: number[];
  body?: Record<string, unknown>;
}

export interface ProbeSession {
  logout?: string;
  recheckPath?: string;
}

export interface ProbeFlow {
  id: string;
  identity: string;
  steps: string[];
}

export interface ProbeBrowserPlan {
  login?: { path: string; userSelector?: string; passSelector?: string; submitSelector?: string };
  protectedPaths?: string[];
  crossUserPaths?: Array<{ path: string; owner: string }>;
  logoutPath?: string;
}

export interface ProbePlan {
  baseUrl?: string;
  identities: ProbeIdentity[];
  endpoints: ProbeEndpoint[];
  session?: ProbeSession;
  flows?: ProbeFlow[];
  browser?: ProbeBrowserPlan;
}

export interface ContractPolicy {
  blockOnSeverities?: string[];
  strict?: boolean;
  disallowedDependencies?: Record<string, string>;
  allowedWorkflowPermissions?: string[];
}

export interface LaunchContract {
  version: 1;
  project: { name: string; path?: string };
  stack: ContractStack;
  surfaces: ContractSurfaces;
  required: ContractRequired;
  risk: ContractRisk;
  environment?: 'local' | 'staging' | 'production';
  probes?: ProbePlan;
  policy?: ContractPolicy;
  meta?: {
    inferred: boolean;
    confirmed: boolean;
    probableFields: string[];
    generatedAt?: string;
  };
}

export interface ContractValidation {
  ok: boolean;
  errors: string[];
  warnings: string[];
}

const SURFACE_KEYS: (keyof ContractSurfaces)[] = [
  'public_web',
  'api',
  'user_accounts',
  'payments',
  'webhooks',
  'file_storage',
];

const REQUIRED_KEYS: (keyof ContractRequired)[] = [
  'authentication',
  'authorization',
  'database_isolation',
  'webhook_signature_verification',
  'secret_boundary',
];

const RISK_KEYS: (keyof ContractRisk)[] = ['handles_personal_data', 'handles_payments', 'public_internet'];

export function emptyContract(name: string, path?: string): LaunchContract {
  return {
    version: 1,
    project: path ? { name, path } : { name },
    stack: {},
    surfaces: {
      public_web: false,
      api: false,
      user_accounts: false,
      payments: false,
      webhooks: false,
      file_storage: false,
    },
    required: {
      authentication: false,
      authorization: false,
      database_isolation: false,
      webhook_signature_verification: false,
      secret_boundary: false,
    },
    risk: {
      handles_personal_data: false,
      handles_payments: false,
      public_internet: false,
    },
    environment: 'local',
    meta: { inferred: false, confirmed: false, probableFields: [] },
  };
}

export function validateContract(raw: unknown): ContractValidation {
  const errors: string[] = [];
  const warnings: string[] = [];
  if (typeof raw !== 'object' || raw === null) {
    return { ok: false, errors: ['contract must be an object'], warnings };
  }
  const c = raw as Partial<LaunchContract>;
  if (c.version !== 1) errors.push('version must be 1');
  if (!c.project || typeof c.project.name !== 'string' || c.project.name.length === 0) {
    errors.push('project.name is required');
  }
  for (const group of ['surfaces', 'required', 'risk'] as const) {
    const value = c[group];
    if (typeof value !== 'object' || value === null) {
      errors.push(`${group} is required`);
      continue;
    }
    const keys = group === 'surfaces' ? SURFACE_KEYS : group === 'required' ? REQUIRED_KEYS : RISK_KEYS;
    for (const key of keys) {
      const v = (value as unknown as Record<string, unknown>)[key];
      if (typeof v !== 'boolean') errors.push(`${group}.${key} must be boolean`);
    }
  }
  if (c.stack && typeof c.stack !== 'object') errors.push('stack must be an object');
  if (c.probes) {
    if (!Array.isArray(c.probes.identities)) errors.push('probes.identities must be an array');
    if (!Array.isArray(c.probes.endpoints)) errors.push('probes.endpoints must be an array');
  }
  if (c.meta?.inferred && !c.meta.confirmed) {
    warnings.push('contract is inferred and not yet confirmed by the user');
  }
  if (c.surfaces?.payments && !c.required?.webhook_signature_verification && c.surfaces.webhooks) {
    warnings.push('payments + webhooks declared but webhook_signature_verification is not required');
  }
  if (c.risk?.handles_payments && !c.surfaces?.payments) {
    warnings.push('risk.handles_payments is true but surfaces.payments is false');
  }
  return { ok: errors.length === 0, errors, warnings };
}
