import type { ProbeEndpoint, ProbeIdentity } from '../model/contract.ts';
import type { RuntimeHandle } from '../checks/types.ts';

export interface CapturedResponse {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
}

export class IdentitySession {
  cookies: string[] = [];
  token: string | null = null;
  loggedIn = false;

  header(): Record<string, string> {
    const out: Record<string, string> = {};
    if (this.cookies.length > 0) out.Cookie = this.cookies.join('; ');
    if (this.token) out.Authorization = `Bearer ${this.token}`;
    return out;
  }

  absorb(res: Response): void {
    const raw = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [];
    const single = res.headers.get('set-cookie');
    const list = raw.length > 0 ? raw : single ? [single] : [];
    for (const cookie of list) {
      const pair = cookie.split(';')[0] ?? '';
      if (!pair.includes('=')) continue;
      const name = pair.split('=')[0]?.trim();
      if (!name) continue;
      this.cookies = this.cookies.filter((c) => !c.startsWith(`${name}=`));
      this.cookies.push(pair.trim());
    }
  }

  async absorbBody(res: Response): Promise<void> {
    this.absorb(res);
    const text = await res.clone().text();
    try {
      const json = JSON.parse(text) as Record<string, unknown>;
      const token = json.token ?? json.access_token ?? json.accessToken ?? json.jwt;
      if (typeof token === 'string' && token.length > 8) this.token = token;
    } catch {
      /* body is not JSON; cookie auth only */
    }
  }
}

export async function loginAs(runtime: RuntimeHandle, identity: ProbeIdentity): Promise<IdentitySession> {
  const session = new IdentitySession();
  if (!identity.login) {
    session.loggedIn = false;
    return session;
  }
  const method = (identity.login.method ?? 'POST').toUpperCase();
  const res = await runtime.fetch(identity.login.path, {
    method,
    headers: { 'content-type': 'application/json', ...(identity.headers ?? {}) },
    body: method === 'GET' ? undefined : JSON.stringify(identity.login.body),
  });
  await session.absorbBody(res).catch(() => undefined);
  session.loggedIn = res.status < 400;
  return session;
}

export async function callEndpoint(
  runtime: RuntimeHandle,
  endpoint: ProbeEndpoint,
  session: IdentitySession | null,
  opts: { bodyOverride?: string; forceNoAuth?: boolean } = {},
): Promise<CapturedResponse> {
  const method = (endpoint.method || 'GET').toUpperCase();
  const headers: Record<string, string> = { accept: 'application/json', ...(endpoint.body ? { 'content-type': 'application/json' } : {}) };
  if (session && !opts.forceNoAuth) Object.assign(headers, session.header());

  const body = opts.bodyOverride !== undefined ? opts.bodyOverride : endpoint.body ? JSON.stringify(endpoint.body) : undefined;
  const res = await runtime.fetch(endpoint.path, {
    method,
    headers,
    body: body && method !== 'GET' && method !== 'HEAD' ? body : undefined,
  });
  if (session && !opts.forceNoAuth) session.absorb(res);
  const text = await res.clone().text().catch(() => '');
  const headerMap: Record<string, string> = {};
  res.headers.forEach((value, key) => {
    headerMap[key] = value;
  });
  return { status: res.status, statusText: res.statusText, headers: headerMap, body: text.slice(0, 2000) };
}

export function responseExcerpt(res: CapturedResponse): Record<string, unknown> {
  return {
    status: res.status,
    statusText: res.statusText,
    contentType: res.headers['content-type'] ?? '',
    bodyPreview: res.body.slice(0, 400),
  };
}

export function defaultGuard(expect: number[] | undefined): number[] {
  return expect && expect.length > 0 ? expect : [401, 403, 404];
}

export function runtimeUnavailableReason(ctx: { probes?: unknown; runtime?: RuntimeHandle }): string | null {
  if (ctx.runtime && ctx.runtime.alive) return null;
  if (ctx.probes) return 'runtime unavailable: the application did not start or the port never answered';
  return 'no probe plan (contract probes or .launchproof/probes.json) and no runtime';
}
