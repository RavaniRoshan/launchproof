import type { CheckDefinition, CheckOutcome } from './types.ts';
import { analyzeRouteContent, isRouteFile, redactLine } from './shared.ts';

function firstAuthMarker(content: string): string | null {
  const markers = [
    'getServerSession',
    'getSession',
    'requireAuth',
    'requireUser',
    'getUser',
    'authenticate',
    'verifySession',
    'getToken',
    'currentUser',
    'req.user',
    'request.user',
    'context.user',
    'session',
    'authorization',
    'middleware',
    '401',
    '403',
    'unauthorized',
    'forbidden',
  ];
  for (const m of markers) {
    if (new RegExp(`\\b${m.replace('.', '\\.')}\\b`, 'i').test(content)) return m;
  }
  return null;
}

export function authChecks(): CheckDefinition[] {
  const auth002: CheckDefinition = {
    id: 'AUTH-002',
    title: 'Protected resource route lacks server-side authorization',
    category: 'authorization',
    cls: 'deterministic',
    phase: 'static',
    severity: 'critical',
    summary:
      'A route that fetches records by id must check identity server-side before returning them; client-side hiding is not authorization.',
    invariant: 'Every API route that loads a record by identifier performs a server-side authorization check.',
    remediation:
      'Resolve the session/user inside the handler and verify ownership or role before reading the record; return 401/403/404 for unauthorized access.',
    prerequisites: [],
    surfaces: ['api', 'authorization', 'user_accounts'],
    profiles: ['quick', 'launch', 'security', 'agent-change', 'stack'],
    agentFixable: true,
    applies: (contract) => contract.surfaces.api || contract.surfaces.user_accounts || contract.required.authorization,
    async run(ctx): Promise<CheckOutcome> {
      const routeFiles = ctx.files.filter(isRouteFile);
      if (routeFiles.length === 0) {
        await ctx.evidence({ category: 'SOURCE', title: 'No API route files discovered', data: { searched: 'app/api, pages/api, api, server, functions' } });
        return { status: 'UNVERIFIED', reason: 'no API route files discovered in this project' };
      }

      const candidates: string[] = [];
      const unprotected: Array<{ file: string; excerpt: string }> = [];
      const protectedFiles: Array<{ file: string; marker: string }> = [];

      for (const file of routeFiles.slice(0, 200)) {
        const content = await ctx.read(file);
        if (!content) continue;
        const analysis = analyzeRouteContent(content);
        if (!analysis.hasData || !analysis.hasId) continue;
        candidates.push(file);
        const marker = firstAuthMarker(content);
        if (marker) {
          protectedFiles.push({ file, marker });
        } else {
          const line = content.split('\n').find((l) => /(find|select|query|db\.|prisma\.|from\()/.test(l)) ?? '';
          unprotected.push({ file, excerpt: redactLine(line.trim().slice(0, 200)) });
        }
      }

      if (candidates.length === 0) {
        await ctx.evidence({
          category: 'SOURCE',
          title: 'Route files scanned for id-scoped data access',
          data: { routeFiles: routeFiles.length, idScopedRoutes: 0 },
        });
        return { status: 'PASS', observed: `no id-scoped data routes detected among ${routeFiles.length} route file(s)` };
      }

      if (unprotected.length > 0) {
        await ctx.evidence({
          category: 'STATIC_ANALYSIS',
          title: 'Id-scoped route without authorization markers',
          data: {
            checkedMarkers: ['session', 'req.user', 'getToken', 'requireAuth', 'getServerSession', '401', '403', 'authorization', 'middleware'],
            findings: unprotected,
          },
          replay: 'open each listed route and confirm no identity check guards the record lookup',
        });
        return {
          status: 'BLOCK',
          observed: `no authorization markers in ${unprotected.length} id-scoped route(s): ${unprotected.map((u) => u.file).join(', ')}`,
          affectedSurface: unprotected.map((u) => u.file),
          confidence: 'medium',
          reproduction: { command: `grep -LniE "session|user|auth|401|403" ${unprotected[0]?.file ?? 'app/api/**'}` },
        };
      }

      await ctx.evidence({
        category: 'STATIC_ANALYSIS',
        title: 'All id-scoped routes carry authorization markers',
        data: { checked: protectedFiles },
      });
      return {
        status: 'PASS',
        observed: `${protectedFiles.length} id-scoped route(s) contain authorization markers`,
        confidence: 'medium',
      };
    },
  };

  const auth003: CheckDefinition = {
    id: 'AUTH-003',
    title: 'Session cookie hardening',
    category: 'authentication',
    cls: 'deterministic',
    phase: 'static',
    severity: 'major',
    summary:
      'Session cookies must be HttpOnly, Secure and SameSite so scripts cannot steal them and cross-site requests cannot replay them.',
    invariant: 'Session cookies are set with HttpOnly, Secure and SameSite attributes.',
    remediation:
      'Set httpOnly: true, secure: true and sameSite: "lax" (or "strict") on every session cookie; rely on framework defaults only where they are documented to be safe.',
    prerequisites: [],
    surfaces: ['authentication', 'user_accounts'],
    profiles: ['launch', 'security', 'agent-change', 'stack'],
    agentFixable: true,
    applies: (contract) => contract.surfaces.user_accounts || contract.required.authentication,
    async run(ctx): Promise<CheckOutcome> {
      const cookieSetters: Array<{ file: string; line: number; snippet: string; flags: { httpOnly: boolean; secure: boolean; sameSite: boolean }; frameworkDefault: boolean; explicitUnsafe: string[] }> = [];
      const cookieRe = /cookies\.set\(|res\.cookie\(|Set-Cookie|setHeader\(\s*['"]Set-Cookie['"]/;

      for (const file of ctx.files) {
        if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(file)) continue;
        const content = await ctx.read(file);
        if (!content || !cookieRe.test(content)) continue;
        content.split('\n').forEach((lineText, index) => {
          if (!cookieRe.test(lineText)) return;
          const windowText = content.split('\n').slice(index, index + 12).join('\n');
          const explicitUnsafe: string[] = [];
          if (/httpOnly\s*:\s*false/i.test(windowText)) explicitUnsafe.push('httpOnly:false');
          if (/secure\s*:\s*false/i.test(windowText)) explicitUnsafe.push('secure:false');
          cookieSetters.push({
            file,
            line: index + 1,
            snippet: redactLine(lineText.trim().slice(0, 200)),
            flags: {
              httpOnly: /httpOnly\s*:\s*true/i.test(windowText) || /\bHttpOnly\b/i.test(windowText),
              secure: /secure\s*:\s*true/i.test(windowText) || /;\s*Secure\b/i.test(windowText),
              sameSite: /sameSite\s*:/i.test(windowText) || /SameSite=/i.test(windowText),
            },
            frameworkDefault: /from\s+['"]next\/headers['"]|cookies\(\)\.set/.test(content),
            explicitUnsafe,
          });
        });
      }

      if (cookieSetters.length === 0) {
        await ctx.evidence({ category: 'SOURCE', title: 'No session cookie setters found', data: { scanned: ctx.files.length } });
        return { status: 'UNVERIFIED', reason: 'no session cookie setters found in source' };
      }

      const unsafe = cookieSetters.filter((c) => c.explicitUnsafe.length > 0);
      const missing = cookieSetters.filter(
        (c) => c.explicitUnsafe.length === 0 && (!c.flags.httpOnly || !c.flags.secure || !c.flags.sameSite) && !c.frameworkDefault,
      );
      const frameworkSetters = cookieSetters.filter((c) => c.frameworkDefault);

      if (unsafe.length === 0 && missing.length === 0) {
        await ctx.evidence({ category: 'SOURCE', title: 'Session cookie hardening confirmed', data: { setters: cookieSetters.map((c) => ({ file: c.file, line: c.line, flags: c.flags, frameworkDefault: c.frameworkDefault })) } });
        return { status: 'PASS', observed: `${cookieSetters.length} cookie setter(s) hardened or framework-defaulted` };
      }

      const findings = [...unsafe, ...missing];
      await ctx.evidence({
        category: 'STATIC_ANALYSIS',
        title: 'Cookie setters missing hardening flags',
        data: {
          findings: findings.map((c) => ({ file: c.file, line: c.line, missing: c.explicitUnsafe.length ? c.explicitUnsafe : Object.entries(c.flags).filter(([, v]) => !v).map(([k]) => k), snippet: c.snippet, frameworkDefault: c.frameworkDefault })),
          frameworkDefaults: frameworkSetters.map((c) => c.file),
        },
      });
      return {
        status: 'WARN',
        observed: `${findings.length} cookie setter(s) missing safe flags: ${findings.map((f) => `${f.file}:${f.line}`).join(', ')}`,
        affectedSurface: findings.map((f) => f.file),
        confidence: 'medium',
      };
    },
  };

  return [auth002, auth003];
}
