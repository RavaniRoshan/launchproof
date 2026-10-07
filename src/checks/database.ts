import type { CheckDefinition, CheckOutcome } from './types.ts';
import { SENSITIVE_TABLE_RE, collectCreateTables, collectPermissivePolicies, collectRlsEnabled, findSecretsInContent, redactLine } from './shared.ts';

async function sqlFiles(ctx: { files: string[]; read(rel: string): Promise<string | null> }): Promise<Array<{ path: string; sql: string }>> {
  const out: Array<{ path: string; sql: string }> = [];
  for (const file of ctx.files) {
    if (!/\.sql$/i.test(file)) continue;
    const sql = await ctx.read(file);
    if (sql) out.push({ path: file, sql });
  }
  return out;
}

export function databaseChecks(): CheckDefinition[] {
  const db003: CheckDefinition = {
    id: 'DB-003',
    title: 'Exposed table has row-level security disabled',
    category: 'database',
    cls: 'deterministic',
    phase: 'database',
    severity: 'critical',
    summary:
      'Tables reachable by the anonymous data path must enforce row-level security; without it any client that can reach the database can read every row.',
    invariant: 'Every table holding row data enables row-level security when database isolation is required.',
    remediation: 'Run `ALTER TABLE <name> ENABLE ROW LEVEL SECURITY;` plus explicit policies for each role, or stop exposing the table to the client data path.',
    prerequisites: [],
    surfaces: ['database', 'user_accounts', 'api'],
    profiles: ['launch', 'security', 'agent-change', 'stack'],
    agentFixable: true,
    applies: (contract) => contract.required.database_isolation || contract.surfaces.api,
    async run(ctx): Promise<CheckOutcome> {
      const files = await sqlFiles(ctx);
      if (files.length === 0) {
        await ctx.evidence({ category: 'DATABASE', title: 'No SQL migration files found', data: { searched: '*.sql' } });
        return { status: 'UNVERIFIED', reason: 'no SQL migration files found; row-level security cannot be verified statically' };
      }

      const created: Array<{ name: string; file: string; line: number }> = [];
      const secured = new Set<string>();
      for (const f of files) {
        for (const t of collectCreateTables(f.sql)) created.push({ ...t, file: f.path });
        for (const name of collectRlsEnabled(f.sql)) secured.add(name.toLowerCase());
      }

      if (created.length === 0) {
        await ctx.evidence({ category: 'DATABASE', title: 'SQL files scanned for table definitions', data: { files: files.map((f) => f.path) } });
        return { status: 'UNVERIFIED', reason: 'SQL files found but no CREATE TABLE statements to evaluate' };
      }

      const unsecured = created.filter((t) => !secured.has(t.name.toLowerCase()));
      const sensitiveUnsecured = unsecured.filter((t) => SENSITIVE_TABLE_RE.test(t.name));
      const referencedUnsecured: typeof unsecured = [];
      for (const t of unsecured) {
        if (referencedUnsecured.includes(t)) continue;
        const escaped = t.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const re = new RegExp(`from\\(\\s*['"\`]${escaped}['"\`\\)]|db\\.${escaped}\\b|table\\s*=?\\s*['"\`]${escaped}`, 'i');
        for (const file of ctx.files) {
          if (!/\.(ts|tsx|js|jsx|py)$/.test(file)) continue;
          const content = await ctx.read(file);
          if (content && re.test(content)) {
            referencedUnsecured.push(t);
            break;
          }
        }
      }

      const findings = sensitiveUnsecured.length > 0 ? sensitiveUnsecured : referencedUnsecured;
      const scopeNote = sensitiveUnsecured.length > 0 ? 'sensitive-named tables' : referencedUnsecured.length > 0 ? 'tables referenced from application code' : [];

      await ctx.evidence({
        category: 'DATABASE',
        title: 'Row-level security coverage',
        data: {
          files: files.map((f) => f.path),
          createdTables: created.map((t) => `${t.name} (${t.file}:${t.line})`),
          rlsEnabled: [...secured],
          findings: findings.map((t) => ({ table: t.name, file: t.file, line: t.line })),
        },
        replay: `grep -n "ENABLE ROW LEVEL SECURITY" ${files[0]?.path ?? '*.sql'}`,
      });

      if (findings.length > 0) {
        return {
          status: 'BLOCK',
          observed: `table(s) without row-level security in ${Array.isArray(scopeNote) ? scopeNote.join('/') || 'project scope' : scopeNote}: ${findings.map((f) => f.name).join(', ')}`,
          affectedSurface: findings.map((f) => f.name),
        };
      }
      if (unsecured.length > 0) {
        return {
          status: 'WARN',
          observed: `${unsecured.length} non-sensitive table(s) without row-level security (not referenced from app code): ${unsecured.map((t) => t.name).join(', ')}`,
          affectedSurface: unsecured.map((t) => t.name),
          confidence: 'medium',
        };
      }
      return { status: 'PASS', observed: `all ${created.length} created table(s) enable row-level security` };
    },
  };

  const db004: CheckDefinition = {
    id: 'DB-004',
    title: 'Service-role key reachable from client code',
    category: 'database',
    cls: 'deterministic',
    phase: 'database',
    severity: 'critical',
    summary:
      'The service-role key bypasses all row-level security; if it ships in client-reachable code or public env vars, every table is readable and writable by anyone.',
    invariant: 'The database service-role credential never appears in client-reachable code or public environment variables.',
    remediation:
      'Remove the key, rotate it in the dashboard, and use it only inside server-only code reading a non-public environment variable.',
    prerequisites: [],
    surfaces: ['database', 'secret_boundary', 'secrets'],
    profiles: ['launch', 'security', 'agent-change', 'stack'],
    agentFixable: false,
    applies: () => true,
    async run(ctx): Promise<CheckOutcome> {
      const findings: Array<{ file: string; line: number; label: string; snippet: string }> = [];
      const clientFiles = ctx.files.filter((f) => /(^|\/)(public|dist|out|build|www|client|static)\/|\.next\/static\//.test(f));
      const publicEnvRefs = ctx.files.filter((f) => /(^|\/)\.env(\.|$)/.test(f));

      for (const file of [...clientFiles, ...publicEnvRefs]) {
        const content = await ctx.read(file);
        if (!content) continue;
        const lines = content.split('\n');
        lines.forEach((lineText, index) => {
          const serviceRef = /(SUPABASE_SERVICE_ROLE|SERVICE_ROLE|SERVICE_KEY|DATABASE_SERVICE_KEY|PG_SERVICE|DRIZZLE.*AUTH_TOKEN|POSTGRES_URL_NON_POOLING)/i;
          if (!serviceRef.test(lineText)) return;
          const isPublicVar = /NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_/i.test(lineText);
          const hasLiteral = /=\s*["']?[A-Za-z0-9_.\-]{12,}/.test(lineText) && !/your[-_]|xxx|example|placeholder|<|process\.env/i.test(lineText);
          if (isPublicVar || hasLiteral || file.includes('public/') || /\.(js|css|html)$/.test(file)) {
            findings.push({ file, line: index + 1, label: isPublicVar ? 'public env prefix' : 'client-served file', snippet: redactLine(lineText.trim()) });
          }
        });
        const secrets = findSecretsInContent(content);
        for (const s of secrets) {
          if (s.label === 'supabase_service_role_key') {
            findings.push({ file, line: s.line, label: s.label, snippet: redactLine(s.snippet) });
          }
        }
      }

      if (findings.length === 0) {
        await ctx.evidence({
          category: 'DATABASE',
          title: 'Service-role key scan clean',
          data: { clientFilesScanned: clientFiles.length, envFilesScanned: publicEnvRefs.length },
        });
        return { status: 'PASS', observed: `no service-role key found in ${clientFiles.length + publicEnvRefs.length} client-reachable file(s)` };
      }

      await ctx.evidence({ category: 'DATABASE', title: 'Service-role key in client-reachable code', data: { findings } });
      return {
        status: 'BLOCK',
        observed: findings.map((f) => `${f.file}:${f.line} (${f.label})`).join('; '),
        affectedSurface: findings.map((f) => f.file),
      };
    },
  };

  const db005: CheckDefinition = {
    id: 'DB-005',
    title: 'Overly permissive row-level security policy',
    category: 'database',
    cls: 'deterministic',
    phase: 'database',
    severity: 'major',
    summary:
      'A policy with `USING (true)` grants every role with access to the table unrestricted rows, which silently voids isolation for that table.',
    invariant: 'Row-level security policies restrict rows by identity instead of allowing all rows.',
    remediation: 'Replace `USING (true)` with a predicate such as `auth.uid() = user_id`, and scope `WITH CHECK` the same way.',
    prerequisites: [],
    surfaces: ['database', 'authorization'],
    profiles: ['launch', 'security', 'agent-change', 'stack'],
    agentFixable: true,
    applies: (contract) => contract.required.database_isolation || Boolean(contract.stack.database),
    async run(ctx): Promise<CheckOutcome> {
      const files = await sqlFiles(ctx);
      if (files.length === 0) {
        await ctx.evidence({ category: 'DATABASE', title: 'No SQL files with policies', data: {} });
        return { status: 'UNVERIFIED', reason: 'no SQL migration files found; policies cannot be evaluated' };
      }
      const permissive: Array<{ policy: string; table: string; file: string; line: number }> = [];
      let policyCount = 0;
      for (const f of files) {
        policyCount += (f.sql.match(/create\s+policy/gi) ?? []).length;
        for (const p of collectPermissivePolicies(f.sql)) permissive.push({ ...p, file: f.path });
      }
      if (permissive.length === 0) {
        await ctx.evidence({ category: 'DATABASE', title: 'RLS policies evaluated', data: { files: files.map((f) => f.path), policies: policyCount, permissive: 0 } });
        return policyCount === 0
          ? { status: 'UNVERIFIED', reason: 'no CREATE POLICY statements found to evaluate' }
          : { status: 'PASS', observed: `${policyCount} policy/policies checked; none allow all rows` };
      }
      await ctx.evidence({ category: 'DATABASE', title: 'Permissive RLS policies found', data: { findings: permissive }, replay: `grep -n "USING (true)" ${permissive[0]?.file ?? '*.sql'}` });
      return {
        status: 'WARN',
        observed: `policy/policies allow all rows: ${permissive.map((p) => `${p.policy} on ${p.table}`).join(', ')}`,
        affectedSurface: permissive.map((p) => p.table),
      };
    },
  };

  return [db003, db004, db005];
}
