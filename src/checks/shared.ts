import YAML from 'yaml';
import { readText } from '../util/fs.ts';

export interface SecretMatch {
  label: string;
  line: number;
  snippet: string;
}

const PLACEHOLDER_RE = /(your[-_]|xxx+|change[-_]?me|example|placeholder|dummy|sample|test123|<[^>]+>|\{\{)/i;

export function isPlaceholder(value: string): boolean {
  return PLACEHOLDER_RE.test(value) || value.length < 8;
}

interface DetectPattern {
  label: string;
  re: RegExp;
  allowInStrings?: boolean;
}

const PATTERNS: DetectPattern[] = [
  { label: 'stripe_secret_key', re: /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  { label: 'aws_access_key_id', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { label: 'github_token', re: /\bghp_[A-Za-z0-9]{30,}\b/g },
  { label: 'github_token', re: /\bgithub_pat_[A-Za-z0-9_]{30,}\b/g },
  { label: 'private_key_block', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g },
  { label: 'supabase_service_role_key', re: /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}/g },
  { label: 'database_url_with_credentials', re: /\b(?:postgres|postgresql|mongodb|mysql):\/\/[^\s"'@]+:[^\s"'@]{4,}@/g },
  { label: 'assigned_secret', re: /\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|service[_-]?role(?:[_-]?key)?)\b["']?\s*[:=]\s*["']([^\s"']{8,})["']/gi },
];

export function findSecretsInContent(content: string, opts: { allowSecretNamedEnv?: boolean } = {}): SecretMatch[] {
  const matches: SecretMatch[] = [];
  const lines = content.split('\n');
  lines.forEach((lineText, index) => {
    for (const { label, re } of PATTERNS) {
      const baseFlags = re.flags.replace(/g/g, '');
      const clone = new RegExp(re.source, baseFlags);
      const global = new RegExp(re.source, `${baseFlags}g`);
      let match: RegExpExecArray | null;
      let found = false;
      while ((match = global.exec(lineText)) !== null) {
        found = true;
        const value = match[1] ?? match[0];
        if (label === 'assigned_secret' && isPlaceholder(value)) continue;
        if (label === 'supabase_service_role_key' && !opts.allowSecretNamedEnv) {
          const looksLikeEnvName = /\b[A-Z0-9_]*(?:ANON|PUBLIC|CLIENT)[A-Z0-9_]*\b/.test(lineText);
          if (looksLikeEnvName) continue;
        }
        matches.push({
          label,
          line: index + 1,
          snippet: redactLine(lineText.trim()),
        });
        break;
      }
      if (!found) void clone;
    }
  });
  return dedupe(matches);
}

function dedupe(matches: SecretMatch[]): SecretMatch[] {
  const seen = new Set<string>();
  const out: SecretMatch[] = [];
  for (const m of matches) {
    const key = `${m.label}:${m.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(m);
  }
  return out;
}

export function redactLine(line: string): string {
  let out = line;
  out = out.replace(/\b[sr]k_(?:live|test)_[A-Za-z0-9]{8,}/g, (m) => `${m.slice(0, 7)}***REDACTED***`);
  out = out.replace(/\bAKIA[0-9A-Z]{12,}/g, 'AKIA***REDACTED***');
  out = out.replace(/\bghp_[A-Za-z0-9]{12,}/g, 'ghp_***REDACTED***');
  out = out.replace(/\bgithub_pat_[A-Za-z0-9_]{12,}/g, 'github_pat_***REDACTED***');
  out = out.replace(/eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}/g, 'eyJ***REDACTED***');
  out = out.replace(/(postgres|postgresql|mongodb|mysql):\/\/[^\s"'@]+:[^\s"'@]+@/g, '$1://***REDACTED***@');
  out = out.replace(
    /\b((?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|service[_-]?role(?:[_-]?key)?)["']?\s*[:=]\s*["'])([^\s"']{4,})["']/gi,
    '$1***REDACTED***"',
  );
  return out.length > 300 ? `${out.slice(0, 300)}…` : out;
}

export const CLIENT_FILE_RE = /(^|\/)(public|dist|out|build|www|client|static)\/|\.next\/static\//;
export const SOURCE_EXT_RE = /\.(?:ts|tsx|js|jsx|mjs|cjs|py|rb|php|go|java)$/;

export function isClientServed(relPath: string): boolean {
  return CLIENT_FILE_RE.test(relPath) && SOURCE_EXT_RE.test(relPath) || /\.(?:js|css|html)$/.test(relPath) && CLIENT_FILE_RE.test(relPath);
}

export const ROUTE_FILE_RE =
  /(^|\/)(?:app\/api\/.*\/route\.[tj]sx?|pages\/api\/.*\.[tj]sx?|src\/pages\/api\/.*\.[tj]sx?|api\/.*\.[tj]sx?|server\/.*\.[tj]sx?|functions\/.*\.[tj]s|server\.[tj]s|src\/server\.[tj]s)$/;

export function isRouteFile(relPath: string): boolean {
  return ROUTE_FILE_RE.test(relPath);
}

const AUTH_MARKERS =
  /\b(?:getServerSession|getSession|requireAuth|requireUser|getUser|getSessionUser|authenticate|verifySession|auth\(\)|getToken|clerk|currentUser|req\.user|request\.user|context\.user|session\b|authorization\b|401|403|unauthorized|forbidden|middleware)\b/i;

const DATA_MARKERS = /\b(?:res\.json|NextResponse\.json|Response\.json|return\s+\{|\.send\(|JSON\.stringify|res\.end|db\.|prisma\.|select\(|find[A-Z]\w*\(|query\(|from\()/;

const ID_MARKERS = /\b(?:params\.|req\.params|context\.params|request\.params|:\s*id\b|\bid\s*[=:]|\bprojectId\b|\buserId\b|\brecordId\b)/;

export interface RouteAnalysis {
  hasAuth: boolean;
  hasData: boolean;
  hasId: boolean;
}

export function analyzeRouteContent(content: string): RouteAnalysis {
  return {
    hasAuth: AUTH_MARKERS.test(content),
    hasData: DATA_MARKERS.test(content),
    hasId: ID_MARKERS.test(content),
  };
}

export async function loadYamlFiles(root: string, relPaths: string[]): Promise<Array<{ path: string; doc: unknown }>> {
  const out: Array<{ path: string; doc: unknown }> = [];
  for (const rel of relPaths) {
    const raw = await readText(root, rel);
    if (!raw) continue;
    try {
      out.push({ path: rel, doc: YAML.parse(raw) });
    } catch {
      out.push({ path: rel, doc: null });
    }
  }
  return out;
}

export function parseVersion(value: string): number[] | null {
  const cleaned = value.trim().replace(/^[\^~>=<\s]+/, '');
  const match = /^(\d+)\.(\d+)\.(\d+)/.exec(cleaned);
  if (!match) {
    const major = /^(\d+)$/.exec(cleaned);
    if (major) return [Number(major[1]), 0, 0];
    return null;
  }
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

export function versionBelow(value: string, min: string): boolean {
  const a = parseVersion(value);
  const b = parseVersion(min);
  if (!a || !b) return false;
  for (let i = 0; i < 3; i += 1) {
    const av = a[i] ?? 0;
    const bv = b[i] ?? 0;
    if (av < bv) return true;
    if (av > bv) return false;
  }
  return false;
}

export const SENSITIVE_TABLE_RE =
  /\b(?:users?|profiles?|accounts?|customers?|orders?|payments?|invoices?|subscriptions?|projects?|files?|documents?|messages?|emails?|addresses?|cards?|customers|sessions?|orgs?|organizations?|members?|tenants?)\b/i;

export function collectCreateTables(sql: string): Array<{ name: string; line: number }> {
  const out: Array<{ name: string; line: number }> = [];
  const re = /create\s+table\s+(?:if\s+not\s+exists\s+)?(?:"|`)?([a-zA-Z0-9_.]+)(?:"|`)?/gi;
  let match: RegExpExecArray | null;
  while ((match = re.exec(sql)) !== null) {
    const name = (match[1] ?? '').split('.').pop() ?? '';
    if (!name) continue;
    out.push({ name, line: sql.slice(0, match.index).split('\n').length });
  }
  return out;
}

export function collectRlsEnabled(sql: string): Set<string> {
  const enabled = new Set<string>();
  const re = /alter\s+table\s+(?:only\s+)?(?:"|`)?([a-zA-Z0-9_.]+)(?:"|`)?\s+enable\s+row\s+level\s+security/gi;
  let match: RegExpExecArray | null;
  while ((match = re.exec(sql)) !== null) {
    const name = (match[1] ?? '').split('.').pop() ?? '';
    if (name) enabled.add(name.toLowerCase());
  }
  return enabled;
}

export function collectPermissivePolicies(sql: string): Array<{ policy: string; table: string; line: number }> {
  const out: Array<{ policy: string; table: string; line: number }> = [];
  const re = /create\s+policy\s+(?:"|`)?([a-zA-Z0-9_]+)(?:"|`)?\s+on\s+(?:"|`)?([a-zA-Z0-9_.]+)(?:"|`)?[^;]*?using\s*\(\s*true\s*\)/gi;
  let match: RegExpExecArray | null;
  while ((match = re.exec(sql)) !== null) {
    out.push({
      policy: match[1] ?? '',
      table: (match[2] ?? '').split('.').pop() ?? '',
      line: sql.slice(0, match.index).split('\n').length,
    });
  }
  return out;
}

export function logCalls(content: string): Array<{ line: number; args: string }> {
  const out: Array<{ line: number; args: string }> = [];
  const re = /console\.(log|info|warn|error|debug|trace)\(([^;]{0,400})\)/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(content)) !== null) {
    out.push({ line: content.slice(0, match.index).split('\n').length, args: match[2] ?? '' });
  }
  return out;
}

export function stripStringLiterals(value: string): string {
  return value.replace(/'(?:[^'\\]|\\.)*'/g, "''").replace(/"(?:[^"\\]|\\.)*"/g, '""').replace(/`(?:[^`\\]|\\.)*`/g, '``');
}
