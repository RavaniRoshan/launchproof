export interface SecretPattern {
  label: string;
  re: RegExp;
}

const PATTERNS: SecretPattern[] = [
  { label: 'STRIPE_KEY', re: /\b[sr]k_(?:live|test)_[A-Za-z0-9]{8,}\b/g },
  { label: 'STRIPE_PUBKEY', re: /\b[pk]k_(?:live|test)_[A-Za-z0-9]{8,}\b/g },
  { label: 'AWS_ACCESS_KEY', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { label: 'GITHUB_TOKEN', re: /\bghp_[A-Za-z0-9]{20,}\b/g },
  { label: 'GITHUB_TOKEN', re: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g },
  { label: 'SLACK_TOKEN', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { label: 'PRIVATE_KEY', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
  { label: 'JWT', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b/g },
  { label: 'DATABASE_URL', re: /\b(?:postgres|postgresql|mongodb|mysql):\/\/[^\s"'@]+:[^\s"'@]+@[^\s"']+/g },
  { label: 'BEARER_TOKEN', re: /\bBearer\s+[A-Za-z0-9._~+/-]{16,}=*/g },
  { label: 'ASSIGNED_SECRET', re: /\b((?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)["']?\s*[:=]\s*["'])([^\s"']{6,})["']/gi },
  { label: 'ENV_SECRET', re: /\b([A-Z0-9_]*(?:SECRET|PRIVATE_KEY|PASSWORD|API_KEY)[A-Z0-9_]*)=(\S{6,})/g },
];

export function scrubText(input: string, extraSecrets: string[] = []): string {
  let out = input;
  for (const secret of extraSecrets) {
    if (secret && secret.length >= 6) {
      out = out.split(secret).join(`***REDACTED:KNOWN_SECRET***`);
    }
  }
  for (const { label, re } of PATTERNS) {
    out = out.replace(re, (match, prefix?: string) => {
      if (typeof prefix === 'string' && prefix.length > 0 && match.startsWith(prefix)) {
        return `${prefix}***REDACTED:${label}***`;
      }
      return `***REDACTED:${label}***`;
    });
  }
  return out;
}

const MAX_STRING = 8000;

export function scrubValue(value: unknown, extraSecrets: string[] = []): unknown {
  if (typeof value === 'string') {
    const scrubbed = scrubText(value, extraSecrets);
    return scrubbed.length > MAX_STRING ? `${scrubbed.slice(0, MAX_STRING)}…[truncated]` : scrubbed;
  }
  if (Array.isArray(value)) return value.map((v) => scrubValue(v, extraSecrets));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = scrubValue(v, extraSecrets);
    }
    return out;
  }
  return value;
}

export function containsRawSecret(value: unknown, extraSecrets: string[] = []): boolean {
  const text = typeof value === 'string' ? value : JSON.stringify(value ?? '');
  for (const secret of extraSecrets) {
    if (secret && secret.length >= 6 && text.includes(secret)) return true;
  }
  for (const { re } of PATTERNS) {
    const clone = new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`);
    const match = clone.exec(text);
    if (match && !match[0].includes('***REDACTED')) return true;
  }
  return false;
}
