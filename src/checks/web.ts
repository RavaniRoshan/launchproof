import type { CheckDefinition, CheckOutcome } from './types.ts';
import { redactLine } from './shared.ts';

export function webChecks(): CheckDefinition[] {
  const browser001: CheckDefinition = {
    id: 'BROWSER-001',
    title: 'HTML injection sink fed by request input',
    category: 'xss',
    cls: 'deterministic',
    phase: 'static',
    severity: 'critical',
    summary:
      'Writing request-derived data into the DOM as HTML (innerHTML, dangerouslySetInnerHTML, document.write) executes attacker script in the victim origin.',
    invariant: 'No request-derived value reaches an HTML-interpretation sink without sanitization.',
    remediation:
      'Render with text bindings (textContent / framework escaping) instead, or sanitize with a vetted sanitizer such as DOMPurify before assignment.',
    prerequisites: [],
    surfaces: ['public_web', 'api'],
    profiles: ['launch', 'security', 'agent-change', 'stack'],
    agentFixable: false,
    applies: (contract) => contract.surfaces.public_web || contract.surfaces.api,
    async run(ctx): Promise<CheckOutcome> {
      const SINK = /\b(?:innerHTML|outerHTML)\s*=|dangerouslySetInnerHTML|document\.write\s*\(|insertAdjacentHTML\s*\(/;
      const REQUEST_SOURCE = /location\.(?:search|hash|href)|URLSearchParams|req\.query|request\.query|req\.params|request\.params|params\.|searchParams|query\./;
      const findings: Array<{ file: string; line: number; snippet: string }> = [];
      let sinks = 0;
      let scanned = 0;

      for (const file of ctx.files) {
        if (!/\.(ts|tsx|js|jsx|vue|svelte)$/.test(file)) continue;
        if (/(^|\/)(test|tests|__tests__|fixtures|study)\//.test(file)) continue;
        const content = await ctx.read(file);
        if (!content || !SINK.test(content)) continue;
        scanned += 1;
        content.split('\n').forEach((lineText, index) => {
          if (!SINK.test(lineText)) return;
          sinks += 1;
          const start = Math.max(0, index - 6);
          const windowText = content.split('\n').slice(start, index + 7).join('\n');
          if (REQUEST_SOURCE.test(windowText)) {
            findings.push({ file, line: index + 1, snippet: redactLine(lineText.trim().slice(0, 200)) });
          }
        });
      }

      await ctx.evidence({
        category: 'STATIC_ANALYSIS',
        title: 'HTML sink scan',
        data: { filesWithSinks: scanned, sinks, requestDerivedFindings: findings },
        replay: 'grep -rnE "innerHTML|dangerouslySetInnerHTML|document.write" src',
      });
      if (findings.length > 0) {
        return {
          status: 'BLOCK',
          observed: findings.map((f) => `${f.file}:${f.line}`).join('; '),
          affectedSurface: findings.map((f) => f.file),
          confidence: 'medium',
        };
      }
      return {
        status: 'PASS',
        observed: `${sinks} HTML sink(s) in ${scanned} file(s); none fed by request-derived input`,
        confidence: 'medium',
      };
    },
  };

  const api002: CheckDefinition = {
    id: 'API-002',
    title: 'Error response exposes internals',
    category: 'api',
    cls: 'deterministic',
    phase: 'static',
    severity: 'minor',
    summary:
      'Returning raw error objects or stack traces leaks file paths, library versions and query shapes that make the next attack cheaper to build.',
    invariant: 'Error responses return a generic message and correlation id, not internal error detail.',
    remediation:
      'Catch at the boundary, log the full error server-side, and respond with a stable message plus an id the support team can correlate.',
    prerequisites: [],
    surfaces: ['api'],
    profiles: ['quick', 'launch', 'security', 'agent-change', 'stack'],
    agentFixable: true,
    applies: (contract) => contract.surfaces.api,
    async run(ctx): Promise<CheckOutcome> {
      const ROUTE_LIKE = /(route|api|server|handler|controller|endpoint)/i;
      const RAW_ERR = /\.(?:json|send|end|write)\s*\(\s*(?:err|error|e)\b|\bstack\s*[:.]/;
      const findings: Array<{ file: string; line: number; snippet: string }> = [];
      let scanned = 0;

      for (const file of ctx.files) {
        if (!/\.(ts|tsx|js|jsx|mjs|cjs|py)$/.test(file)) continue;
        if (!ROUTE_LIKE.test(file) && !/catch\s*\(/.test((await ctx.read(file)) ?? '')) continue;
        const content = await ctx.read(file);
        if (!content || !/catch\s*\(/.test(content)) continue;
        scanned += 1;
        content.split('\n').forEach((lineText, index) => {
          if (!RAW_ERR.test(lineText)) return;
          if (/message\s*[:=]|generic|sanitiz/i.test(lineText) && !/stack/i.test(lineText)) return;
          findings.push({ file, line: index + 1, snippet: redactLine(lineText.trim().slice(0, 200)) });
        });
      }

      await ctx.evidence({
        category: 'STATIC_ANALYSIS',
        title: 'Error response scan',
        data: { filesScanned: scanned, findings },
        replay: 'grep -rnE "json\\(err|send\\(err|err\\.stack" src',
      });
      if (findings.length === 0) {
        return { status: 'PASS', observed: `scanned ${scanned} handler file(s); no raw error objects or stacks returned` };
      }
      return {
        status: 'WARN',
        observed: findings.map((f) => `${f.file}:${f.line}`).join('; '),
        affectedSurface: findings.map((f) => f.file),
        confidence: 'medium',
      };
    },
  };

  return [browser001, api002];
}
