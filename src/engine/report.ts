import type { LaunchContract } from '../model/contract.ts';
import type { CheckResult, RunSummary } from '../model/result.ts';
import type { RunRecord } from '../model/run.ts';
import type { NormalizedProject } from '../model/state.ts';
import type { Verdict } from '../model/types.ts';

export interface ReportInput {
  run: RunRecord;
  results: CheckResult[];
  summary: RunSummary;
  verdict: Verdict;
  contract: LaunchContract;
  project: NormalizedProject;
}

export function generateReport(input: ReportInput): string {  const { run, results, summary, verdict, contract, project } = input;
  let out = '';
  out += `# LaunchProof Verification Report\n\n`;
  out += `**Verdict:** ${verdict}\n\n`;
  out += `- Run: \`${run.id}\`\n`;
  out += `- Project: ${contract.project.name} (\`${run.projectPath}\`)\n`;
  out += `- Profile: ${run.profile}\n`;
  out += `- Started: ${run.startedAt ?? run.createdAt}\n`;
  out += `- Finished: ${run.endedAt ?? '-'}\n`;
  out += `- Stack: ${project.framework?.key ?? 'unknown'} / db=${project.database.map((d) => d.key).join(',') || 'none'}\n\n`;
  out += `## Summary\n\n`;
  out += `| total | PASS | BLOCK | WARN | SKIPPED | UNVERIFIED | ERROR |\n`;
  out += `|---|---|---|---|---|---|---|\n`;
  out += `| ${summary.total} | ${summary.pass} | ${summary.block} | ${summary.warn} | ${summary.skipped} | ${summary.unverified} | ${summary.error} |\n`;

  const findings = results.filter((r) => r.status === 'BLOCK' || r.status === 'WARN');
  if (findings.length > 0) {
    out += `\n## Findings\n\n`;
    for (const result of findings) {
      out += `### ${result.checkId} — ${result.title} (${result.status}, ${result.severity})\n\n`;
      out += `- **Invariant:** ${result.expected}\n`;
      out += `- **Observed:** ${result.observed}\n`;
      out += `- **Surface:** ${result.affectedSurface.join(', ') || 'n/a'}\n`;
      out += `- **Evidence:** ${result.evidence.map((e) => e.id).join(', ') || 'none'}\n`;
      out += `- **Remediation:** ${result.remediation}\n`;
      if (result.reproduction?.command) out += `- **Reproduce:** \`${result.reproduction.command}\`\n`;
      out += `\n`;
    }
  }

  const nonPass = results.filter(
    (r) => r.status !== 'PASS' && r.status !== 'BLOCK' && r.status !== 'WARN',
  );
  if (nonPass.length > 0) {
    out += `\n## Not verified as passing\n\n`;
    out += `SKIPPED, UNVERIFIED and ERROR results are not passes.\n\n`;
    for (const result of nonPass) {
      out += `- **${result.checkId}** ${result.status}: ${result.reason ?? result.observed}\n`;
    }
    out += `\n`;
  }

  out += `\n## All results\n\n| ID | status | severity | class | evidence |\n|---|---|---|---|---|\n`;
  for (const result of results) {
    out += `| ${result.checkId} | ${result.status} | ${result.severity} | ${result.verificationClass} | ${result.evidence.map((e) => e.id).join(' ')} |\n`;
  }

  out += `\n## Limits\n\n`;
  out += `This report covers only the checks executed in this run under the active launch contract.\n`;
  out += `A READY verdict is not a statement that the application is secure.\n`;
  return out;
}
