import path from 'node:path';
import { mkdir, readFile, writeFile, readdir } from 'node:fs/promises';
import { executeRun } from '../engine/engine.ts';
import type { PhaseHook } from '../engine/engine.ts';
import { loadContract, inferContract } from '../contract/infer.ts';
import { validateContract } from '../model/contract.ts';
import { discoverProject } from '../discovery/detect.ts';
import { analyzeChanges } from '../discovery/changed.ts';
import { loadDefaultRegistry } from '../checks/registry.ts';
import { EvidenceLedger } from '../evidence/ledger.ts';
import { newRunId } from '../model/ids.ts';
import { summarize } from '../model/result.ts';
import type { ProfileId } from '../checks/types.ts';
import { ensureStorage, storagePaths, writeJsonAtomic, launchproofHome } from '../storage/paths.ts';
import { createRuntimeLab } from '../runtime/lab.ts';
import { createBrowserLab } from '../browser/playwright.ts';
import { registerProject, listProjects, listRuns, readRunReport } from '../daemon/store.ts';
import { adapterFor } from '../agents/adapters.ts';
import { createFixTask } from '../agents/fixloop.ts';

export const USAGE = `launchproof — independent launch-readiness verification

Usage:
  launchproof init [path]                 scaffold launchproof.yaml + probe plan
  launchproof detect [path]               print stack detection + risk surfaces
  launchproof verify <path> [--profile <name>] [--strict] [--json] [--only ID,ID] [--daemon|--local]
  launchproof report [--run <id>] [--json]  show the latest (or given) run report
  launchproof history [--json]            list recent verification runs
  launchproof explain <CHECK-ID>          print invariant, evidence needs, remediation
  launchproof fix <CHECK-ID> --path <dir> --run <id> [--agent codex|claude|script] [--approve] [--dry-run]
  launchproof doctor                      check node, daemon, browsers, agents
  launchproof desktop [--port N]          start daemon + open local control plane
  launchproof daemon [--port N]           start the local verification daemon

Profiles: quick | launch | security | agent-change | stack | custom (default: launch)
Exit codes: 0 READY · 1 BLOCKED · 2 usage or runtime error`;

class CliError extends Error {}

function fail(message: string): never {
  throw new CliError(message);
}

function truncate(value: string, max = 140): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

interface GlobalOpts {
  json: boolean;
  daemon: boolean;
  local: boolean;
}

async function daemonCall(method: 'GET' | 'POST', route: string, body?: unknown): Promise<{ ok: boolean; status: number; data: unknown }> {
  const home = launchproofHome();
  const portFile = path.join(home, 'daemon.json');
  let port = 0;
  try {
    const raw = await readFile(portFile, 'utf8');
    port = (JSON.parse(raw) as { port?: number }).port ?? 0;
  } catch {
    return { ok: false, status: 0, data: { error: 'daemon not running (no daemon.json port file)' } };
  }
  if (!port) return { ok: false, status: 0, data: { error: 'daemon port unknown' } };
  try {
    const res = await fetch(`http://127.0.0.1:${port}${route}`, {
      method,
      headers: { 'content-type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    return { ok: res.ok, status: res.status, data };
  } catch (error) {
    return { ok: false, status: 0, data: { error: error instanceof Error ? error.message : String(error) } };
  }
}

async function cmdInit(target: string): Promise<number> {
  const root = path.resolve(target);
  const { project } = await discoverProject({ id: path.basename(root), name: path.basename(root), root });
  const contract = await inferContract(project);
  contract.meta = { ...contract.meta, inferred: true, confirmed: false, probableFields: contract.meta?.probableFields ?? [] };
  const validation = validateContract(contract);
  if (!validation.ok) fail(`inferred contract invalid: ${validation.errors.join('; ')}`);
  const YAML = await import('yaml');
  const contractFile = path.join(root, 'launchproof.yaml');
  try {
    await readFile(contractFile, 'utf8');
    process.stdout.write(`launchproof.yaml already exists at ${contractFile} (not overwritten)\n`);
  } catch {
    await writeFile(contractFile, YAML.stringify(contract), 'utf8');
    process.stdout.write(`wrote ${contractFile}\n`);
  }
  const probesFile = path.join(root, '.launchproof', 'probes.json');
  try {
    await readFile(probesFile, 'utf8');
    process.stdout.write(`probe plan already exists at ${probesFile}\n`);
  } catch {
    await mkdir(path.dirname(probesFile), { recursive: true });
    const probes = {
      baseUrl: 'http://127.0.0.1:3000',
      identities: [
        { id: 'alice', label: 'user A', login: { path: '/api/auth/login', body: { email: 'alice@example.com', password: 'password123' } } },
        { id: 'bob', label: 'user B', login: { path: '/api/auth/login', body: { email: 'bob@example.com', password: 'password123' } } },
      ],
      endpoints: [
        { id: 'list', method: 'GET', path: '/api/projects', purpose: 'resource' },
        { id: 'admin', method: 'GET', path: '/api/admin/users', purpose: 'admin' },
        { id: 'webhook', method: 'POST', path: '/api/webhooks/stripe', purpose: 'webhook', body: { id: 'evt_test', type: 'payment_intent.succeeded' } },
      ],
      session: { logout: '/api/auth/logout', recheckPath: '/api/projects' },
      browser: { login: { path: '/login' }, protectedPaths: ['/dashboard'], logoutPath: '/logout' },
    };
    await writeFile(probesFile, JSON.stringify(probes, null, 2), 'utf8');
    process.stdout.write(`wrote probe template ${probesFile} — edit baseUrl/paths to match your app\n`);
  }
  await registerProject(project.name, root);
  process.stdout.write(`contract: framework=${contract.stack.framework ?? '?'} db=${contract.stack.database ?? '?'} surfaces=${Object.entries(contract.surfaces).filter(([, v]) => v).map(([k]) => k).join(',') || 'none'}\n`);
  if (validation.warnings.length > 0) process.stdout.write(`warnings: ${validation.warnings.join('; ')}\n`);
  return 0;
}

async function cmdDetect(target: string, asJson: boolean): Promise<number> {
  const root = path.resolve(target);
  const { project } = await discoverProject({ id: path.basename(root), name: path.basename(root), root });
  const changes = await analyzeChanges(root).catch(() => null);
  const out = {
    path: root,
    framework: project.framework,
    languages: project.languages,
    database: project.database,
    auth: project.auth,
    payments: project.payments,
    deployment: project.deployment,
    ci: project.ci,
    riskSurfaces: project.riskSurfaces,
    detectors: project.detectors.slice(0, 40),
    changes: changes ? { available: changes.available, activatedSurfaces: changes.activatedSurfaces, files: changes.files.slice(0, 20) } : null,
  };
  if (asJson) {
    process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
  } else {
    const fw = project.framework ? `${project.framework.key} (${project.framework.state})` : 'unknown';
    process.stdout.write(`framework: ${fw}\n`);
    process.stdout.write(`languages: ${project.languages.join(', ') || 'unknown'}\n`);
    process.stdout.write(`database: ${project.database.map((d) => d.key).join(', ') || 'none'}\n`);
    process.stdout.write(`auth: ${project.auth.map((d) => d.key).join(', ') || 'none'}\n`);
    process.stdout.write(`risk surfaces: ${project.riskSurfaces.join(', ') || 'none'}\n`);
    if (changes?.available) {
      process.stdout.write(`\nCHANGE ANALYSIS\n`);
      for (const f of changes.files.slice(0, 15)) process.stdout.write(`  ${f.change.padEnd(8)} ${f.path} [${f.surfaces.join(', ')}]\n`);
      if (changes.activatedSurfaces.length > 0) {
        process.stdout.write(`\nAdditional verification enabled:\n`);
        for (const s of changes.activatedSurfaces) process.stdout.write(`  ✓ ${s} — ${changes.activatedReasons[s] ?? ''}\n`);
      }
    } else {
      process.stdout.write(`change analysis: ${changes?.reason ?? 'unavailable'}\n`);
    }
  }
  return 0;
}

async function verifyLocal(root: string, profile: ProfileId, strict: boolean, only: string[] | undefined, asJson: boolean): Promise<number> {
  const log = (line: string): void => {
    if (!asJson) process.stdout.write(`${line}\n`);
  };
  await ensureStorage();
  const paths = storagePaths();
  const runId = newRunId();
  const runDir = path.join(paths.runs, runId);
  await mkdir(runDir, { recursive: true });
  await mkdir(path.join(runDir, 'evidence'), { recursive: true });

  const { project } = await discoverProject({ id: path.basename(root), name: path.basename(root), root });
  const changeAnalysis = await analyzeChanges(root).catch(() => undefined);
  const { contract, validation } = await loadContract(root, project);
  if (!validation.ok) fail(`contract validation failed: ${validation.errors.join('; ')}`);
  const registry = await loadDefaultRegistry();
  const ledger = await EvidenceLedger.open(runId, path.join(runDir, 'evidence'));

  log(`LaunchProof verify ${root}`);
  log(`run ${runId} · profile ${profile}${strict ? ' · strict' : ''}`);
  if (changeAnalysis?.available && changeAnalysis.activatedSurfaces.length > 0) {
    log(`change surfaces: ${changeAnalysis.activatedSurfaces.join(', ')}`);
  }

  const hooks: PhaseHook[] = [createRuntimeLab(), createBrowserLab()];
  const startedAt = new Date().toISOString();
  const outcome = await executeRun({
    run: { id: runId, projectId: project.id, projectPath: root, profile, status: 'running', strict, createdAt: startedAt, phases: [], plan: [] },
    root, contract, project, changeAnalysis, registry, ledger,
    signal: new AbortController().signal,
    profile, strict, only, scratchDir: runDir, hooks,
    emit: (event) => {
      if (event.type === 'check.finished' && event.result) {
        const r = event.result;
        log(`${r.status.padEnd(9)} ${r.checkId}  ${truncate(r.status === 'PASS' ? (r.observed ?? '') : (r.reason ?? r.observed ?? ''))}`);
      } else if (event.type === 'log' && event.message) {
        log(`          ${event.message}`);
      }
    },
    persistResults: async () => undefined,
    persistPhases: async () => undefined,
  });

  const summary = summarize(outcome.results);
  const report = {
    runId, projectPath: root, profile, strict, startedAt, finishedAt: new Date().toISOString(),
    verdict: outcome.verdict, summary,
    results: outcome.results.map((r) => ({
      checkId: r.checkId, title: r.title, status: r.status, severity: r.severity,
      observed: r.observed, reason: r.reason, evidence: r.evidence.length, agentLabel: r.agentLabel,
    })),
  };
  const reportPath = path.join(runDir, 'report.json');
  await writeJsonAtomic(reportPath, report);
  if (asJson) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    log('');
    log(`verdict ${outcome.verdict} · ${summary.pass} pass · ${summary.block} block · ${summary.warn} warn · ${summary.unverified} unverified · ${summary.skipped} skipped · ${summary.error} error`);
    log(`report ${reportPath}`);
  }
  return outcome.verdict === 'READY' ? 0 : 1;
}

async function verifyViaDaemon(root: string, profile: ProfileId, strict: boolean, only: string[] | undefined, asJson: boolean): Promise<number> {
  const started = await daemonCall('POST', '/api/verify', { path: root, profile, strict, only });
  if (!started.ok) {
    const detail = (started.data as { error?: string }).error ?? `status ${started.status}`;
    if (started.status === 0) {
      process.stderr.write(`daemon unreachable (${detail}); falling back to local engine\n`);
      return verifyLocal(root, profile, strict, only, asJson);
    }
    throw new CliError(`daemon verify failed: ${detail}`);
  }
  const runId = ((started.data as { run?: { id?: string } }).run?.id ?? '') as string;
  if (!asJson) process.stdout.write(`run ${runId} started on daemon; streaming events…\n`);
  // Poll for completion (SSE streaming is served at /api/runs/:id/events; poll keeps CLI dependency-free).
  for (;;) {
    await new Promise((r) => setTimeout(r, 1000));
    const res = await daemonCall('GET', `/api/runs/${runId}`);
    if (!res.ok) throw new CliError(`daemon run poll failed: ${JSON.stringify(res.data)}`);
    const payload = res.data as { run?: { status?: string; verdict?: string }; summary?: Record<string, number>; results?: Array<{ checkId: string; status: string; observed?: string; reason?: string }> };
    if (payload.run?.status === 'running' || payload.run?.status === 'pending') continue;
    if (asJson) {
      process.stdout.write(`${JSON.stringify({ runId, ...payload }, null, 2)}\n`);
    } else {
      for (const r of payload.results ?? []) {
        process.stdout.write(`${String(r.status).padEnd(9)} ${r.checkId}  ${truncate(String(r.status === 'PASS' ? (r.observed ?? '') : (r.reason ?? r.observed ?? '')))}\n`);
      }
      process.stdout.write(`\nverdict ${payload.run?.verdict ?? 'unknown'}\n`);
    }
    return payload.run?.verdict === 'READY' ? 0 : 1;
  }
}

async function cmdReport(runId: string | undefined, asJson: boolean): Promise<number> {
  if (!runId) {
    const ids = await listRuns();
    runId = ids[0];
    if (!runId) fail('no verification runs yet');
  }
  const report = await readRunReport(runId!);
  if (!report) fail(`unknown run ${runId}`);
  if (asJson) process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  else {
    const r = report as { verdict?: string; summary?: Record<string, number>; results?: Array<{ checkId: string; status: string; severity: string }> };
    process.stdout.write(`run ${runId} · verdict ${r.verdict}\n`);
    process.stdout.write(`summary ${JSON.stringify(r.summary)}\n`);
    for (const item of r.results ?? []) process.stdout.write(`  ${String(item.status).padEnd(9)} ${item.checkId} (${item.severity})\n`);
  }
  return 0;
}

async function cmdHistory(asJson: boolean): Promise<number> {
  const home = launchproofHome();
  const paths = storagePaths(home);
  let ids: string[] = [];
  try {
    const entries = await readdir(paths.runs, { withFileTypes: true });
    ids = entries.filter((e) => e.isDirectory()).map((e) => e.name).sort().reverse().slice(0, 20);
  } catch { ids = []; }
  const rows: Array<Record<string, unknown>> = [];
  for (const id of ids) {
    const report = (await readRunReport(id, home)) as { verdict?: string; projectPath?: string; finishedAt?: string; summary?: unknown } | null;
    if (!report) continue; // skip orphaned run dirs with no report (never render as PASS)
    rows.push({ runId: id, verdict: report.verdict ?? 'ERROR', project: report.projectPath ?? '?', finishedAt: report.finishedAt ?? '?', summary: report.summary ?? {} });
  }
  const projects = await listProjects(home);
  if (asJson) process.stdout.write(`${JSON.stringify({ runs: rows, projects }, null, 2)}\n`);
  else {
    process.stdout.write(`projects (${projects.length}):\n`);
    for (const p of projects) process.stdout.write(`  ${p.id}  ${p.name}  ${p.path}  lastRun=${p.lastRunId ?? '-'}\n`);
    process.stdout.write(`runs (${rows.length}):\n`);
    for (const r of rows) process.stdout.write(`  ${r.runId}  ${r.verdict}  ${r.project}\n`);
  }
  return 0;
}

async function cmdExplain(checkId: string): Promise<number> {
  const registry = await loadDefaultRegistry();
  const check = registry.get(checkId.toUpperCase());
  if (!check) fail(`unknown check ${checkId}; see 'launchproof history' or daemon /api/checks`);
  process.stdout.write(`${check.id} — ${check.title} [${check.severity}/${check.cls}/${check.phase}]\n\nInvariant: ${check.invariant}\nSummary: ${check.summary}\nRemediation: ${check.remediation}\nProfiles: ${check.profiles.join(', ')}\nSurfaces: ${check.surfaces.join(', ') || 'none'}\nPrerequisites: ${check.prerequisites.join(', ') || 'none'}\nAgent-fixable: ${check.agentFixable ? 'yes (with approval)' : 'no'}\nReproduce: launchproof verify --only ${check.id}\n`);
  return 0;
}

async function cmdFix(checkId: string, opts: { root: string; runId: string; agent: 'codex' | 'claude' | 'script'; approve: boolean; dryRun: boolean }): Promise<number> {
  const id = checkId.toUpperCase();
  const report = (await readRunReport(opts.runId)) as { results?: Array<{ checkId: string; status: string; title?: string; observed?: string; reason?: string }>; projectPath?: string } | null;
  if (!report) fail(`unknown run ${opts.runId}`);
  const hit = report!.results?.find((r) => r.checkId === id);
  if (!hit) fail(`check ${id} not found in run ${opts.runId}`);
  if (hit.status !== 'BLOCK' && hit.status !== 'WARN') fail(`check ${id} is ${hit.status} — only BLOCK/WARN findings can be sent for fix`);
  const registry = await loadDefaultRegistry();
  const def = registry.get(id);
  const task = await createFixTask(
    {
      checkId: id,
      agentId: opts.agent,
      evidenceText: hit.observed ?? hit.reason ?? JSON.stringify(hit).slice(0, 2000),
      result: {
        id: `R-manual`, checkId: id, status: hit.status as 'BLOCK', severity: (def?.severity ?? 'major') as 'major',
        title: hit.title ?? def?.title ?? id, category: def?.category ?? 'general', verificationClass: (def?.cls ?? 'deterministic') as 'deterministic',
        evidence: [], affectedSurface: [], expected: def?.invariant ?? '', observed: hit.observed ?? '', explanation: '',
        remediation: def?.remediation ?? '', confidence: 'high', agentFixable: def?.agentFixable ?? true, durationMs: 0,
        startedAt: new Date().toISOString(), endedAt: new Date().toISOString(), phase: def?.phase ?? 'static',
      },
    },
    { runId: opts.runId, projectId: opts.root, resultId: `R-manual` },
  );
  process.stdout.write(`fix task ${task.id} for ${id} via ${opts.agent} [${task.status}]\n\n${task.instruction}\n\n`);
  if (!opts.approve) {
    process.stdout.write(`NOT sent: re-run with --approve to invoke the agent. Source is never modified without approval.\n`);
    process.stdout.write(`After any fix, re-run: launchproof verify --only ${id} --path ${opts.root}\n`);
    return 0;
  }
  const { runFixTask } = await import('../agents/fixloop.ts');
  const outcome = await runFixTask(task, { approved: true, dryRun: opts.dryRun });
  process.stdout.write(`${outcome.note}\n`);
  if (outcome.agentOutput) process.stdout.write(`\n--- agent output ---\n${outcome.agentOutput.slice(0, 3000)}\n`);
  process.stdout.write(`\nNext: launchproof verify --only ${id} (independent re-verification; agent output is not evidence)\n`);
  return 0;
}

async function cmdDoctor(): Promise<number> {
  const rows: Array<[string, string]> = [];
  rows.push(['node', `${process.version} (need >=24)`]);
  try {
    const tsc = await import('node:child_process').then((m) => m.execFileSync('npx', ['tsc', '--version'], { encoding: 'utf8' }).trim());
    rows.push(['typescript', tsc]);
  } catch {
    rows.push(['typescript', 'unavailable']);
  }
  const daemon = await daemonCall('GET', '/health');
  rows.push(['daemon', daemon.ok ? `reachable (${JSON.stringify(daemon.data)})` : `not running (${(daemon.data as { error?: string }).error})`]);
  try {
    await import('playwright');
    rows.push(['playwright', 'installed']);
    try {
      const { chromium } = await import('playwright');
      const browser = await chromium.launch({ headless: true });
      await browser.close();
      rows.push(['chromium', 'launch OK']);
    } catch (error) {
      rows.push(['chromium', `launch failed: ${error instanceof Error ? error.message : String(error)}`]);
    }
  } catch {
    rows.push(['playwright', 'not installed — browser checks will be UNVERIFIED']);
  }
  for (const agent of ['codex', 'claude', 'script'] as const) {
    try {
      const adapter = adapterFor(agent);
      const caps = await adapter.discoverCapabilities();
      rows.push([`agent:${agent}`, caps.available ? `available (${caps.tools.join(',') || 'no tools'})` : `unavailable: ${caps.gaps.join('; ')}`]);
    } catch (error) {
      rows.push([`agent:${agent}`, `error: ${error instanceof Error ? error.message : String(error)}`]);
    }
  }
  try {
    const git = await import('node:child_process').then((m) => m.execFileSync('git', ['--version'], { encoding: 'utf8' }).trim());
    rows.push(['git', git]);
  } catch {
    rows.push(['git', 'unavailable — change analysis disabled']);
  }
  let width = 0;
  for (const [k] of rows) width = Math.max(width, k.length);
  for (const [k, v] of rows) process.stdout.write(`${k.padEnd(width)}  ${v}\n`);
  return 0;
}

async function cmdDesktop(portOpt?: number): Promise<number> {
  const { createDaemon } = await import('../daemon/server.ts');
  const { port } = await createDaemon({ port: portOpt ?? 0 });
  const url = `http://127.0.0.1:${port}/`;
  process.stdout.write(`LaunchProof control plane: ${url}\n`);
  const opener = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'cmd' : 'xdg-open';
  try {
    const { execFile } = await import('node:child_process');
    const args = process.platform === 'win32' ? ['/c', 'start', url] : process.platform === 'darwin' ? [url] : [url];
    execFile(opener, args, (err) => {
      if (err) process.stdout.write(`open ${url} manually in a browser\n`);
    });
  } catch {
    process.stdout.write(`open ${url} manually in a browser\n`);
  }
  process.stdout.write(`press Ctrl+C to stop\n`);
  await new Promise(() => undefined);
  return 0;
}

export async function main(argv: string[]): Promise<number> {
  try {
    const args = [...argv];
    const asJson = args.includes('--json');
    const useDaemon = args.includes('--daemon');
    const useLocal = args.includes('--local');
    const filtered = args.filter((a) => a !== '--json' && a !== '--daemon' && a !== '--local');
    const [cmd, ...rest] = filtered;

    if (!cmd || cmd === '-h' || cmd === '--help' || cmd === 'help') {
      process.stdout.write(`${USAGE}\n`);
      return !cmd ? 2 : 0;
    }

    const globals: GlobalOpts = { json: asJson, daemon: useDaemon, local: useLocal };

    switch (cmd) {
      case 'init': {
        if (rest.includes('-h') || rest.includes('--help')) {
          process.stdout.write(`${USAGE}\n`);
          return 0;
        }
        const target = rest.find((a) => !a.startsWith('-')) ?? process.cwd();
        return cmdInit(target);
      }
      case 'detect': {
        if (rest.includes('-h') || rest.includes('--help')) {
          process.stdout.write(`${USAGE}\n`);
          return 0;
        }
        const target = rest.find((a) => !a.startsWith('-')) ?? process.cwd();
        return cmdDetect(target, globals.json);
      }
      case 'verify': {
        let target: string | undefined;
        let profile: ProfileId = 'launch';
        let strict = false;
        let only: string[] | undefined;
        for (let i = 0; i < rest.length; i += 1) {
          const a = rest[i]!;
          if (a === '--profile' || a.startsWith('--profile=')) {
            const v = a.includes('=') ? a.slice(a.indexOf('=') + 1) : rest[++i];
            if (!v || !['quick', 'launch', 'security', 'agent-change', 'stack', 'custom'].includes(v)) fail(`unknown profile: ${v ?? '(missing)'}`);
            profile = v as ProfileId;
          } else if (a === '--strict') strict = true;
          else if (a === '--only' || a.startsWith('--only=')) {
            const v = a.includes('=') ? a.slice(a.indexOf('=') + 1) : rest[++i];
            if (!v) fail('--only needs a comma-separated check id list');
            only = v.split(',').map((s) => s.trim().toUpperCase()).filter((s) => s.length > 0);
          } else if (a.startsWith('-')) fail(`unknown option: ${a}`);
          else if (!target) target = a;
          else fail('verify takes exactly one project path');
        }
        if (!target) fail('verify takes exactly one project path');
        const root = path.resolve(target!);
        if (globals.local) return verifyLocal(root, profile, strict, only, globals.json);
        return verifyViaDaemon(root, profile, strict, only, globals.json);
      }
      case 'report': {
        if (rest.includes('-h') || rest.includes('--help')) {
          process.stdout.write(`${USAGE}\n`);
          return 0;
        }
        let runId: string | undefined;
        for (let i = 0; i < rest.length; i += 1) {
          const a = rest[i]!;
          if (a === '--run' || a.startsWith('--run=')) runId = a.includes('=') ? a.slice(a.indexOf('=') + 1) : rest[++i];
          else if (a.startsWith('-')) fail(`unknown option: ${a}`);
          else if (!runId) runId = a;
          else fail(`unknown argument: ${a}`);
        }
        return cmdReport(runId, globals.json);
      }
      case 'history': {
        return cmdHistory(globals.json);
      }
      case 'explain': {
        if (!rest[0]) fail('explain needs a check id, e.g. launchproof explain AUTH-002');
        return cmdExplain(rest[0]);
      }
      case 'fix': {
        if (rest.includes('-h') || rest.includes('--help')) {
          process.stdout.write(`${USAGE}\n`);
          return 0;
        }
        let checkId = '';
        let root = process.cwd();
        let runId = '';
        let agent: 'codex' | 'claude' | 'script' = 'script';
        let approve = false;
        let dryRun = false;
        for (let i = 0; i < rest.length; i += 1) {
          const a = rest[i]!;
          if (a === '--path' || a.startsWith('--path=')) root = a.includes('=') ? a.slice(a.indexOf('=') + 1) : rest[++i]!;
          else if (a === '--run' || a.startsWith('--run=')) runId = a.includes('=') ? a.slice(a.indexOf('=') + 1) : rest[++i]!;
          else if (a === '--agent' || a.startsWith('--agent=')) {
            const v = (a.includes('=') ? a.slice(a.indexOf('=') + 1) : rest[++i]) as string;
            if (!['codex', 'claude', 'script'].includes(v)) fail(`unknown agent: ${v}`);
            agent = v as typeof agent;
          } else if (a === '--approve') approve = true;
          else if (a === '--dry-run') dryRun = true;
          else if (a.startsWith('-')) fail(`unknown option: ${a}`);
          else if (!checkId) checkId = a;
          else fail(`unknown argument: ${a}`);
        }
        if (!checkId) fail('fix needs a check id, e.g. launchproof fix AUTH-002 --run <id> --path <dir>');
        if (!runId) {
          const ids = await listRuns();
          runId = ids[0] ?? '';
          if (!runId) fail('no runs found; pass --run <id>');
          process.stdout.write(`using latest run ${runId}\n`);
        }
        return cmdFix(checkId, { root: path.resolve(root), runId, agent, approve, dryRun });
      }
      case 'doctor': {
        return cmdDoctor();
      }
      case 'desktop': {
        const portArg = rest.find((a) => a.startsWith('--port='));
        return cmdDesktop(portArg ? Number(portArg.slice(7)) : undefined);
      }
      case 'daemon': {
        const portArg = rest.find((a) => a.startsWith('--port='));
        const { createDaemon } = await import('../daemon/server.ts');
        const { port } = await createDaemon({ port: portArg ? Number(portArg.slice(7)) : 0 });
        process.stdout.write(`launchproof daemon listening on 127.0.0.1:${port}\n`);
        await new Promise(() => undefined);
        return 0;
      }
      default:
        fail(`unknown command: ${cmd}`);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`launchproof: ${message}\n`);
    return 2;
  }
  return 2;
}
