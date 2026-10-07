import { spawn } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { executeRun } from '../engine/engine.ts';
import type { PhaseHook } from '../engine/engine.ts';
import { loadContract } from '../contract/infer.ts';
import { discoverProject } from '../discovery/detect.ts';
import { analyzeChanges } from '../discovery/changed.ts';
import { loadDefaultRegistry } from '../checks/registry.ts';
import { EvidenceLedger } from '../evidence/ledger.ts';
import { newRunId } from '../model/ids.ts';
import { summarize, decideVerdict } from '../model/result.ts';
import type { CheckResult } from '../model/result.ts';
import type { PhaseState, RunEvent, RunRecord } from '../model/run.ts';
import { createRuntimeLab } from '../runtime/lab.ts';
import { createBrowserLab } from '../browser/playwright.ts';
import { ensureStorage, storagePaths, writeJsonAtomic, readJson } from '../storage/paths.ts';
import { listProjects, registerProject, touchProjectRun, readRunReport } from './store.ts';
import type { ProfileId } from '../checks/types.ts';

export interface DaemonOptions {
  port?: number;
  host?: string;
  home?: string;
}

interface ActiveRun {
  record: RunRecord;
  controller: AbortController;
  results: CheckResult[];
  promise: Promise<void>;
  clients: Set<ServerResponse>;
}

const runs = new Map<string, ActiveRun>();

function sendJson(res: ServerResponse, code: number, value: unknown): void {
  const body = JSON.stringify(value);
  res.writeHead(code, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) });
  res.end(body);
}

async function readBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const raw = Buffer.concat(chunks).toString('utf8');
  if (!raw) return {};
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return {};
  }
}

function broadcast(active: ActiveRun, event: RunEvent): void {
  const line = `data: ${JSON.stringify(event)}\n\n`;
  for (const client of active.clients) {
    try {
      client.write(line);
    } catch {
      // drop broken SSE clients lazily
    }
  }
}

async function startVerification(opts: {
  projectPath: string;
  profile: ProfileId;
  strict: boolean;
  only?: string[];
  home?: string;
}): Promise<RunRecord> {
  const home = opts.home;
  const paths = await ensureStorage(home);
  const root = path.resolve(opts.projectPath);
  const runId = newRunId();
  const runDir = path.join(paths.runs, runId);
  await mkdir(runDir, { recursive: true });
  await mkdir(path.join(runDir, 'evidence'), { recursive: true });

  const projectName = path.basename(root);
  const { project } = await discoverProject({ id: projectName, name: projectName, root });
  const changeAnalysis = await analyzeChanges(root).catch(() => undefined);
  const { contract, validation } = await loadContract(root, project);
  if (!validation.ok) throw new Error(`contract invalid: ${validation.errors.join('; ')}`);
  const registry = await loadDefaultRegistry();
  const ledger = await EvidenceLedger.open(runId, path.join(runDir, 'evidence'));

  const record: RunRecord = {
    id: runId,
    projectId: project.id,
    projectPath: root,
    profile: opts.profile,
    status: 'running',
    strict: opts.strict,
    createdAt: new Date().toISOString(),
    startedAt: new Date().toISOString(),
    phases: [],
    plan: [],
    changeAnalysis,
    contractSnapshot: contract,
    projectSnapshot: project,
    project: { id: project.id, name: project.name, path: root, createdAt: new Date().toISOString() },
  };
  await writeJsonAtomic(path.join(runDir, 'run.json'), record);

  const controller = new AbortController();
  const active: ActiveRun = { record, controller, results: [], promise: Promise.resolve(), clients: new Set() };
  runs.set(runId, active);

  const hooks: PhaseHook[] = [createRuntimeLab(), createBrowserLab()];
  const emit = (event: RunEvent): void => {
    broadcast(active, event);
  };

  active.promise = (async () => {
    try {
      const outcome = await executeRun({
        run: record,
        root,
        contract,
        project,
        changeAnalysis,
        registry,
        ledger,
        signal: controller.signal,
        profile: opts.profile,
        strict: opts.strict,
        only: opts.only,
        scratchDir: runDir,
        hooks,
        emit,
        persistResults: async (results) => {
          active.results = results;
          record.summary = summarize(results);
          await writeJsonAtomic(path.join(runDir, 'results.json'), results);
        },
        persistPhases: async (phases: PhaseState[]) => {
          record.phases = phases;
          await writeJsonAtomic(path.join(runDir, 'phases.json'), phases);
        },
      });
      record.status = controller.signal.aborted ? 'cancelled' : 'completed';
      record.verdict = outcome.verdict;
      record.summary = outcome.summary;
      record.endedAt = new Date().toISOString();
      record.phases = outcome.phases;
      const report = {
        runId,
        projectPath: root,
        profile: opts.profile,
        strict: opts.strict,
        startedAt: record.startedAt,
        finishedAt: record.endedAt,
        verdict: outcome.verdict,
        summary: outcome.summary,
        results: outcome.results.map((r) => ({
          checkId: r.checkId, title: r.title, status: r.status, severity: r.severity,
          observed: r.observed, reason: r.reason, evidence: r.evidence.length, agentLabel: r.agentLabel,
        })),
      };
      await writeJsonAtomic(path.join(runDir, 'report.json'), report);
      await writeJsonAtomic(path.join(runDir, 'run.json'), record);
      await touchProjectRun(project.id, runId, home).catch(() => undefined);
      broadcast(active, { type: controller.signal.aborted ? 'run.cancelled' : 'run.finished', runId, at: new Date().toISOString(), data: { verdict: outcome.verdict } });
    } catch (error) {
      // Crash recovery: persist an ERROR run instead of corrupting history.
      record.status = controller.signal.aborted ? 'cancelled' : 'error';
      record.error = error instanceof Error ? error.message : String(error);
      record.endedAt = new Date().toISOString();
      await writeJsonAtomic(path.join(runDir, 'run.json'), record).catch(() => undefined);
      broadcast(active, { type: 'run.error', runId, at: new Date().toISOString(), message: record.error });
    } finally {
      for (const client of [...active.clients]) {
        try { client.end(); } catch { /* ignore */ }
      }
      active.clients.clear();
    }
  })();

  return record;
}

export async function createDaemon(options: DaemonOptions = {}): Promise<{ server: Server; port: number; close(): Promise<void> }> {
  const home = options.home;
  const paths = await ensureStorage(home);
  const host = options.host ?? '127.0.0.1';

  const server = createServer(async (req, res) => {
    // CORS for the local control plane only.
    res.setHeader('access-control-allow-origin', '*');
    res.setHeader('access-control-allow-methods', 'GET,POST,DELETE,OPTIONS');
    res.setHeader('access-control-allow-headers', 'content-type');
    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    const pathname = url.pathname;

    try {
      if (req.method === 'GET' && pathname === '/health') {
        sendJson(res, 200, { ok: true, version: '0.1.0', runs: runs.size, time: new Date().toISOString() });
        return;
      }
      if (req.method === 'GET' && pathname === '/api/checks') {
        const registry = await loadDefaultRegistry();
        sendJson(res, 200, { checks: registry.all().map((c) => ({ id: c.id, title: c.title, severity: c.severity, cls: c.cls, phase: c.phase })) });
        return;
      }
      if (req.method === 'GET' && pathname === '/api/projects') {
        sendJson(res, 200, { projects: await listProjects(home) });
        return;
      }
      if (req.method === 'POST' && pathname === '/api/projects') {
        const body = (await readBody(req)) as { name?: string; path?: string };
        if (!body.path) {
          sendJson(res, 400, { error: 'path is required' });
          return;
        }
        const rec = await registerProject(body.name ?? path.basename(path.resolve(body.path)), body.path, home);
        sendJson(res, 200, { project: rec });
        return;
      }
      if (req.method === 'POST' && pathname === '/api/verify') {
        const body = (await readBody(req)) as { path?: string; profile?: ProfileId; strict?: boolean; only?: string[] };
        if (runs.size >= 1 && [...runs.values()].some((r) => r.record.status === 'running')) {
          sendJson(res, 429, { error: 'a verification run is already active (max 1 concurrent run)' });
          return;
        }
        if (!body.path) {
          sendJson(res, 400, { error: 'path is required' });
          return;
        }
        const record = await startVerification({
          projectPath: body.path,
          profile: body.profile ?? 'launch',
          strict: Boolean(body.strict),
          only: body.only,
          home,
        });
        sendJson(res, 202, { run: record });
        return;
      }
      const runMatch = /^\/api\/runs\/([^/]+)(\/events|\/cancel|\/report|\/evidence|\/fix)?$/.exec(pathname);
      if (runMatch) {
        const runId = runMatch[1]!;
        const suffix = runMatch[2] ?? '';
        if (suffix === '/events' && req.method === 'GET') {
          const active = runs.get(runId);
          if (!active) {
            // Historical run: replay stored phases/results then close.
            const report = await readRunReport(runId, home);
            res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive' });
            res.write(`data: ${JSON.stringify({ type: 'run.finished', runId, at: new Date().toISOString(), data: report })}\n\n`);
            res.end();
            return;
          }
          res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive' });
          active.clients.add(res);
          req.on('close', () => active.clients.delete(res));
          res.write(`data: ${JSON.stringify({ type: 'run.started', runId, at: new Date().toISOString() })}\n\n`);
          return;
        }
        if (suffix === '/cancel' && req.method === 'POST') {
          const active = runs.get(runId);
          if (!active) {
            sendJson(res, 404, { error: 'unknown run' });
            return;
          }
          active.controller.abort();
          active.record.cancelRequested = true;
          sendJson(res, 200, { ok: true, runId });
          return;
        }
        if ((suffix === '' || suffix === '/report') && req.method === 'GET') {
          const active = runs.get(runId);
          if (active) {
            sendJson(res, 200, {
              run: active.record,
              summary: active.record.summary ?? summarize(active.results),
              verdict: active.record.verdict ?? decideVerdict(active.results, { strict: active.record.strict }),
              results: active.results,
            });
            return;
          }
          const report = await readRunReport(runId, home);
          if (!report) {
            sendJson(res, 404, { error: 'unknown run' });
            return;
          }
          sendJson(res, 200, report);
          return;
        }
        if (suffix === '/evidence' && req.method === 'GET') {
          // Evidence ledger read: one record (?id=E-0001) or all for the run.
          const { readFile, readdir } = await import('node:fs/promises');
          const evDir = path.join(paths.runs, runId, 'evidence');
          const wanted = url.searchParams.get('id');
          try {
            if (wanted) {
              const raw = await readFile(path.join(evDir, `${wanted}.json`), 'utf8');
              sendJson(res, 200, { evidence: JSON.parse(raw) });
              return;
            }
            const files = (await readdir(evDir)).filter((f) => f.endsWith('.json'));
            const list = [];
            for (const f of files) {
              try { list.push(JSON.parse(await readFile(path.join(evDir, f), 'utf8'))); } catch { /* skip corrupt */ }
            }
            list.sort((a, b) => String(a.id).localeCompare(String(b.id)));
            sendJson(res, 200, { evidence: list });
            return;
          } catch {
            sendJson(res, 404, { error: 'no evidence for this run' });
            return;
          }
        }
        if (suffix === '/fix' && req.method === 'POST') {
          // Fix loop (opt-in): preview by default; agent runs only with approve:true.
          const body = (await readBody(req)) as { checkId?: string; agentId?: 'codex' | 'claude' | 'script'; approve?: boolean };
          if (!body.checkId) { sendJson(res, 400, { error: 'checkId is required' }); return; }
          const report = (await readRunReport(runId, home)) as { results?: Array<Record<string, unknown>> } | null;
          const active = runs.get(runId);
          const results = active?.results ?? report?.results ?? [];
          const hit = results.find((r) => r.checkId === body.checkId);
          if (!hit) { sendJson(res, 404, { error: `check ${body.checkId} not found in run ${runId}` }); return; }
          if (hit.status !== 'BLOCK' && hit.status !== 'WARN') {
            sendJson(res, 400, { error: `check ${body.checkId} is ${hit.status}; only BLOCK/WARN findings can be fixed` });
            return;
          }
          const { createFixTask, runFixTask } = await import('../agents/fixloop.ts');
          const { loadDefaultRegistry } = await import('../checks/registry.ts');
          const registry = await loadDefaultRegistry();
          const def = registry.get(body.checkId);
          const task = await createFixTask(
            {
              checkId: body.checkId,
              agentId: body.agentId ?? 'script',
              evidenceText: String(hit.observed ?? hit.reason ?? ''),
              result: {
                id: `R-daemon`, checkId: body.checkId, status: hit.status as 'BLOCK',
                severity: (def?.severity ?? 'major') as 'major', title: String(hit.title ?? body.checkId),
                category: def?.category ?? 'general', verificationClass: (def?.cls ?? 'deterministic') as 'deterministic',
                evidence: [], affectedSurface: [], expected: def?.invariant ?? '',
                observed: String(hit.observed ?? ''), explanation: '', remediation: def?.remediation ?? '',
                confidence: 'high', agentFixable: def?.agentFixable ?? true, durationMs: 0,
                startedAt: new Date().toISOString(), endedAt: new Date().toISOString(), phase: def?.phase ?? 'static',
              },
            },
            { runId, projectId: active?.record.projectId ?? runId, resultId: 'R-daemon' },
          );
          if (!body.approve) {
            sendJson(res, 200, { task, approved: false, note: 'preview only: approve:true required before any agent runs or source changes' });
            return;
          }
          const outcome = await runFixTask(task, { approved: true });
          sendJson(res, 200, { task: outcome.task, approved: true, note: outcome.note, instruction: task.instruction });
          return;
        }
        if (suffix === '' && req.method === 'DELETE') {
          runs.delete(runId);
          sendJson(res, 200, { ok: true });
          return;
        }
      }
      if (req.method === 'GET' && pathname === '/api/agents') {
        // Capability discovery: gaps are recorded, never invented.
        const { adapterFor } = await import('../agents/adapters.ts');
        const out = [];
        for (const id of ['codex', 'claude', 'script'] as const) {
          try {
            out.push(await adapterFor(id).discoverCapabilities());
          } catch (error) {
            out.push({ id, available: false, tools: [], networkAccess: false, streaming: false, approvals: false, gaps: [error instanceof Error ? error.message : String(error)] });
          }
        }
        sendJson(res, 200, { agents: out });
        return;
      }
      if (req.method === 'GET' && pathname === '/api/runs') {
        const { readdir } = await import('node:fs/promises');
        let ids: string[] = [];
        try {
          const entries = await readdir(paths.runs, { withFileTypes: true });
          ids = entries.filter((e) => e.isDirectory()).map((e) => e.name).sort().reverse().slice(0, 50);
        } catch { ids = []; }
        const live = [...runs.values()].map((r) => ({ id: r.record.id, status: r.record.status, verdict: r.record.verdict, profile: r.record.profile }));
        sendJson(res, 200, { live, recent: ids });
        return;
      }
      // Static control plane: Vite build at src/ui/dist/ (preferred),
      // single-file fallback at src/ui/index.html. No verification logic in either.
      if (req.method === 'GET') {
        const { readFile, stat } = await import('node:fs/promises');
        const { fileURLToPath } = await import('node:url');
        const here = path.dirname(fileURLToPath(import.meta.url));
        const distDir = path.join(here, '..', 'ui', 'dist');
        const isAsset = pathname.startsWith('/assets/');
        const isPage = pathname === '/' || pathname === '/app' || pathname === '/app/';
        if (isAsset) {
          const rel = pathname.slice(1); // strip leading /
          const full = path.join(distDir, rel);
          if (!full.startsWith(distDir)) { sendJson(res, 403, { error: 'forbidden' }); return; }
          try {
            const info = await stat(full);
            if (info.isFile()) {
              const body = await readFile(full);
              const type = full.endsWith('.js') ? 'application/javascript' : full.endsWith('.css') ? 'text/css' : full.endsWith('.svg') ? 'image/svg+xml' : full.endsWith('.woff2') ? 'font/woff2' : 'application/octet-stream';
              res.writeHead(200, { 'content-type': type, 'cache-control': 'public, max-age=31536000, immutable', 'content-length': body.length });
              res.end(body);
              return;
            }
          } catch { /* fall through to 404 */ }
          sendJson(res, 404, { error: `asset not found ${pathname}` });
          return;
        }
        if (isPage) {
          const candidates = [path.join(distDir, 'index.html'), path.join(here, '..', 'ui', 'index.html')];
          for (const htmlFile of candidates) {
            try {
              const html = await readFile(htmlFile, 'utf8');
              res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
              res.end(html);
              return;
            } catch { /* try next candidate */ }
          }
          sendJson(res, 500, { error: 'control plane UI not built (run npm run build in src/ui-frontend)' });
          return;
        }
      }
      sendJson(res, 404, { error: `unknown route ${pathname}` });
    } catch (error) {
      sendJson(res, 500, { error: error instanceof Error ? error.message : String(error) });
    }
  });

  const port = await new Promise<number>((resolve, reject) => {
    server.on('error', reject);
    server.listen(options.port ?? 0, host, () => {
      const addr = server.address();
      if (addr && typeof addr === 'object') resolve(addr.port);
      else resolve(options.port ?? 0);
    });
  });

  // Crash recovery: mark orphaned running runs as ERROR on boot.
  try {
    const { readdir, readFile, writeFile } = await import('node:fs/promises');
    const entries = await readdir(paths.runs, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const runFile = path.join(paths.runs, entry.name, 'run.json');
      try {
        const raw = await readFile(runFile, 'utf8');
        const record = JSON.parse(raw) as RunRecord;
        if (record.status === 'running') {
          record.status = 'error';
          record.recovered = true;
          record.error = 'daemon restarted while this run was active; run marked as recovered ERROR';
          record.endedAt = new Date().toISOString();
          await writeFile(runFile, JSON.stringify(record, null, 2), 'utf8');
        }
      } catch { /* ignore corrupt entries */ }
    }
  } catch { /* first boot */ }

  // Port file for CLI/UI discovery.
  try {
    await writeFile(path.join(paths.root, 'daemon.json'), JSON.stringify({ host, port, pid: process.pid, startedAt: new Date().toISOString() }, null, 2), 'utf8');
  } catch { /* ignore */ }

  void spawn;
  void delay;

  return {
    server,
    port,
    close: async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      for (const active of runs.values()) {
        try { active.controller.abort(); } catch { /* ignore */ }
      }
    },
  };
}
