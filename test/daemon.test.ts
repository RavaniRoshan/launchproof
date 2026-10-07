import { test } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp } from 'node:fs/promises';

import { createDaemon } from '../src/daemon/server.ts';
import { listProjects, registerProject } from '../src/daemon/store.ts';
import { adapterFor } from '../src/agents/adapters.ts';
import { buildFixInstruction, buildVerifierInstruction } from '../src/agents/gateway.ts';
import { createFixTask, runFixTask } from '../src/agents/fixloop.ts';
import { main } from '../src/cli/main.ts';

const FIXTURES = path.join(import.meta.dirname, '..', 'fixtures');

async function tempHome(): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'lp-home-'));
  process.env.LAUNCHPROOF_HOME = dir;
  return dir;
}

test('daemon: health, checks, projects, verify quick, cancel unknown run', async () => {
  const home = await tempHome();
  const { port, close } = await createDaemon({ port: 0, home });
  try {
    const base = `http://127.0.0.1:${port}`;

    const health = await (await fetch(`${base}/health`)).json() as { ok: boolean };
    assert.equal(health.ok, true);

    const checks = await (await fetch(`${base}/api/checks`)).json() as { checks: Array<{ id: string }> };
    assert.ok(checks.checks.length >= 30, `expected 30+ checks, got ${checks.checks.length}`);
    assert.ok(checks.checks.some((c) => c.id === 'AUTH-002'));

    const created = await (await fetch(`${base}/api/projects`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ path: path.join(FIXTURES, 'secure-app'), name: 'secure-app' }),
    })).json() as { project: { id: string } };
    assert.ok(created.project.id);

    const projects = await listProjects(home);
    assert.equal(projects.length, 1);

    const started = await (await fetch(`${base}/api/verify`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ path: path.join(FIXTURES, 'secure-app'), profile: 'quick' }),
    })).json() as { run: { id: string } };
    assert.ok(started.run.id);

    // Second concurrent run must be rejected (max 1).
    const second = await fetch(`${base}/api/verify`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ path: path.join(FIXTURES, 'secure-app'), profile: 'quick' }),
    });
    assert.equal(second.status, 429);

    // Poll to completion.
    let verdict = '';
    for (let i = 0; i < 40; i += 1) {
      await new Promise((r) => setTimeout(r, 500));
      const report = await (await fetch(`${base}/api/runs/${started.run.id}`)).json() as { run: { status: string; verdict?: string } };
      if (report.run.status !== 'running' && report.run.status !== 'pending') {
        verdict = report.run.verdict ?? '';
        break;
      }
    }
    assert.equal(verdict, 'READY');

    const cancelMissing = await fetch(`${base}/api/runs/nope/cancel`, { method: 'POST' });
    assert.equal(cancelMissing.status, 404);
  } finally {
    await close();
  }
});

test('daemon: crash recovery marks orphaned running runs as ERROR', async () => {
  const home = await tempHome();
  const { close } = await createDaemon({ port: 0, home });
  await close();
  const { mkdir, writeFile } = await import('node:fs/promises');
  const { storagePaths } = await import('../src/storage/paths.ts');
  const paths = storagePaths(home);
  await mkdir(path.join(paths.runs, 'run_orphan'), { recursive: true });
  await writeFile(
    path.join(paths.runs, 'run_orphan', 'run.json'),
    JSON.stringify({ id: 'run_orphan', status: 'running', projectId: 'x', projectPath: '.', profile: 'quick', strict: false, createdAt: new Date().toISOString(), phases: [], plan: [] }),
    'utf8',
  );
  const second = await createDaemon({ port: 0, home });
  try {
    const { readFile } = await import('node:fs/promises');
    const raw = await readFile(path.join(paths.runs, 'run_orphan', 'run.json'), 'utf8');
    const record = JSON.parse(raw) as { status: string; recovered?: boolean };
    assert.equal(record.status, 'error');
    assert.equal(record.recovered, true);
  } finally {
    await second.close();
  }
});

test('agent gateway: adapters expose capability gaps honestly', async () => {
  for (const id of ['codex', 'claude', 'script'] as const) {
    const adapter = adapterFor(id);
    const caps = await adapter.discoverCapabilities();
    assert.equal(caps.id, id);
    assert.ok(Array.isArray(caps.gaps));
    if (!caps.available) assert.ok(caps.gaps.length > 0, `${id} unavailable must record gaps`);
  }
  const instruction = buildVerifierInstruction({
    checkId: 'AUTH-002',
    launchContract: {},
    relevantSource: [],
    evidence: [{ observed: 'x' }],
    objective: 'verify',
    constraints: ['no prod'],
  });
  assert.ok(instruction.includes('AUTH-002'));
  assert.ok(instruction.includes('Unable to verify'));
  const fix = buildFixInstruction({ checkId: 'AUTH-002', title: 't', evidence: 'e', surface: 's', invariant: 'i' });
  assert.ok(fix.includes('independently'));
});

test('fix loop: rejected without approval; approved dry-run never touches source', async () => {
  const task = await createFixTask(
    {
      checkId: 'AUTH-002',
      agentId: 'script',
      evidenceText: 'user A read user B record',
      result: {
        id: 'R-1', checkId: 'AUTH-002', status: 'BLOCK', severity: 'critical', title: 't',
        category: 'authorization', verificationClass: 'deterministic', evidence: [],
        affectedSurface: ['/api/x'], expected: 'invite-only', observed: 'open',
        explanation: '', remediation: '', confidence: 'high', agentFixable: true,
        durationMs: 0, startedAt: new Date().toISOString(), endedAt: new Date().toISOString(), phase: 'static',
      },
    },
    { runId: 'run_x', projectId: 'proj_x', resultId: 'R-1' },
  );
  assert.equal(task.status, 'pending_approval');
  assert.ok(task.instruction.includes('AUTH-002'));

  const rejected = await runFixTask(task, { approved: false });
  assert.equal(rejected.task.status, 'rejected');

  const dry = await runFixTask(task, { approved: true, dryRun: true });
  assert.equal(dry.task.status, 'approved');
  assert.ok(dry.note.includes('dry-run'));
});

test('cli: explain, history, report, fix (no approval) work headlessly', async () => {
  await tempHome();
  assert.equal(await main(['explain', 'AUTH-002']), 0);
  assert.equal(await main(['history']), 0);
  assert.equal(await main(['verify', '--help']), 2);
  assert.equal(await main(['init', '--help']), 0);
  assert.equal(await main(['detect', '--help']), 0);
  assert.equal(await main(['report', '--help']), 0);
  assert.equal(await main(['fix', '--help']), 0);
  // fix without --run and no runs yet -> usage error, not a crash
  assert.equal(await main(['fix', 'AUTH-002', '--path', path.join(FIXTURES, 'secure-app')]), 2);
});

test('store: registerProject is idempotent', async () => {
  const home = await tempHome();
  const a = await registerProject('x', path.join(FIXTURES, 'secure-app'), home);
  const b = await registerProject('x', path.join(FIXTURES, 'secure-app'), home);
  assert.equal(a.id, b.id);
});

test('daemon: evidence list/single, agents capabilities, fix preview without approval', async () => {
  const home = await tempHome();
  const { port, close } = await createDaemon({ port: 0, home });
  const base = `http://127.0.0.1:${port}`;
  try {
    // Run a quick verification on the vulnerable fixture (has BLOCKs + evidence).
    const started = await (await fetch(`${base}/api/verify`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ path: path.join(FIXTURES, 'vulnerable-app'), profile: 'quick' }),
    })).json() as { run: { id: string } };
    const runId = started.run.id;
    for (let i = 0; i < 40; i += 1) {
      await new Promise((r) => setTimeout(r, 500));
      const rep = await (await fetch(`${base}/api/runs/${runId}`)).json() as { run?: { status: string } };
      if (rep.run && rep.run.status !== 'running' && rep.run.status !== 'pending') break;
    }

    // Evidence list + single record.
    const evList = await (await fetch(`${base}/api/runs/${runId}/evidence`)).json() as { evidence: Array<{ id: string; category: string; sha256: string }> };
    assert.ok(evList.evidence.length > 0, 'run must have evidence records');
    const first = evList.evidence[0]!;
    assert.match(first.id, /^E-\d{4}$/);
    assert.ok(first.sha256.length === 64);
    const single = await (await fetch(`${base}/api/runs/${runId}/evidence?id=${first.id}`)).json() as { evidence: { id: string } };
    assert.equal(single.evidence.id, first.id);
    const missing = await fetch(`${base}/api/runs/${runId}/evidence?id=E-9999`);
    assert.equal(missing.status, 404);

    // Agent capability discovery records gaps, never crashes.
    const agents = await (await fetch(`${base}/api/agents`)).json() as { agents: Array<{ id: string; gaps: string[] }> };
    assert.deepEqual(agents.agents.map((a) => a.id).sort(), ['claude', 'codex', 'script']);
    for (const a of agents.agents) assert.ok(Array.isArray(a.gaps));

    // Fix preview: must NOT approve or run anything.
    const fix = await (await fetch(`${base}/api/runs/${runId}/fix`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ checkId: 'AUTH-002', agentId: 'script' }),
    })).json() as { approved: boolean; task: { status: string; instruction: string }; note: string };
    assert.equal(fix.approved, false);
    assert.equal(fix.task.status, 'pending_approval');
    assert.ok(fix.task.instruction.includes('AUTH-002'));
    assert.ok(fix.note.includes('approve:true'));

    // Fix on unknown check -> 404.
    const unknown = await fetch(`${base}/api/runs/${runId}/fix`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ checkId: 'NOPE-999', agentId: 'script' }),
    });
    assert.equal(unknown.status, 404);

    // Static UI: control plane HTML served (built bundle preferred, fallback OK).
    const page = await fetch(`${base}/`);
    assert.equal(page.status, 200);
    const html = await page.text();
    assert.ok(html.includes('<div id="root">') || html.includes('LAUNCHPROOF'), 'control plane HTML expected');
  } finally {
    await close();
  }
});
