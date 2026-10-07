import { test } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdir, mkdtemp } from 'node:fs/promises';

import { executeRun } from '../src/engine/engine.ts';
import { loadContract } from '../src/contract/infer.ts';
import { discoverProject } from '../src/discovery/detect.ts';
import { loadDefaultRegistry } from '../src/checks/registry.ts';
import { EvidenceLedger } from '../src/evidence/ledger.ts';
import { newRunId } from '../src/model/ids.ts';
import type { CheckResult } from '../src/model/result.ts';
import { createRuntimeLab } from '../src/runtime/lab.ts';
import { createBrowserLab } from '../src/browser/playwright.ts';

const FIXTURES = path.join(import.meta.dirname, '..', 'fixtures');

const API_DYN = ['AUTH-101', 'AUTH-102', 'API-104', 'API-105', 'PAY-106'];
const RUNTIME_PHASE = ['FLOW-109'];
const BROWSER_PHASE = ['AUTH-103', 'BROWSER-101', 'BROWSER-102', 'BROWSER-103'];

interface LiveRun {
  results: CheckResult[];
  verdict: 'READY' | 'BLOCKED';
}

const cache = new Map<string, Promise<LiveRun>>();

function runLive(name: string): Promise<LiveRun> {
  let pending = cache.get(name);
  if (!pending) {
    pending = (async () => {
      process.env.LAUNCHPROOF_HOME ??= await mkdtemp(path.join(os.tmpdir(), 'lp-home-'));
      const root = path.join(FIXTURES, name);
      const { project } = await discoverProject({ id: name, name, root });
      const { contract } = await loadContract(root, project);
      assert.ok(contract.probes, `${name} contract must declare probes`);

      const registry = await loadDefaultRegistry();
      const runId = newRunId();
      const scratchDir = await mkdtemp(path.join(os.tmpdir(), 'lp-scratch-'));
      await mkdir(path.join(scratchDir, 'evidence'), { recursive: true });
      const ledger = await EvidenceLedger.open(runId, path.join(scratchDir, 'evidence'));

      const outcome = await executeRun({
        run: {
          id: runId,
          projectId: project.id,
          projectPath: root,
          profile: 'custom',
          status: 'running',
          strict: false,
          createdAt: new Date().toISOString(),
          phases: [],
          plan: [],
        },
        root,
        contract,
        project,
        registry,
        ledger,
        signal: new AbortController().signal,
        profile: 'custom',
        strict: false,
        scratchDir,
        hooks: [createRuntimeLab(), createBrowserLab()],
        emit: () => undefined,
        persistResults: async () => undefined,
        persistPhases: async () => undefined,
      });

      assert.equal(outcome.results.length, registry.size());
      return { results: outcome.results, verdict: outcome.verdict };
    })();
    cache.set(name, pending);
  }
  return pending;
}

function resultOf(results: CheckResult[], checkId: string): CheckResult {
  const result = results.find((r) => r.checkId === checkId);
  assert.ok(result, `missing result for ${checkId}`);
  return result;
}

function statusOf(results: CheckResult[], checkId: string): string {
  return resultOf(results, checkId).status;
}

function browserMissing(results: CheckResult[]): boolean {
  const r = resultOf(results, 'BROWSER-101');
  return r.status === 'UNVERIFIED' && /browser runtime unavailable/i.test(r.reason ?? '');
}

function assertNoErrors(results: CheckResult[]): void {
  for (const result of results) {
    assert.ok(
      result.status !== 'ERROR',
      `${result.checkId} errored: ${result.reason ?? ''} ${JSON.stringify(result.evidence).slice(0, 500)}`,
    );
  }
}

test('vulnerable fixture live run: IDOR, admin leak, replay, unsigned webhook and browser flows BLOCK', async () => {
  const { results, verdict } = await runLive('vulnerable-app');
  assertNoErrors(results);
  assert.equal(verdict, 'BLOCKED');

  for (const id of ['AUTH-101', 'AUTH-102', 'AUTH-103', 'API-104', 'PAY-106']) {
    assert.equal(statusOf(results, id), 'BLOCK', `${id} expected BLOCK but was ${statusOf(results, id)}: ${resultOf(results, id).observed ?? ''}`);
  }
  assert.equal(statusOf(results, 'API-105'), 'WARN', 'malformed JSON causing 5xx is WARN');
  assert.equal(statusOf(results, 'FLOW-109'), 'PASS', 'declared flow completes on the vulnerable app');
  assert.equal(statusOf(results, 'ADV-001'), 'BLOCK', 'probe-backed attack sweep succeeds against the vulnerable app');
  assert.equal(resultOf(results, 'ADV-001').agentLabel, 'Observed', 'agentic result must carry a label');

  if (browserMissing(results)) {
    for (const id of BROWSER_PHASE.filter((x) => x !== 'AUTH-103')) {
      assert.equal(statusOf(results, id), 'UNVERIFIED', `${id} without chromium must be UNVERIFIED`);
    }
  } else {
    for (const id of ['BROWSER-101', 'BROWSER-102', 'BROWSER-103']) {
      assert.equal(statusOf(results, id), 'BLOCK', `${id} expected BLOCK but was ${statusOf(results, id)}: ${resultOf(results, id).observed ?? ''}`);
    }
  }

  assert.equal(statusOf(results, 'AUTH-103'), 'BLOCK', 'pre-logout session still valid after logout');
  for (const id of [...API_DYN, ...RUNTIME_PHASE]) {
    assert.ok(resultOf(results, id).evidence.length > 0, `${id} must attach evidence`);
  }
});

test('secure fixture live run: every dynamic check PASS, verdict READY', async () => {
  const { results, verdict } = await runLive('secure-app');
  assertNoErrors(results);
  assert.equal(verdict, 'READY');

  const passing = [...API_DYN, ...RUNTIME_PHASE, 'AUTH-103'];
  for (const id of passing) {
    const r = resultOf(results, id);
    assert.equal(r.status, 'PASS', `${id} expected PASS but was ${r.status}: ${r.observed ?? r.reason ?? ''}`);
  }
  assert.equal(statusOf(results, 'ADV-001'), 'PASS', 'every probe-backed attack attempt is refuted');
  assert.equal(resultOf(results, 'ADV-001').agentLabel, 'Observed', 'agentic result must carry a label');

  if (browserMissing(results)) {
    for (const id of ['BROWSER-101', 'BROWSER-102', 'BROWSER-103']) {
      assert.equal(statusOf(results, id), 'UNVERIFIED', `${id} without chromium must be UNVERIFIED`);
    }
  } else {
    for (const id of ['BROWSER-101', 'BROWSER-102', 'BROWSER-103']) {
      const r = resultOf(results, id);
      assert.equal(r.status, 'PASS', `${id} expected PASS but was ${r.status}: ${r.observed ?? r.reason ?? ''}`);
    }
  }
});
