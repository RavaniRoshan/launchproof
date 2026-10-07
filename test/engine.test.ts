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
import { decideVerdict } from '../src/model/result.ts';
import type { CheckResult } from '../src/model/result.ts';

const FIXTURES = path.join(import.meta.dirname, '..', 'fixtures');

const DYNAMIC_IDS = [
  'AUTH-101', 'AUTH-102', 'AUTH-103', 'API-104', 'API-105',
  'PAY-106', 'FLOW-109', 'BROWSER-101', 'BROWSER-102', 'BROWSER-103',
];
const AGENTIC_IDS = ['ADV-001'];

const VULNERABLE_EXPECTED: Record<string, string[]> = {
  'AUTH-002': ['BLOCK'],
  'AUTH-003': ['WARN'],
  'SECRET-001': ['BLOCK'],
  'SECRET-002': ['BLOCK'],
  'ENV-005': ['BLOCK'],
  'DB-003': ['BLOCK'],
  'DB-004': ['BLOCK'],
  'DB-005': ['WARN'],
  'PAY-004': ['BLOCK'],
  'PAY-005': ['BLOCK'],
  'CI-007': ['BLOCK'],
  'CI-008': ['BLOCK'],
  'CI-009': ['BLOCK'],
  'INFRA-001': ['WARN'],
  'INFRA-002': ['BLOCK'],
  'BROWSER-001': ['BLOCK'],
  'API-002': ['WARN'],
  'OBS-001': ['WARN'],
  'DEP-006': ['BLOCK'],
  'DEP-007': ['WARN'],
  'REPO-001': ['BLOCK', 'WARN'],
  'REPO-002': ['WARN'],
};

interface FixtureRun {
  source: string;
  baseUrl: string;
  results: CheckResult[];
  verdict: 'READY' | 'BLOCKED';
}

const cache = new Map<string, Promise<FixtureRun>>();

function runFixture(name: string): Promise<FixtureRun> {
  let pending = cache.get(name);
  if (!pending) {
    pending = (async () => {
      process.env.LAUNCHPROOF_HOME ??= await mkdtemp(path.join(os.tmpdir(), 'lp-home-'));
      const root = path.join(FIXTURES, name);
      const { project } = await discoverProject({ id: name, name, root });
      const { contract, source } = await loadContract(root, project);
      assert.equal(source, 'file', `${name} must load launchproof.yaml, not an inferred contract`);
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
        emit: () => undefined,
        persistResults: async () => undefined,
        persistPhases: async () => undefined,
      });

      assert.equal(outcome.results.length, registry.size(), `${name} must run every check in the registry`);
      return {
        source,
        baseUrl: contract.probes?.baseUrl ?? '',
        results: outcome.results,
        verdict: outcome.verdict,
      };
    })();
    cache.set(name, pending);
  }
  return pending;
}

function statusOf(results: CheckResult[], checkId: string): string {
  const result = results.find((r) => r.checkId === checkId);
  assert.ok(result, `missing result for ${checkId}`);
  return result.status;
}

test('fixtures load their launchproof.yaml contract with probe plans', async () => {
  const vulnerable = await runFixture('vulnerable-app');
  const secure = await runFixture('secure-app');
  assert.equal(vulnerable.baseUrl, 'http://127.0.0.1:4310');
  assert.equal(secure.baseUrl, 'http://127.0.0.1:4311');
});

test('vulnerable fixture: every planted defect is observed, verdict BLOCKED', async () => {
  const { results, verdict } = await runFixture('vulnerable-app');
  assert.equal(verdict, 'BLOCKED');

  for (const [checkId, allowed] of Object.entries(VULNERABLE_EXPECTED)) {
    const actual = statusOf(results, checkId);
    assert.ok(
      allowed.includes(actual),
      `${checkId} expected ${allowed.join('|')} but was ${actual}`,
    );
  }

  for (const checkId of [...DYNAMIC_IDS, ...AGENTIC_IDS]) {
    assert.equal(statusOf(results, checkId), 'UNVERIFIED', `${checkId} without runtime must be UNVERIFIED`);
  }

  for (const result of results) {
    assert.ok(result.status !== 'ERROR', `${result.checkId} errored: ${result.reason ?? ''}`);
    if (['PASS', 'BLOCK', 'WARN'].includes(result.status)) {
      assert.ok(result.evidence.length > 0, `${result.checkId} must attach evidence`);
    }
    if (result.status === 'UNVERIFIED') {
      assert.ok(result.reason || result.agentLabel, `${result.checkId} UNVERIFIED must carry a reason`);
    }
  }
});

test('secure fixture: all deterministic checks PASS, non-strict verdict READY', async () => {
  const { results, verdict } = await runFixture('secure-app');
  assert.equal(verdict, 'READY');

  for (const result of results) {
    assert.ok(result.status !== 'ERROR', `${result.checkId} errored: ${result.reason ?? ''}`);
    if (DYNAMIC_IDS.includes(result.checkId) || AGENTIC_IDS.includes(result.checkId)) {
      assert.equal(result.status, 'UNVERIFIED', `${result.checkId} without runtime must be UNVERIFIED`);
    } else {
      assert.equal(result.status, 'PASS', `${result.checkId} expected PASS but was ${result.status}: ${result.observed ?? ''}`);
    }
  }
});

test('strict mode promotes UNVERIFIED to BLOCKED; non-strict does not', async () => {
  const { results, verdict } = await runFixture('secure-app');
  assert.equal(verdict, 'READY');
  assert.equal(decideVerdict(results, { strict: false }), 'READY');
  assert.equal(decideVerdict(results, { strict: true }), 'BLOCKED');
});
