import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateResult, summarize, decideVerdict } from '../src/model/result.ts';
import type { CheckResult } from '../src/model/result.ts';

function base(overrides: Partial<CheckResult> = {}): CheckResult {
  return {
    id: 'r_1',
    checkId: 'REPO-001',
    status: 'PASS',
    severity: 'critical',
    title: 't',
    category: 'repository',
    verificationClass: 'deterministic',
    evidence: [{ id: 'e_1', category: 'SOURCE', title: 'sample' }],
    affectedSurface: [],
    expected: 'no sensitive files',
    observed: 'scanned 10 files',
    explanation: 'why',
    remediation: 'fix',
    confidence: 'high',
    agentFixable: true,
    durationMs: 1,
    startedAt: '2026-01-01T00:00:00.000Z',
    endedAt: '2026-01-01T00:00:01.000Z',
    phase: 'static',
    ...overrides,
  };
}

test('BLOCK without evidence is rejected', () => {
  assert.throws(() => validateResult(base({ status: 'BLOCK', evidence: [] })), /without evidence/);
});

test('WARN without evidence is rejected', () => {
  assert.throws(() => validateResult(base({ status: 'WARN', evidence: [] })), /without evidence/);
});

test('PASS without evidence is rejected for deterministic results', () => {
  assert.throws(() => validateResult(base({ status: 'PASS', evidence: [] })), /must record how it was verified/);
});

test('UNVERIFIED without reason is rejected', () => {
  assert.throws(() => validateResult(base({ status: 'UNVERIFIED', reason: ' ', evidence: [] })), /without a reason/);
});

test('SKIPPED with reason is accepted without evidence', () => {
  validateResult(base({ status: 'SKIPPED', reason: 'no runtime', evidence: [] }));
});

test('agent claims can never yield PASS', () => {
  assert.throws(() => validateResult(base({ status: 'PASS', confidence: 'agent_claim' })), /agent claims can never produce PASS/);
});

test('agentic results require a label', () => {
  assert.throws(
    () => validateResult(base({ verificationClass: 'agentic', status: 'PASS', agentLabel: undefined, confidence: 'verified' })),
    /require an explicit label/,
  );
});

test('agentic PASS with label and confidence is accepted', () => {
  validateResult(base({ verificationClass: 'agentic', status: 'PASS', agentLabel: 'Observed', confidence: 'verified' }));
});

test('unknown status is rejected', () => {
  assert.throws(
    // @ts-expect-error intentionally invalid status
    () => validateResult(base({ status: 'MAYBE' })),
    /unknown status/,
  );
});

test('summarize counts every status and never folds UNVERIFIED into pass', () => {
  const results = [
    base({ status: 'PASS' }),
    base({ status: 'BLOCK', evidence: [{ id: 'e_x', category: 'SOURCE', title: 'sample' }] }),
    base({ status: 'WARN', evidence: [{ id: 'e_x', category: 'SOURCE', title: 'sample' }] }),
    base({ status: 'SKIPPED', reason: 'r', evidence: [] }),
    base({ status: 'UNVERIFIED', reason: 'r', evidence: [] }),
    base({ status: 'ERROR', reason: 'r', evidence: [] }),
  ];
  const summary = summarize(results);
  assert.equal(summary.total, 6);
  assert.equal(summary.pass, 1);
  assert.equal(summary.block, 1);
  assert.equal(summary.warn, 1);
  assert.equal(summary.skipped, 1);
  assert.equal(summary.unverified, 1);
  assert.equal(summary.error, 1);
});

test('decideVerdict: BLOCK yields BLOCKED; UNVERIFIED blocks only in strict mode', () => {
  const blocked = [base({ status: 'BLOCK', evidence: [{ id: 'e_x', category: 'SOURCE', title: 'sample' }] })];
  assert.equal(decideVerdict(blocked), 'BLOCKED');

  const unverified = [base({ status: 'UNVERIFIED', reason: 'no runtime', evidence: [] })];
  assert.equal(decideVerdict(unverified), 'READY');
  assert.equal(decideVerdict(unverified, { strict: true }), 'BLOCKED');

  const passes = [base({ status: 'PASS' })];
  assert.equal(decideVerdict(passes, { strict: true }), 'READY');
});
