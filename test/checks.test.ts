import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadDefaultRegistry } from '../src/checks/registry.ts';
import { isCheckId, PHASE_ORDER } from '../src/model/types.ts';

const EXPECTED_IDS = [
  'REPO-001', 'REPO-002',
  'SECRET-001', 'SECRET-002', 'ENV-005',
  'AUTH-002', 'AUTH-003',
  'DB-003', 'DB-004', 'DB-005',
  'PAY-004', 'PAY-005',
  'DEP-006', 'DEP-007',
  'CI-007', 'CI-008', 'CI-009',
  'INFRA-001', 'INFRA-002',
  'OBS-001',
  'BROWSER-001', 'API-002',
  'AUTH-101', 'AUTH-102', 'AUTH-103',
  'API-104', 'API-105', 'PAY-106', 'FLOW-109',
  'BROWSER-101', 'BROWSER-102', 'BROWSER-103',
  'ADV-001',
].sort();

test('registry loads all design-inventory checks with unique valid ids', async () => {
  const registry = await loadDefaultRegistry();
  const ids = registry.ids();
  assert.deepEqual(ids, EXPECTED_IDS);
  for (const id of ids) assert.ok(isCheckId(id), `invalid id ${id}`);
  assert.equal(registry.size(), EXPECTED_IDS.length);
});

test('every check declares a complete contract', async () => {
  const registry = await loadDefaultRegistry();
  for (const check of registry.all()) {
    assert.ok(check.summary.length > 30, `${check.id} needs a summary`);
    assert.ok(check.invariant.length > 10, `${check.id} needs an invariant`);
    assert.ok(check.remediation.length > 10, `${check.id} needs remediation`);
    assert.ok(['deterministic', 'dynamic', 'agentic'].includes(check.cls), `${check.id} class`);
    assert.ok(PHASE_ORDER.includes(check.phase), `${check.id} phase ${check.phase}`);
    assert.ok(['critical', 'major', 'minor', 'info'].includes(check.severity), `${check.id} severity`);
    assert.ok(check.profiles.length > 0, `${check.id} profiles`);
    assert.ok(typeof check.applies === 'function', `${check.id} applies`);
    const cls = check.cls;
    if (cls === 'dynamic') {
      assert.ok(check.phase === 'runtime' || check.phase === 'browser' || check.phase === 'api' || check.phase === 'database' || check.phase === 'decision', `${check.id} dynamic phase`);
    }
    if (cls === 'agentic') {
      assert.ok(check.id === 'ADV-001', 'only ADV-001 is agentic');
    }
  }
});

test('deterministic, dynamic and agentic inventory counts match design', async () => {
  const registry = await loadDefaultRegistry();
  const deterministic = registry.all().filter((c) => c.cls === 'deterministic');
  const dynamic = registry.all().filter((c) => c.cls === 'dynamic');
  const agentic = registry.all().filter((c) => c.cls === 'agentic');
  assert.equal(deterministic.length, 22);
  assert.equal(dynamic.length, 10);
  assert.equal(agentic.length, 1);
});
