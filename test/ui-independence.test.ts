import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir, access } from 'node:fs/promises';
import path from 'node:path';

const ROOT = path.join(import.meta.dirname, '..');

async function walk(dir: string, exts: string[]): Promise<string[]> {
  const out: string[] = [];
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...(await walk(full, exts)));
    else if (exts.some((x) => e.name.endsWith(x))) out.push(full);
  }
  return out;
}

const isBackend = (f: string) => !f.includes('ui-frontend') && !f.includes(`${path.sep}ui${path.sep}`);

test('UI20: root typecheck excludes the Space UI frontend', async () => {
  const tsconfig = JSON.parse(await readFile(path.join(ROOT, 'tsconfig.json'), 'utf8')) as {
    exclude?: string[];
    include?: string[];
  };
  assert.ok(tsconfig.exclude?.includes('src/ui-frontend'), 'root tsconfig must exclude src/ui-frontend');
  assert.ok(!(tsconfig.include ?? []).some((i) => i.includes('ui-frontend')), 'root include must not pull ui-frontend');
});

test('UI20: backend (engine, daemon, CLI, CI, policy) never imports Space UI / React', async () => {
  const banned = /from ['"](?:react|react-dom|next|tailwindcss|motion|lucide-react|@base-ui\/|@spaceui|space-ui)/;
  const files = await walk(path.join(ROOT, 'src'), ['.ts']);
  const offenders: string[] = [];
  for (const f of files) {
    if (!isBackend(f)) continue;
    const content = await readFile(f, 'utf8');
    if (banned.test(content)) offenders.push(path.relative(ROOT, f));
  }
  assert.deepEqual(offenders, [], `backend must not depend on UI libraries: ${offenders.join(', ')}`);
});

test('UI20: root package.json has no frontend dependencies (Space UI confined)', async () => {
  const pkg = JSON.parse(await readFile(path.join(ROOT, 'package.json'), 'utf8')) as {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };
  const all = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
  for (const banned of ['react', 'react-dom', 'next', 'tailwindcss', 'motion', '@base-ui/react', '@base-ui-components/react']) {
    assert.ok(!(banned in all), `root package.json must not depend on ${banned}`);
  }
});

test('UI21: frontend never computes verification results (no engine imports, no verdict math)', async () => {
  const frontend = path.join(ROOT, 'src', 'ui-frontend', 'src');
  const files = await walk(frontend, ['.ts', '.tsx']);
  assert.ok(files.length > 5, 'frontend source expected');
  const engineSymbols = /decideVerdict|validateResult|executeRun|selectChecks|summarize\(/;
  const verdictMath = /status\s*===?\s*['"]BLOCK['"]\s*\?\s*['"]BLOCKED['"]/;
  const offenders: string[] = [];
  for (const f of files) {
    const content = await readFile(f, 'utf8');
    if (engineSymbols.test(content) || verdictMath.test(content)) offenders.push(path.relative(ROOT, f));
  }
  assert.deepEqual(offenders, [], `UI must not compute results: ${offenders.join(', ')}`);
});

test('UI21: fallback single-file UI also takes verdict only from the daemon', async () => {
  const html = await readFile(path.join(ROOT, 'src', 'ui', 'index.html'), 'utf8');
  assert.ok(!/status\s*===\s*'BLOCK'\s*\?\s*'BLOCKED'/.test(html), 'fallback UI must not derive verdict');
  assert.ok(html.includes('run.verdict'), 'fallback UI must use daemon verdict');
});

test('UI22: no agent credential is stored by the frontend', async () => {
  const frontend = path.join(ROOT, 'src', 'ui-frontend', 'src');
  const files = await walk(frontend, ['.ts', '.tsx', '.html']);
  const banned = /ANTHROPIC_API_KEY|OPENAI_API_KEY|API_KEY\s*=|localStorage\.setItem\([^)]*(key|token|credential)/i;
  for (const f of files) {
    const content = await readFile(f, 'utf8');
    assert.ok(!banned.test(content), `credential storage pattern in ${path.relative(ROOT, f)}`);
  }
});

test('UI: Space UI component system is installed through the supported path (registry vendored + Base UI present)', async () => {
  // Vendored Space UI sources exist (shadcn-registry format) and Base UI peer resolves.
  const uiDir = path.join(ROOT, 'src', 'ui-frontend', 'src', 'components', 'ui');
  const comps = await readdir(uiDir);
  for (const required of ['button.tsx', 'card.tsx', 'dialog.tsx', 'drawer.tsx', 'tabs.tsx', 'progress.tsx', 'badge.tsx']) {
    assert.ok(comps.includes(required), `Space UI primitive missing: ${required}`);
  }
  const uiPkg = JSON.parse(await readFile(path.join(ROOT, 'src', 'ui-frontend', 'package.json'), 'utf8')) as {
    dependencies: Record<string, string>;
  };
  assert.ok('@base-ui/react' in uiPkg.dependencies, 'Space UI Base UI peer must be a frontend dependency');
  await access(path.join(ROOT, 'src', 'ui-frontend', 'node_modules', '@base-ui', 'react'));
});
