#!/usr/bin/env bash
# LaunchProof external repository study (P12).
# Clones target repos into study/work (gitignored), runs the verification
# engine headlessly, and records reproducible artifacts + comparison metrics.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="docs/study/results.json"
WORK="study/work"
mkdir -p "$WORK" docs/study

# Default corpus: the two in-repo fixtures (always available, reproducible).
# Override with: ./scripts/study.sh <repo-url-1> [repo-url-2 ...]
TARGETS=("$@")
if [[ ${#TARGETS[@]} -eq 0 ]]; then
  TARGETS=("fixtures/vulnerable-app" "fixtures/secure-app")
fi

echo "==> typecheck"
npx tsc --noEmit -p tsconfig.json

run_one() {
  local target="$1"
  local name
  name="$(basename "$target")"
  local src="$target"
  if [[ "$target" =~ ^https?:// ]]; then
    local dest="$WORK/$name"
    rm -rf "$dest"
    git clone --depth 1 "$target" "$dest" >/dev/null 2>&1 || { echo "clone failed: $target" >&2; return 0; }
    src="$dest"
  fi
  local start end ms code verdict
  start="$(date +%s%N)"
  set +e
  node bin/launchproof.js verify "$src" --json >"$WORK/$name.report.json" 2>"$WORK/$name.err"
  code=$?
  set -e
  end="$(date +%s%N)"
  ms=$(( (end - start) / 1000000 ))
  verdict="$(node -e "try{console.log(require('./$WORK/$name.report.json').verdict)}catch{console.log('ERROR')}" 2>/dev/null || echo ERROR)"
  # Existing-tool overlap: gitleaks if present, else recorded as unavailable.
  local overlap="gitleaks-unavailable"
  if command -v gitleaks >/dev/null 2>&1; then
    if gitleaks detect --source "$src" --no-git -v >/dev/null 2>&1; then overlap="gitleaks-clean";
    else overlap="gitleaks-flagged"; fi
  fi
  node -e "
    const fs = require('fs');
    const r = JSON.parse(fs.readFileSync('$WORK/$name.report.json', 'utf8'));
    const byDomain = {};
    let block = 0, critical = 0, warn = 0, unverified = 0;
    for (const item of r.results || []) {
      const d = item.checkId.split('-')[0];
      byDomain[d] = byDomain[d] || { pass: 0, block: 0, warn: 0 };
      if (item.status === 'BLOCK') { block++; critical += item.severity === 'critical' ? 1 : 0; byDomain[d].block++; }
      else if (item.status === 'WARN') { warn++; byDomain[d].warn++; }
      else if (item.status === 'PASS') byDomain[d].pass++;
      else if (item.status === 'UNVERIFIED') unverified++;
    }
    console.log(JSON.stringify({ repo: '$name', source: '$target', verdict: '$verdict', exit: $code, runtimeMs: $ms, checks: (r.results || []).length, blockers: block, critical, warnings: warn, unverified, byDomain, overlap: '$overlap' }));
  "
}

echo "==> study: ${TARGETS[*]}"
RESULTS=""
for t in "${TARGETS[@]}"; do
  LINE="$(run_one "$t")"
  echo "$LINE"
  RESULTS="$RESULTS$LINE"$'\n'
done

node -e "
  const fs = require('fs');
  const lines = \`$RESULTS\`.trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
  const repos = lines.length;
  const failing = lines.filter((l) => l.verdict === 'BLOCKED').length;
  const study = {
    generatedAt: new Date().toISOString(),
    hypothesis: 'Agent-built applications frequently satisfy builder tests while failing independent launch-readiness checks',
    repositories: repos,
    failing,
    blockerRate: repos ? failing / repos : 0,
    totalBlockers: lines.reduce((a, l) => a + l.blockers, 0),
    totalCritical: lines.reduce((a, l) => a + l.critical, 0),
    totalRuntimeMs: lines.reduce((a, l) => a + l.runtimeMs, 0),
    results: lines,
    limits: 'Observed facts only: verdicts, counts, runtimes. False-positive and unique-finding rates need manual review per repo (see docs/study/METHOD.md).',
  };
  fs.writeFileSync('$OUT', JSON.stringify(study, null, 2));
  console.log(\`study: \${repos} repos, \${failing} failing (\${(study.blockerRate * 100).toFixed(1)}%), \${study.totalBlockers} blockers, \${study.totalCritical} critical -> $OUT\`);
"
