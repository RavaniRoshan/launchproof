#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> typecheck"
npx tsc --noEmit -p tsconfig.json

echo "==> tests"
node --test --test-concurrency=2 "test/**/*.test.ts"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "==> CLI smoke: vulnerable fixture (expect exit 1 / BLOCKED)"
set +e
node bin/launchproof.js verify fixtures/vulnerable-app --json >"$work/vulnerable.json" 2>"$work/vulnerable.err"
vuln_code=$?
set -e
if [[ "$vuln_code" -ne 1 ]]; then
  echo "expected exit 1 for BLOCKED run, got ${vuln_code}" >&2
  cat "$work/vulnerable.err" >&2 || true
  exit 1
fi

echo "==> CLI smoke: secure fixture (expect exit 0 / READY)"
set +e
node bin/launchproof.js verify fixtures/secure-app --json >"$work/secure.json" 2>"$work/secure.err"
secure_code=$?
set -e
if [[ "$secure_code" -ne 0 ]]; then
  echo "expected exit 0 for READY run, got ${secure_code}" >&2
  cat "$work/secure.err" >&2 || true
  exit 1
fi

grep -Eq '"verdict": *"BLOCKED"' "$work/vulnerable.json"
grep -Eq '"verdict": *"READY"' "$work/secure.json"

echo "E2E PASS"
