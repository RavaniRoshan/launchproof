# LaunchProof — build progress

## P0 PLAN (done)

- Implemented: yes · Tested: n/a (read-only) · Evidence: `docs/product/DESIGN.md`
- Audited empty repo; chose Node 24 + native-TS daemon, framework-free control
  plane served by the daemon, Tauri release shell deferred (no webkit2gtk).
- Owner defaults recorded in DESIGN §14; no blocking questions asked.

## P1 FOUNDATION (done)

- Daemon (`src/daemon/server.ts` + `store.ts` + `main.ts`): JSON API + SSE on
  127.0.0.1, project registry, run lifecycle, cancellation, crash recovery
  (orphaned `running` → recovered `ERROR`), health endpoint, max 1 concurrent
  run, control-plane static serving.
- Verified: `test/daemon.test.ts` — health/checks/projects/verify/quick-READY,
  429 on second concurrent run, cancel-404, orphan recovery.
- CLI connects to daemon with local-engine fallback (`--local`/`--daemon`).

## P2 DISCOVERY (done, pre-existing + surfaced)

- `src/discovery/detect.ts` (22 framework/db/auth/payment/deploy/CI rules,
  detected/probable/unknown), `changed.ts` (git worktree diff → surfaces →
  risk-adaptive selection), `src/contract/infer.ts` (infer/validate/save).
- Verified: `launchproof detect` prints stack + CHANGE ANALYSIS; engine
  selection test covers profile/contract/change routing.

## P3 VERIFICATION ENGINE (done, pre-existing)

- 33 checks with stable IDs; registry/contract/result/evidence invariants
  enforced in code (`validateResult`: BLOCK/WARN need evidence, agent claims
  can never PASS, agentic needs label).
- Verified: `test/checks.test.ts` (inventory + contracts), `test/result.test.ts`
  (16 invariant tests), `test/engine.test.ts` (fixture matrix incl. strict).

## P4 RUNTIME LAB (done, pre-existing)

- `src/runtime/lab.ts`: probe-driven spawn, readiness wait, log capture,
  SIGTERM→SIGKILL teardown, startup-failure path leaves runtime unavailable.
- Verified: `test/runtime.test.ts` live runs (vulnerable BLOCK / secure READY).

## P5 BROWSER VERIFIER (done, pre-existing)

- `src/browser/playwright.ts` + BROWSER-101/102/103: login/protected/cross-user
  flows with screenshots + replayable evidence; graceful UNVERIFIED when
  Chromium/probes missing.
- Verified: live fixture runs; `doctor` reports chromium launch OK here.

## P6 DATABASE + API VERIFIER (done, pre-existing)

- DB-003/004/005 (RLS coverage, service-role boundary, permissive/destructive
  migrations) + API-104/105 + PAY-106 dynamic probes.
- Verified: vulnerable fixture BLOCKs on DB-003/004, API-104, PAY-106.

## P7 AGENT INTEGRATION (done)

- `src/agents/gateway.ts` (normalized interface) + `adapters.ts`
  (Codex/Claude/script process adapters, capability-gap honesty).
- Verified: gateway test asserts gaps recorded when unavailable; `doctor`
  lists all three adapters. codex+claude binaries exist on this host and
  report available; engine never depends on them.

## P8 ADVERSARIAL VERIFICATION (done, pre-existing + planner)

- `src/adversarial/planner.ts` hypothesis builder + ADV-001 executor
  (idor/anon_admin/logout_reuse/unsigned_webhook/amount_tamper/malformed_input
  with refuted/succeeded/not-attempted taxonomy, Observed-only PASS).
- Verified: vulnerable ADV-001 BLOCKs (attack-succeeded), secure refutes.

## P9 DESKTOP APPLICATION (done)

- `src/ui/index.html` served by the daemon: Projects/Verification/Findings/
  Evidence/Agents/History/Settings, SSE progress, verdict badge, one-click
  evidence per blocker, fix-instruction generator. Zero verification logic.
- Verified: manual via `launchproof desktop`; UI serves 200 with all tabs.
- Not verified: Tauri packaging (deferred P13, webkit2gtk absent).

## P10 FIX LOOP (done)

- `src/agents/fixloop.ts` + `launchproof fix` (scoped instruction, approval
  gate, dry-run, capability-failure fallback, mandatory re-verify note).
- Verified: fixloop tests (reject w/o approval, dry-run no-op); CLI fix
  without approval prints instruction + re-verify command.

## P11 CI / GITHUB (done)

- `.github/workflows/launchproof.yml` (gates on both fixtures) +
  `.github/actions/launchproof/action.yml` (BLOCK→error+fail, WARN→warning).
- Verified: workflow file present; headless `verify --json` exit codes 1/0
  proven in e2e. Not verified: live GitHub Actions run (owner-side).

## P12 VALIDATION (done, harness + first measurement)

- `scripts/study.sh` + `docs/study/METHOD.md`: reproducible corpus runner,
  per-repo verdict/counts/runtime/overlap → `docs/study/results.json`.
- Measured (this host): run `bash scripts/study.sh` — fixtures only until the
  owner adds public repos; false-positive/unique rates need manual review.

## P13 RELEASE (done — gated on owner for public release)

- `docs/release/PACKAGING.md` (per-OS plan, Tauri blocked on webkit2gtk, signing
  needs owner certs), `CLI.md` (full command contract), `SECURITY.md` (threat
  mitigations + sandbox limits). README quickstart + limits current.
- Verified: all CLI `--help` paths return 0 (regression test); orphaned run
  dirs skipped in history, never PASS.
- Remaining owner gates: name, platform priority, Tauri build host, license
  confirmation, study corpus, public-release sign-off.

## Checklist X1–X42

X1 daemon/UI documented interface — yes (`/api/*`, SSE). X2 CLI w/o UI —
yes (`--local` + daemon fallback). X3 cancel — yes (AbortController +
`/cancel`). X4 crash recovery — yes (orphan→ERROR test). X5 stable IDs —
yes (33, registry test). X6 BLOCK evidence — yes (validator + tests). X7
statuses distinct — yes (16 result tests). X8–X11 discovery — yes (detect +
change tests). X12 determinism — yes (fixture matrix). X13 scrubbing — yes
(ledger + scrub tests). X14–X16 prerequisites/deps/independence — yes
(engine tests). X17–X20 runtime/browser/IDOR — yes (live runs). X21–X24
agent separation/labels — yes (gateway + ADV tests). X25–X28 adapters — yes
(doctor + gateway tests; creds never written to projects). X29–X32 fix loop —
yes (approval + re-verify tests). X33–X36 desktop/history — yes (UI serves,
runs persist; restart-survival via files). X37–X39 CI — yes (workflow +
action; WARN never fails). X40–X42 study — harness done, first measurement
pending owner corpus (fixtures only).
