# LaunchProof — independent launch-readiness verification for agent-built apps

> The agent that builds the app is never sufficient proof that it is ready to
> launch. LaunchProof produces **independent evidence** and answers one
> question: *is this application ready to launch under its launch contract?*
> A READY verdict is **not** a claim that the application is secure.

## Quick start

```bash
npm install
node bin/launchproof.js doctor
node bin/launchproof.js init ./your-app     # scaffold launchproof.yaml + probe template
node bin/launchproof.js detect ./your-app   # stack, surfaces, change analysis
node bin/launchproof.js verify ./your-app --local
node bin/launchproof.js verify ./your-app --local --strict
node bin/launchproof.js verify ./your-app --local --only AUTH-002,DB-003
```

Or via the daemon (desktop control plane + CLI share it):

```bash
node src/daemon/main.ts --port=4821 &
node bin/launchproof.js verify ./your-app            # uses daemon, falls back to local
node bin/launchproof.js desktop --port=4821          # open the control plane UI
node bin/launchproof.js report / history / explain AUTH-002
```

Try the fixtures:

```bash
node bin/launchproof.js verify fixtures/vulnerable-app --local   # expect BLOCKED, exit 1
node bin/launchproof.js verify fixtures/secure-app --local       # expect READY, exit 0
bash scripts/e2e.sh
bash scripts/study.sh
```

## Architecture (one engine, three consumers)

```
Desktop control plane (src/ui, served by daemon, zero verification logic)
CLI (src/cli) ──┐
CI action ──────┤── Local Verification Daemon (src/daemon: runs, SSE, recovery)
                │         ├── Verification Engine (src/engine + src/checks: 33 checks)
                │         ├── Agent Gateway (src/agents: codex/claude/script adapters)
                │         └── Evidence Store (~/.launchproof: runs/, evidence/, ledger)
                └── headless engine (CLI --local, CI)
```

## Check inventory (33)

Deterministic (22): REPO-001/002, SECRET-001/002, ENV-005, AUTH-002/003,
DB-003/004/005, PAY-004/005, DEP-006/007, CI-007/008/009, INFRA-001/002,
OBS-001, BROWSER-001, API-002.
Dynamic (10): AUTH-101/102/103, API-104/105, PAY-106, FLOW-109,
BROWSER-101/102/103. Agentic (1): ADV-001 (hypothesis sweep; labels
Observed/Derived/Hypothesized/Unable-to-verify; can never PASS on claims).

Statuses `PASS/BLOCK/WARN/SKIPPED/UNVERIFIED/ERROR` are distinct —
`SKIPPED/UNVERIFIED/ERROR` are never passes (`--strict` promotes the latter
two to blocking).

## Fix loop (opt-in, approval-gated)

```bash
node bin/launchproof.js fix AUTH-002 --path ./your-app --run <id> --agent codex
node bin/launchproof.js fix AUTH-002 --path ./your-app --run <id> --agent codex --approve --dry-run
# after any change, independently re-verify:
node bin/launchproof.js verify ./your-app --local --only AUTH-002
```

Source is never modified without `--approve`. Agent output is never evidence.

## CI

- Workflow: `.github/workflows/launchproof.yml` (typecheck, tests, both fixtures).
- Reusable action: `.github/actions/launchproof/` — BLOCK → `::error`
  annotation + failing job; WARN → `::warning` only (never fails).

## Security model (summary)

Repos and running apps are untrusted: prompt-injection scans treat code as
data, runtime lab spawns with scrubbed env + timeouts, evidence is scrubbed
before persistence, no production targets by default, max 1 concurrent run.
See `docs/product/DESIGN.md` §11.

## Limits

- No security guarantee; coverage = the executed checks only.
- Browser checks need Playwright Chromium (`doctor` tells you).
- Dynamic checks need a probe plan (`launchproof.yaml` probes or
  `.launchproof/probes.json`) + a startable app; otherwise UNVERIFIED.
- Tauri release shell is deferred to P13 (no webkit2gtk here) — the control
  plane contract (spawn daemon → open `http://127.0.0.1:<port>`) is fixed now.

## Docs

- `docs/product/DESIGN.md` — Phase 0 design
- `docs/product/PROGRESS.md` — per-phase evidence log
- `docs/study/METHOD.md` + `scripts/study.sh` — validation study
