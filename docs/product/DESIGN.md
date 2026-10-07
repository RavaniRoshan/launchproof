# LaunchProof — Phase 0 Design

**Status:** Draft for owner review (implementation proceeds under the standing instruction to deliver the full product; owner decisions below are resolved with recorded defaults and can be revisited).
**Date:** 2026-10-06
**Repository state at audit:** empty directory (greenfield). No existing code, no architecture constraints, no reusable modules.

---

## 1. Product thesis

AI coding agents can generate a working application quickly, but the same agent writes the app, runs its own tests, inspects its own work, and declares success. LaunchProof inserts an **independent verification layer** between "the agent says it works" and "the developer ships it."

The product answers one question:

> Is this application ready to launch under the verification contract defined for this project?

It never answers "is this application secure?" Passing checks means *the verified invariants held in the verified environment*, nothing more.

**Central invariant:** the builder agent is never sufficient proof. Every blocking result carries reproducible evidence produced by LaunchProof itself.

## 2. Target user

- Solo developers and small teams shipping agent-built web applications (indie SaaS, internal tools, side projects).
- Developers using Codex / Claude Code who want a second, independent opinion before deploy.
- CI owners who want a blocking pre-deploy gate with stable check IDs.

Not targeted in V1: enterprise security teams, SOC2 programs, dedicated pentest buyers.

## 3. Product boundary

**In scope (V1):** local launch-readiness verification — repository integrity, secrets, dependency policy, authN/authZ static + dynamic checks, database isolation (RLS) analysis, API behavior, payment webhook behavior, CI/CD hygiene, infrastructure config, reliability/observability spot checks, browser flows, opt-in agentic investigation, fix-and-reverify loop, local history/evidence, CLI + headless CI.

**Out of scope (non-goals for V1):** enterprise SIEM, general-purpose pentest platform, full SAST replacement, CSPM, vulnerability database, generic AI assistant, autonomous deployment, any absolute security guarantee, hosted multi-tenant service.

**Explicit limits (enforced in code and docs):**
- No claim of security or complete coverage from a green run.
- `SKIPPED`, `UNVERIFIED`, `ERROR` are never rendered or counted as `PASS`.
- No silent source modification, no production interaction by default, no upload of source to cloud services.
- No dozens of low-confidence checks to inflate counts.

## 4. Architecture

```text
Desktop control plane (web UI, shell wrapper)
        │  HTTP + SSE (127.0.0.1)
CLI ─────┤
CI  ─────┘ (headless: in-process engine or daemon)
        │
  Local Verification Daemon  ← owns execution state
        │
   ┌────┴──────────────┬───────────────────┐
   │                   │                   │
Verification Engine   Agent Gateway     Evidence Store
   │                   │                   │
   ├ discovery         ├ codex adapter     ├ runs/
   ├ static checks     ├ claude adapter    ├ evidence/
   ├ runtime lab       ├ script adapter    ├ projects/
   ├ browser verifier  └ (future)          ├ policies/
   ├ db/api verifier                        ├ logs/
   ├ adversarial planner                   └ cache/
   └ decision engine
```

Component responsibilities and hard boundaries:

| Component | Owns | Must not own |
|---|---|---|
| Desktop UI | rendering, navigation, approval clicks | any verification logic, any run state |
| CLI | argument parsing, output formatting, exit codes | verification logic (calls engine/daemon) |
| Daemon | run lifecycle, process spawn, cancellation, recovery, persistence | check implementations |
| Verification Engine | check registry, execution, statuses, decision | agent protocols, UI state |
| Agent Gateway | agent process lifecycle, capability discovery, streaming, approvals | check results, evidence interpretation |
| Evidence Store | ledger, scrubbing, artifact persistence | verdicts |

**Rule:** one verification engine, three consumers (desktop, CLI, CI). No duplicated business logic. No agent internals leak into the engine — the gateway exposes `connect / discover / start / send / stream / interrupt / approve / collect / close` only.

## 5. Desktop strategy

Evaluated: **Tauri**, **Electron**, **native shells**, **local web control plane**.

| Criterion | Tauri | Electron | Native shell | Web control plane |
|---|---|---|---|---|
| Filesystem/child-process access | via Rust sidecar | excellent | per-platform cost | via daemon API only |
| Daemon integration | sidecar process | child process | bespoke | daemon is the app |
| Installer size | ~5–15 MB | ~150–200 MB | varies | 0 |
| Memory use | low (webview) | high (200–500 MB) | lowest | browser only |
| Win/mac/Linux | yes (needs webkit deps) | yes | 3× work | yes |
| Dev experience here | **blocked**: no `webkit2gtk`, no sudo | feasible but RAM-heavy | slow | fastest |

**Decision:** the control plane is a local web app served by the daemon (screens: Projects, Verification, Findings, Evidence, Agents, AI Workspace, Policies, History, Settings). `launchproof desktop` starts the daemon and opens the control plane in an app-mode Chromium window (fallback: default browser). The **release** desktop shell is Tauri (small, low memory, sidecar daemon) — the shell contract is fixed now: *spawn daemon → open `http://127.0.0.1:<port>` → no logic in the shell*. Tauri packaging is deferred to P13 where webkit2gtk exists; it cannot be honestly verified in this environment and is therefore not claimed as done.

Electron rejected: RAM cost (crash risk on 7.5 GB host), installer size, no capability gain over the shell contract.

### 5a. Frontend component system: Space UI

**What Space UI is (verified 2026-10-07 against spaceui.one/docs + /library):** an open-source (MIT) React component distribution in the shadcn registry format — copy-first source, not an npm runtime. Built on **Tailwind CSS + Motion + Base UI** headless primitives (61+ primitives: Accordion, Alert Dialog, Dialog, Drawer/Sheet, Tabs, Card, Table, Toast, Tooltip, etc.), 114+ interactive components, 17+ templates, 61+ hooks. Install: `shadcn add @spaceui/...` (Next.js and Vite+React guides both exist; components are plain React + Tailwind, usable outside Next.js). AI-friendly by design (llms.txt index, agent skills).

**Decision:** Space UI is the primary frontend component library. A thin LaunchProof design layer (tokens, status/severity semantics, product components) sits above it. This supersedes the earlier "framework-free" choice: the existing single-file `src/ui/index.html` becomes the fallback shell, and the P9 frontend is a React + Vite + Tailwind + Space UI (Base UI primitives) app served by the daemon at `/`.

**Why Vite + React, not Next.js:** Space UI targets Next.js but its components are plain React + Tailwind + Base UI and work under Vite (documented Vite+React install path). Next.js brings a Node server runtime and build weight that conflict with the RAM budget (7.5 GB host) and the rule "the shell must not dictate the verification-engine language". Vite emits a static bundle the daemon serves as files — zero frontend server, zero new network surface. **The daemon stays dependency-free of React/Next.js/Space UI** (see §5b).

### 5b. UI architecture (three layers — Space UI confined to the frontend)

```text
LaunchProof Desktop
  Desktop Shell (Tauri sidecar; app-mode Chromium in V1)
  Frontend UI  ← Space UI lives ONLY here
    - Space UI (vendored source via shadcn registry, MIT)
    - LaunchProof design tokens + status semantics
    - Product-specific components (wrappers, not forks)
    - Application state (daemon SSE events → structured store)
  Local Verification Daemon  ← NO Space UI dependency
    - Verification engine, Agent gateway, Runtime lab,
      Browser verifier, Evidence store, Policy engine
```

Hard rules: Space UI must NOT become a dependency of verification logic, policy evaluation, daemon execution, CLI, CI, evidence storage, the agent gateway, or security checks. A test proves engine/daemon/CLI/CI/policy work with Space UI removed (delete the frontend dir, run `npm test` + e2e — must stay green). No verification result is computed inside a UI component. No agent credential is stored by the frontend. Structured daemon SSE events remain structured in the UI — typed cards/timeline entries, never flattened into plain chat text.

### 5c. Priority surfaces (P9 build order)

1. **Dashboard** — five questions immediately: which project, READY/BLOCKED, what blocks it, what is running, what the verifier proved. Per-domain pass counts + recent findings, each opening into evidence. No decorative security scores.
2. **Verification timeline** — phases (Discovery, Static, Build, Runtime, Database, Browser, Adversarial, Deployment, Final verdict) with real daemon state; selecting a phase opens its checks + evidence.
3. **Findings** — structured cards: stable ID, severity, status, surface, class, evidence (request/response, identity, expected vs observed), actions (View Request, View Response, Replay Test), remediation, fix actions (Fix with Codex / Claude Code / Mark Accepted Risk).
4. **Evidence viewer** — request/response, terminal output, screenshots, traces, DB queries/results, source locations, diffs, logs, config, agent messages, verification metadata. Progressive disclosure: conclusion first, expand into proof.
5. **Agent activity** — distinct states: Thinking, Tool execution, File inspection, Terminal command, Browser test, Database test, Finding discovered, Evidence collected, Approval required, Agent waiting, Agent completed, Verification blocked. Motion communicates state, never decorates.
6. **AI workspace** — agent rail (Verification Agent, Codex, Claude Code, live status) beside a chat pane rendering structured events (user message, agent response, tool execution, verification event, finding, evidence, approval request, file reference, command result, verification status, agent handoff). An engineering control surface, not a generic chatbot; source of truth stays the structured verification state + evidence store.
7. **Fix-and-reverify** — scoped instruction preview → explicit approval → agent run → independent re-run → regression → updated verdict, all visible.
8. **Approval flows** — structured Approve/Reject exposing action, reason, scope, risk. Never hidden inside a generic chat response.

### 5d. Design system, accessibility, motion, responsive

- Thin LaunchProof layer above Space UI: colors, typography, spacing, radii, elevation, motion, icons, panels/cards/code/evidence views. Statuses `PASS/BLOCK/WARN/UNVERIFIED/SKIPPED/ERROR` have one consistent visual meaning everywhere; critical findings distinguishable from warnings without relying on color alone.
- Space UI is not automatically sufficient for a11y: verify keyboard navigation, focus management (dialogs/drawers), screen-reader labeling, contrast, error announcement, reduced-motion behavior for every critical workflow. Custom wrappers must preserve Base UI accessibility behavior.
- Motion for progress/activity/transitions; none on critical evidence, error identification, verdicts, or dense code. Everything understandable with `prefers-reduced-motion`.
- Desktop-first (large displays), responsive down to laptop/split-screen with collapsed evidence panels. Not a mobile web UI.

### 5e. Frontend implementation rule + UI decisions log

Before creating a UI component: (1) search Space UI; (2) check existing primitive/component/block/hook/template; (3) reuse; (4) wrap for LaunchProof behavior; (5) custom only when none fits — allowed only if Space UI cannot satisfy the behavior, a11y/security demands it, or the dependency would be architecturally wrong. Every meaningful exception is recorded in `docs/product/UI_DECISIONS.md` (component, alternative considered, reason, a11y notes, maintenance cost).

## 6. Daemon strategy

- Node.js (v24, native TypeScript execution) single process, `node:http`, JSON API + SSE event stream, bound to `127.0.0.1` only (random port, port file in `~/.launchproof/daemon.json`).
- Owns: project registry, run lifecycle, process execution (runtime lab, agents), cancellation (cooperative + kill escalation), crash recovery (orphaned runs marked `ERROR` with `recovered: true` on boot), evidence persistence, log capture.
- Individually testable: `pnpm daemon` with no UI attached; every CLI feature works against it headlessly.
- **RAM policy (host has 7.5 GB total):** max 1 concurrent verification run per daemon, max 1 browser instance, runtime lab child processes get `--max-old-space-size=256`, all spawns have hard timeouts, tests run with `--test-concurrency=2`. No Electron, no dev-server + browser simultaneously unless required.

## 7. Verification model

Three classes, all behind the same result schema:

- **Class A — deterministic** (no LLM): file/source/config analysis, dependency inspection, migration SQL parsing, workflow policy, bundle scanning. Majority of V1 checks.
- **Class B — dynamic**: runtime lab boots the app; probes exercise authN/authZ/API/webhooks; browser drives real flows. Full request/response/identity/environment/timestamp evidence, replayable.
- **Class C — agentic**: fresh-context verifier generates hypotheses and investigates. Output labels: `Observed | Derived | Hypothesized | Unable to verify`. **An agent conclusion can never set a result to PASS without evidence attached** (enforced by the decision engine: `confidence: agent_claim` results are capped at `UNVERIFIED`/`WARN` unless an evidence record from a non-agent category exists).

### Status model

`PASS | BLOCK | WARN | SKIPPED | UNVERIFIED | ERROR` — first-class, never collapsed. Verdict: `READY` (no BLOCK; WARN allowed) or `BLOCKED` (≥1 BLOCK). Policy flag `--strict` promotes `UNVERIFIED`/`ERROR` to blocking.

### Evidence model

Ledger entry: `id (E-nnnn)`, category (`SOURCE|BUILD|STATIC_ANALYSIS|RUNTIME|BROWSER|DATABASE|NETWORK|DEPLOYMENT|AGENT|USER_CONFIRMATION`), payload, checksum, timestamps, replay command. Secret scrubbing (pattern + known-secret registry) runs **before persistence**.

### Lifecycle phases

`Discover → Understand → Static → Build → Runtime → Browser → Database → API → Adversarial → Deployment → Regression → Decision → Report`. A failed phase does not abort the run; dependent checks become `SKIPPED` with the failed prerequisite recorded.

### Risk-adaptive selection

Changed-surface analysis maps diffs to domains (auth → authN+authZ+browser, migrations → db, stripe → payments+webhooks, `.github/workflows` → CI, deploy config → infra) and records *why* each extra domain was enabled. Visible in the UI and in the run report.

## 8. Launch contract

`launchproof.yaml` (or inferred → `.launchproof/contract.yaml`): `project`, `stack`, `surfaces`, `required`, `risk`, plus optional `probes` (dynamic test identities/endpoints) and `policy` (blocking severities, disallowed deps, workflow permissions). Inference only states what repository evidence justifies; uncertain values are marked `confidence: probable` and require user confirmation. Contract never invents requirements.

## 9. Agent model

- **Builder agent**: the developer's own Codex/Claude Code session. Never trusted as proof.
- **Verifier agent**: runs in a **fresh context** (no builder transcript). Inputs: contract, change summary, scoped source, observed evidence, explicit objective. Config: model, max turns, token budget, allowed tools, network access, approval policy.
- **Gateway adapters:** `codex` (CLI), `claude` (Claude Code CLI), `script` (generic/fixture adapter for tests). Capability gaps are recorded (`unsupported`), never faked.
- **Fix loop (opt-in):** finding → scoped instruction (ID, evidence, invariant, surface, constraints, required re-verification) → user approval gate → agent edits → **LaunchProof independently re-runs the check** → regression profile → new verdict. "Fixed" claims are never evidence.

## 10. Security model (verifier is privileged software)

Threats: malicious repo content, malicious dependencies, prompt injection in source, malicious fixtures, runtime escape, credential leakage, agent tool misuse, unexpected network, result tampering.

Controls in V1:
- Repo content is untrusted input: checks never `eval` repo code; source is read as text; agent prompts embed repo content wrapped as data with an anti-injection preamble, and verifier output is schema-validated (no free-text → status).
- Runtime lab: child processes get a scrubbed environment (only allowlisted vars), cwd confined to project, `HOME` redirected to a run-scoped dir, network allowed only to localhost targets by default, hard timeouts, output caps, process-group kill. **Not a hard sandbox** — documented as a limitation (no namespaces/seccomp without Docker; Docker unavailable here). Full isolation documented as the Docker-backed lab (future, behind `--sandbox docker`).
- Credentials: never written to project files, never placed in evidence (scrubbed), never sent to agents; stored for reuse only in OS keychain when available, else `~/.launchproof/agents/` with `0600` (documented).
- Verifier agent: read-only tools by default, no network by default, approvals required for any write.
- No production endpoints: probes must target loopback or explicitly approved hosts; contract marks `environment: production` → dynamic checks refuse to run.

## 11. Storage model

```text
~/.launchproof/
  daemon.json          # pid, port, version
  projects/<id>.json   # registered projects + contract
  runs/<runId>/        # run.json, results.json, events.jsonl, logs/
  evidence/<runId>/    # E-nnnn artifacts (scrubbed)
  policies/            # custom profiles/contracts
  agents/              # agent config (0600)
  cache/               # discovery cache (content-hash keyed)
  logs/                # daemon logs
```

Local-only by default. Source code is never copied into storage (only paths, hashes, snippets ≤ 64 lines referenced by evidence, scrubbed).

## 12. First verification domains (V1)

Repository integrity, Secrets/credentials, Authentication, Authorization, Database, API, Payments, CI/CD, Infrastructure, Dependencies, Observability, Reliability (minimal), Browser, Adversarial (opt-in). Backups/recovery and full deployment verification are labeled `UNVERIFIED`-capable (no evidence source → explicit `UNVERIFIED`, never silent skip).

## 13. First supported stack

**Primary:** Next.js + Supabase + Stripe + Vercel (detectors also cover React/Vite/Nuxt/Node/Python/Prisma/Drizzle/Clerk/Auth.js/Firebase/Mongo/Postgres/Docker/GitHub Actions/Railway/Render/Cloudflare/AWS).
Detector states: `detected | probable | unknown`. Package presence alone never implies an integration is in use (e.g., `@supabase/supabase-js` in client code vs. server-only usage).

Dynamic/browser checks need a probe map; V1 sources it from (a) contract `probes`, (b) `.launchproof/probes.json`, (c) derived Next.js route paths. Without one → dynamic checks report `UNVERIFIED` with reason (never PASS).

## 14. Check inventory (V1 target: 22 deterministic + 7 dynamic + 3 browser)

Deterministic (Class A) — stable IDs, all with severity + prerequisites + evidence:

| ID | Title | Default |
|---|---|---|
| REPO-001 | Sensitive file tracked in repository | BLOCK |
| REPO-002 | Package lifecycle install scripts present | WARN |
| SECRET-001 | Server-only credential present in client-served files | BLOCK |
| SECRET-002 | Hardcoded credential in source | BLOCK |
| ENV-005 | Secret-looking value in public env configuration | BLOCK |
| AUTH-002 | Protected resource route lacks server-side authorization | BLOCK |
| AUTH-003 | Session cookie missing secure/HttpOnly/SameSite hardening | WARN |
| DB-003 | Exposed database table has RLS disabled | BLOCK |
| DB-004 | Privileged/service-role key referenced from client-accessible code | BLOCK |
| DB-005 | Overly permissive RLS policy (`USING (true)`) | WARN |
| PAY-004 | Payment webhook accepts payload without signature verification | BLOCK |
| PAY-005 | Client-controlled amount used in checkout/price creation | WARN |
| DEP-006 | Disallowed dependency version detected | BLOCK |
| DEP-007 | Dependencies declared without lockfile | WARN |
| CI-007 | Workflow permissions exceed policy | BLOCK |
| CI-008 | Untrusted context interpolated into shell `run:` | BLOCK |
| CI-009 | `pull_request_target` checks out PR-controlled code | BLOCK |
| INFRA-001 | Container runs as root (no `USER`) | WARN |
| INFRA-002 | Cloud credential in infrastructure config | BLOCK |
| OBS-001 | Sensitive value passed to logging | WARN |
| BROWSER-001 | Request-derived input reaches HTML injection sink | WARN |
| API-002 | Error response exposes internal detail (stack/SQL) | WARN |

Dynamic (Class B): `AUTH-101` cross-user record access, `AUTH-102` unauthenticated admin route, `AUTH-103` session invalidation after logout, `API-104` unauthenticated resource access, `API-105` invalid input handling, `PAY-106` webhook replay/unsigned acceptance, `FLOW-109` logout state transition.

Browser (Class B): `BROWSER-101` protected route reachable without auth, `BROWSER-102` cross-user resource visible in UI, `BROWSER-103` session persists after logout.

Agentic (Class C): `ADV-001` trust-boundary hypothesis sweep → produces `Observed/Derived/Hypothesized/Unable to verify` findings; successful attacks convertible to regression checks (P8).

Every check: stable ID, severity, prerequisites, affected surface, expected invariant, remediation text, `agent_fixable` flag, reproducible execution.

## 15. MVP scope (what ships)

1. `launchproof` CLI: `init detect verify report doctor explain fix history daemon desktop`.
2. Daemon: HTTP+SSE, runs, cancel, recovery, health, persistence.
3. Discovery + launch-contract inference/validation.
4. Engine: 22 deterministic checks, profiles (`quick|launch|security|agent-change|stack|custom`), risk-adaptive selection, decision engine, evidence ledger with scrubbing.
5. Runtime lab + browser verifier against local apps (fixture-proven: vulnerable vs fixed).
6. Database/API verifiers (static RLS analysis + dynamic probes).
7. Agent gateway: codex/claude/script adapters, fresh-context verifier, hypothesis labelling.
8. Fix loop with approval gate + independent re-run + regression.
9. Desktop control plane: React + Vite + Space UI frontend (dashboard, timeline, findings, evidence viewer, agent activity, AI workspace, fix-and-reverify, approvals) served as a static bundle by the daemon, with the single-file fallback shell retained; live SSE state, evidence one click from every blocker, `READY`/`BLOCKED` as the primary state; UI decisions logged in `UI_DECISIONS.md`; engine/daemon/CLI/CI proven independent of Space UI.
10. CI: headless engine, exit codes, GitHub annotations, composite action.
11. Validation study protocol + first measured run; README claims bounded by data.

## 16. Technical risks

| Risk | Mitigation |
|---|---|
| Static authz heuristics → false positives | narrow triggers (project has auth system + route has zero auth/401/403 tokens), severity review, study measures FP rate, `UNVERIFIED` when ambiguous |
| Dynamic checks need app-specific probes | contract/probes file; otherwise explicit `UNVERIFIED` (never PASS) |
| Agent CLIs change protocols | gateway capability discovery + `unsupported` recording; script adapter for tests |
| Runtime lab escape (no Docker) | scrubbed env, loopback-only, timeouts; limitation documented; Docker sandbox later |
| RAM pressure (7.5 GB) | serial runs, 1 browser, node heap caps, concurrency 2 in tests |
| Tauri unbuildable here | shell contract fixed; packaging deferred, not claimed done |
| Verifier prompt injection | repo text treated as data, schema-validated agent output, no status authority |
| Space UI leaks into backend | three-layer rule (§5b) + removal test (delete frontend dir, engine/daemon/CLI/CI must stay green); daemon serves static files only, never imports React |
| Space UI React/Tailwind weight vs RAM | Vite static bundle (no Next.js server); bundle budget ≤ 500 KB gzip initial; no dev-server + browser simultaneously in tests |
| Space UI ≠ automatic a11y | per-workflow keyboard/focus/contrast/reduced-motion verification (UI16–UI19); Base UI behavior preserved in wrappers |
| UI fabricates daemon state | all progress/findings/verdicts render from SSE + run records only; empty/loading states distinct from data; UI10/UI11 tests |

## 17. Validation plan

**Hypothesis:** agent-built apps frequently pass their own tests while failing independent launch-blocker checks.

- **Study protocol** (`docs/study/PROTOCOL.md`): corpus = small public repos using the primary stack with visible agent-tool usage or indie-SaaS shape; N ≥ 10 target; per repo record: repos evaluated, checks evaluated, blockers, critical findings, false positives (manual triage), runtime, overlap with baseline tools (grep-based secret scan baseline), unique findings, domain distribution.
- **Primary metric:** % of repos failing ≥ 1 independent launch blocker.
- **Fixture-based regression:** vulnerable vs fixed demo app — vulnerable must BLOCK with evidence, fixed must be READY (automated in `scripts/e2e.sh`).
- **Separation:** observed facts vs hypotheses labeled in artifacts; results stored under `study/results/` as reproducible JSON.

## 18. Open owner decisions (resolved defaults — confirm or override)

| # | Question | Default taken | Revisit cost |
|---|---|---|---|
| 1 | Working name | **LaunchProof** | rename, cosmetic |
| 2 | Platform priority | **cross-platform simultaneously** (pure TS, no platform code in V1) | low |
| 3 | Desktop framework | **Tauri shell for release; V1 frontend = React + Vite + Space UI static bundle served by the daemon** (Next.js rejected: server runtime + RAM weight; webkit2gtk missing here so packaging stays P13) | medium (P13) |
| 3b | Frontend component system (new mandate) | **Space UI primary library (MIT, shadcn-registry vendored source: Base UI + Tailwind + Motion); thin LaunchProof design layer above; custom components only per §5e, logged in UI_DECISIONS.md** | low |
| 4 | First stack | **Next.js + Supabase + Stripe first-class**, broader detectors included where cheap | low |
| 5 | First agent | **both** Codex and Claude Code adapters (both CLIs present on host) | low |
| 6 | External LLM for verifier | **opt-in only**; default = offline heuristic adversarial planner (no API key on host) | medium |
| 7 | Local-only hard requirement | **yes** — default operation never leaves the machine | — |
| 8 | Docker required for first release | **no** — native process lab; Docker sandbox is an optional later hardening | medium |
| 9 | Max local resource use | **≤ 1.5 GB RSS, ≤ 1 run, ≤ 1 browser, 120 s default phase timeout** (enforced via caps/timeouts) | low |
| 10 | Licensing/distribution | **open-source (Apache-2.0), no hosted tier in V1** | medium |

## 19. Definition of done (MVP)

Mapped from the product checklist X1–X42 plus Space UI checklist UI1–UI22; automated where marked `[T]`. Tracked per-phase in `docs/product/PROGRESS.md`.

Desktop/UI completion additionally requires: shell operational; Space UI integrated via the supported registry path; dashboard, AI workspace, structured-event chat, daemon-driven progress, evidence-linked findings, explicit approvals, fix-and-reverify representation, keyboard + reduced-motion verification, zero verification logic in the frontend, engine/daemon/CLI/CI/policy green with Space UI removed, and `UI_DECISIONS.md` current.
