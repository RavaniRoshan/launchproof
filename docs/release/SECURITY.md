# LaunchProof security model

LaunchProof is privileged software: it reads untrusted repositories, spawns
untrusted applications, and orchestrates third-party agents. The design
treats all three as hostile.

## Threats addressed

| Threat | Mitigation (where in code) |
|---|---|
| Malicious repo content / prompt injection in source | Checks treat file text as data; `redactLine`/`scrubValue` before display/persist; agent verifier gets excerpts, not full history (`src/checks/shared.ts`, `src/evidence/scrub.ts`, `src/agents/gateway.ts`) |
| Malicious dependencies / install scripts | No `npm install` during verification; runtime lab spawns `node server.js` (or declared start) directly; dependency checks are static lockfile/manifest reads (`src/runtime/lab.ts`, `src/checks/payments-deps.ts`) |
| Malicious runtime app behavior | Spawn with cwd=root, `PORT` override, captured logs (500-line cap), readiness timeout, SIGTERM→SIGKILL teardown; max 1 run + 1 browser (RAM policy); no HOME/SSH/cloud-env passthrough beyond the ambient process env (`src/runtime/lab.ts`) |
| Credential leakage into artifacts | `scrubText`/`scrubValue` on every ledger write; `containsRawSecret` redaction fallback; secret-pattern tests; `launchproof.yaml` probes are user-edited test creds only (`src/evidence/ledger.ts`, `src/evidence/scrub.ts`) |
| Agent tool misuse | Adapters spawn allow-listed CLIs with instruction-on-stdin; `requestApproval` defaults to deny in headless mode; fix loop needs explicit `--approve`; verifier context is fresh and minimal (`src/agents/adapters.ts`, `src/agents/fixloop.ts`) |
| Unexpected network access | Daemon binds 127.0.0.1 only; agents declared `networkAccess: false`; runtime probes hit `probes.baseUrl` (local) only; no cloud upload anywhere (`src/daemon/server.ts`) |
| Verification-result tampering | Atomic JSON writes; append-only evidence JSONL with sha256 per record; orphaned runs marked recovered ERROR, never PASS (`src/storage/paths.ts`, `src/evidence/ledger.ts`) |

## What the sandbox is NOT

- Not a container boundary: the runtime app runs as the local user. Do not
  verify repos you would not otherwise execute. Docker isolation is **not**
  required for V1 but is recommended hardening for hostile code.
- Not a secrets vault: OS-native credential storage is **not** implemented;
  agent credentials live in ambient env (`LAUNCHPROOF_*_BIN` overrides only).
  Never put production secrets in `launchproof.yaml` or probes.
- Not a production tester: probes target local URLs only. Pointing
  `probes.baseUrl` at production is user error; the tool never does it.

## Defaults that protect the user

- UI has no verification logic and no direct fs/process access (daemon API).
- Fix loop defaults to deny; dry-run available; agent output never evidence.
- `SKIPPED`/`UNVERIFIED`/`ERROR` never render or count as PASS.
- History skips orphaned run dirs instead of guessing.
- Reports disclaim: READY ≠ secure; coverage = executed checks only.
