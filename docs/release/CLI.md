# LaunchProof CLI contract

Exit codes: `0` READY · `1` BLOCKED · `2` usage or runtime error.
`--json` on `verify/report/history` prints machine-readable output.
`--daemon` forces daemon mode; `--local` forces in-process engine.
Default `verify` tries the daemon and falls back to local with a warning.

## init [path]

Scaffolds `launchproof.yaml` (inferred contract) + `.launchproof/probes.json`
template without overwriting existing files. Registers the project locally.

## detect [path] [--json]

Prints framework/languages/database/auth/payments/deployment/CI,
risk surfaces, and CHANGE ANALYSIS (changed files → activated surfaces →
additional verification enabled). `--json` adds detector hits.

## verify <path> [--profile N] [--strict] [--json] [--only ID,ID]

Runs the engine. Profiles: `quick|launch|security|agent-change|stack|custom`
(default `launch`). `--strict` promotes UNVERIFIED/ERROR to blocking.
`--only` runs a comma-separated subset (reproduction path for every check).

Progress lines: `<STATUS> <CHECK-ID>  <detail>`, then
`verdict … · N pass · N block · …` and the report path.

## report [--run <id>] [--json]

Prints the latest (or given) run: verdict, summary, per-check
ID/status/severity. Unknown run → exit 2.

## history [--json]

Lists registered projects (with last run) and recent runs with verdicts.
Orphaned run dirs without reports are skipped, never shown as passes.

## explain <CHECK-ID>

Prints invariant, summary, remediation, profiles, surfaces, prerequisites,
agent-fixability, and the reproduce command. Unknown ID → exit 2.

## fix <CHECK-ID> --path <dir> --run <id> [--agent codex|claude|script] [--approve] [--dry-run]

Generates a scoped fix instruction from a BLOCK/WARN result and prints it.
Without `--approve` nothing is invoked (exit 0). With `--approve` the agent
adapter runs; `--dry-run` approves without invoking. Non-BLOCK/WARN,
unknown check, or unknown run → exit 2. After any change:

```bash
launchproof verify <path> --only <CHECK-ID>
```

Agent output is never evidence.

## doctor

Prints node/typescript/daemon/playwright/chromium/agent/git availability.
Agent lines include capability gaps when binaries are missing.
Always exits 0 unless the command itself crashes.

## desktop [--port N] / daemon [--port N]

`daemon` starts the JSON API + SSE + control-plane server on 127.0.0.1 and
writes the port file. `desktop` starts it and opens the control plane in a
browser. Both run until Ctrl+C.
