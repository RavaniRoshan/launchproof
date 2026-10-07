# LaunchProof release preparation (P13)

**Release readiness: NOT READY for public release — owner approval required.**
This document records exactly what is shippable, what is deferred, and what
the owner must decide.

## Shippable now (verified this host)

| Artifact | How | Evidence |
|---|---|---|
| CLI (`launchproof`) | `bin/launchproof.js` on Node ≥24 | `bash scripts/e2e.sh` → E2E PASS |
| Daemon | `npm run daemon` / `launchproof daemon` | health/checks/verify/SSE/cancel tested |
| Control plane UI | served by daemon at `/` | `src/ui/index.html`, manual via `launchproof desktop` |
| CI gate | `.github/workflows/launchproof.yml` | fixture-gated (BLOCK fails, READY passes) |
| Reusable action | `.github/actions/launchproof/action.yml` | BLOCK→`::error`+fail, WARN→`::warning` |
| Validation harness | `bash scripts/study.sh` | `docs/study/results.json` measured |

Install from source:

```bash
git clone <repo> && cd launchproof
npm install
npm run typecheck && npm test && bash scripts/e2e.sh
npm link   # or: node bin/launchproof.js <command>
```

## Per-OS packaging (deferred to owner environment)

- **Linux**: `npm pack` tarball + systemd unit for the daemon (port file at
  `~/.launchproof/daemon.json`). Verified path on this host.
- **macOS**: same tarball; launchd plist; `launchproof desktop` uses `open`.
  Not verified here (no macOS host).
- **Windows**: same tarball; `cmd /c start` opener in `desktop` command.
  Not verified here (no Windows host).
- **Desktop shell**: Tauri sidecar wrapping `http://127.0.0.1:<port>` per
  DESIGN §5. **Blocked**: no `webkit2gtk` on this host, so the shell was not
  built and is not claimed. The shell contract is fixed and the control plane
  is complete, so packaging is mechanical once webkit deps exist.
- **Signing**: no certificates configured. Owner must provide Apple Developer
  / Windows Authenticode / GPG identities before any public binary.

## Documentation set

- `README.md` — install, quickstart, architecture, limits
- `docs/product/DESIGN.md` — P0 design + threat model
- `docs/product/PROGRESS.md` — per-phase evidence log + X1–X42
- `docs/release/CLI.md` — full CLI contract
- `docs/release/SECURITY.md` — security model + sandbox limits
- `docs/release/PACKAGING.md` — this file
- `docs/study/METHOD.md` + `results.json` — validation evidence

## Transparent limitations (ship with every release)

1. READY is not a security guarantee; coverage = executed checks only.
2. `SKIPPED`/`UNVERIFIED`/`ERROR` are never passes.
3. Dynamic checks need a probe plan + startable app.
4. Browser checks need Playwright Chromium.
5. No production targets by default; no silent source edits.
6. Tauri shell, signed installers, hosted tier: not in this release.

## Owner decisions required before public release

1. Product name confirmation (LaunchProof is the working name).
2. Platform priority + signing identities.
3. Desktop shell go-ahead (Tauri build host with webkit2gtk).
4. License/distribution model (currently Apache-2.0, source install).
5. Public-repo study corpus approval (extend beyond fixtures).
6. Explicit public-release sign-off.
