# LaunchProof repository study — method

**Hypothesis:** agent-built applications frequently satisfy their builder's
tests while failing independent launch-readiness checks.

**Primary metric:** % of repositories that appear functional but fail ≥1
independent launch-blocker check.

## Corpus

Default (reproducible, in-repo): `fixtures/vulnerable-app`,
`fixtures/secure-app`. Extend with public agent-built repos:

```bash
bash scripts/study.sh https://github.com/<org>/<repo> [...]
```

## Recorded per repo

- verdict (READY/BLOCKED), exit code, runtime
- checks evaluated, blockers, critical findings, warnings, unverified
- findings by domain (check-ID prefix: SECRET/AUTH/DB/PAY/…)
- existing-tool overlap (`gitleaks` when installed, else `unavailable`)

## Observed vs hypothesized

`docs/study/results.json` holds **observed facts only**. These need manual
review and are NOT auto-claimed:

- false positives (requires reading each BLOCK)
- unique findings vs SAST/secret scanners
- missed issues (requires a reference audit)

## Reproduce

```bash
bash scripts/study.sh
cat docs/study/results.json
```
