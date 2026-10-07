import type { AppServices } from '../App'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Progress } from '../components/ui/progress'
import { StatusBadge, SeverityBadge } from '../status'

const PHASE_LABELS: Record<string, string> = {
  discover: 'Discovery',
  understand: 'Static analysis',
  static: 'Static checks',
  build: 'Build verification',
  runtime: 'Runtime',
  browser: 'Browser',
  database: 'Database',
  api: 'API',
  adversarial: 'Adversarial',
  deployment: 'Deployment',
  regression: 'Regression',
  decision: 'Final verdict',
  report: 'Report',
}

const GLYPH: Record<string, string> = { done: '✓', running: '●', pending: '○', skipped: '→', error: '⊗' }

// Verification timeline: every state from daemon phase records + live events.
export function Verification({ s }: { s: AppServices }) {
  const run = s.report?.run
  const results = s.report?.results ?? []
  const phases = run?.phases ?? []
  const done = phases.filter((p) => p.status === 'done').length
  const pct = phases.length > 0 ? Math.round((done / phases.length) * 100) : 0
  const change = run?.changeAnalysis

  return (
    <div className="grid gap-6 lg:grid-cols-3">
      <Card className="lg:col-span-2">
        <CardHeader>
          <CardTitle>Verification timeline</CardTitle>
          <CardDescription>
            {run ? `run ${run.id} · ${run.status}${run.profile ? ` · ${run.profile}` : ''}` : 'no run selected'}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="flex items-center gap-3">
            <Progress value={pct} aria-label={`verification ${pct}% complete`} className="flex-1" />
            <span className="text-sm tabular-nums text-muted-foreground">{pct}%</span>
            {run?.status === 'running' && (
              <Button variant="outline" size="sm" onClick={() => void s.cancelRun()}>Cancel run</Button>
            )}
          </div>

          <ol className="flex flex-col gap-1" aria-label="Verification phases">
            {(phases.length > 0
              ? phases
              : ['discover', 'understand', 'static', 'build', 'runtime', 'browser', 'database', 'adversarial', 'deployment', 'decision'].map(
                  (id) => ({ id, status: 'pending' as const }),
                )
            ).map((p) => (
              <li key={p.id} className="flex items-center gap-3 rounded-lg px-3 py-1.5 hover:bg-accent" data-phase={p.id}>
                <span
                  aria-hidden
                  className={`w-4 text-center ${
                    p.status === 'done' ? 'text-emerald-500' : p.status === 'running' ? 'text-amber-500' : p.status === 'error' ? 'text-red-500' : 'text-muted-foreground'
                  }`}
                >
                  {GLYPH[p.status] ?? '○'}
                </span>
                <span className="text-sm">{PHASE_LABELS[p.id] ?? p.id}</span>
                <span className="ml-auto text-xs uppercase text-muted-foreground" aria-label={`phase ${p.status}`}>
                  {p.status}
                </span>
              </li>
            ))}
          </ol>

          {run?.recovered && (
            <p className="rounded-lg border border-amber-500/50 px-3 py-2 text-sm text-amber-600 dark:text-amber-400">
              This run was recovered after a daemon restart and is marked ERROR — not a pass.
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Change analysis</CardTitle>
          <CardDescription>why extra verification was activated</CardDescription>
        </CardHeader>
        <CardContent>
          {!change?.available ? (
            <p className="text-sm text-muted-foreground">{change?.reason ?? 'no change analysis for this run'}</p>
          ) : (
            <div className="flex flex-col gap-2 text-sm">
              {change.activatedSurfaces.length === 0 && <p className="text-muted-foreground">no security-sensitive changes detected</p>}
              {change.activatedSurfaces.map((surf) => (
                <div key={surf} className="rounded-lg border border-border px-3 py-2">
                  <div className="font-medium">✓ {surf}</div>
                  <div className="text-xs text-muted-foreground">{change.activatedReasons[surf]}</div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Card className="lg:col-span-3">
        <CardHeader>
          <CardTitle>Live results</CardTitle>
          <CardDescription>each row opens directly into its evidence</CardDescription>
        </CardHeader>
        <CardContent>
          {results.length === 0 ? (
            <p className="text-sm text-muted-foreground">no checks finished yet</p>
          ) : (
            <div className="flex flex-wrap gap-2">
              {results.map((r) => (
                <button
                  key={r.checkId}
                  onClick={() => void s.openEvidence(r)}
                  className="flex items-center gap-2 rounded-lg border border-border px-3 py-1.5 text-left hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring"
                >
                  <StatusBadge status={r.status} />
                  <span className="font-mono text-xs">{r.checkId}</span>
                  <SeverityBadge severity={r.severity} />
                  <span className="max-w-72 truncate text-xs text-muted-foreground">{r.title}</span>
                </button>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
