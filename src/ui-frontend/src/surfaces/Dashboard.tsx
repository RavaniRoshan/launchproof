import { useState } from 'react'
import type { AppServices } from '../App'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Separator } from '../components/ui/separator'
import { StatusBadge, SeverityBadge, VerdictBadge } from '../status'

const PROFILES = ['quick', 'launch', 'security', 'agent-change', 'stack'] as const

// Dashboard answers five questions from daemon data only:
// which project, ready to ship?, what blocks it, what's running, what was proven.
export function Dashboard({ s, onNavigate }: { s: AppServices; onNavigate: (t: 'Dashboard' | 'Verification' | 'Findings' | 'Workspace' | 'History' | 'Settings') => void }) {
  const [path, setPath] = useState('')
  const [profile, setProfile] = useState<string>('launch')
  const [strict, setStrict] = useState(false)

  const results = s.report?.results ?? []
  const blockers = results.filter((r) => r.status === 'BLOCK')
  const warnings = results.filter((r) => r.status === 'WARN')
  const run = s.report?.run
  const summary = run?.summary

  const domains = new Map<string, { pass: number; block: number; warn: number; other: number }>()
  for (const r of results) {
    const d = (r.checkId.split('-')[0] ?? 'OTHER')
    const cur = domains.get(d) ?? { pass: 0, block: 0, warn: 0, other: 0 }
    if (r.status === 'PASS') cur.pass++
    else if (r.status === 'BLOCK') cur.block++
    else if (r.status === 'WARN') cur.warn++
    else cur.other++
    domains.set(d, cur)
  }

  return (
    <div className="grid gap-6 lg:grid-cols-3">
      <Card className="lg:col-span-2">
        <CardHeader>
          <CardTitle>Launch readiness</CardTitle>
          <CardDescription>
            {run ? `${run.projectPath} · profile ${run.profile} · run ${run.id}` : 'no run yet'}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="flex flex-wrap items-center gap-4">
            <VerdictBadge verdict={run?.verdict ?? s.report?.verdict} className="text-lg" />
            <div className="grid grid-cols-3 gap-2 text-sm sm:grid-cols-6">
              <Stat label="pass" value={summary?.pass ?? 0} />
              <Stat label="block" value={summary?.block ?? 0} danger />
              <Stat label="warn" value={summary?.warn ?? 0} />
              <Stat label="unverif" value={summary?.unverified ?? 0} />
              <Stat label="skip" value={summary?.skipped ?? 0} />
              <Stat label="error" value={summary?.error ?? 0} danger />
            </div>
          </div>

          <div className="text-xs text-muted-foreground">
            {run?.status === 'running' ? 'verification running — see Verification tab' : run ? `last run ${run.status}` : 'start a verification below'}
          </div>

          <Separator />
          <div className="flex flex-wrap items-end gap-3">
            <label className="min-w-64 flex-1 text-sm">
              Project path
              <Input
                value={path}
                onChange={(e) => setPath(e.target.value)}
                placeholder="/path/to/app"
                aria-label="Project path"
                className="mt-1"
              />
            </label>
            <label className="text-sm">
              Profile
              <select
                value={profile}
                onChange={(e) => setProfile(e.target.value)}
                aria-label="Verification profile"
                className="mt-1 h-9 rounded-lg border border-input bg-background px-2 text-sm"
              >
                {PROFILES.map((p) => (
                  <option key={p} value={p}>{p}</option>
                ))}
              </select>
            </label>
            <label className="flex items-center gap-2 pb-2 text-sm">
              <input type="checkbox" checked={strict} onChange={(e) => setStrict(e.target.checked)} />
              strict
            </label>
            <Button
              onClick={() => void s.startVerify(path || '.', profile, strict)}
              disabled={!path || run?.status === 'running'}
            >
              Verify
            </Button>
            {run?.status === 'running' && (
              <Button variant="outline" onClick={() => void s.cancelRun()}>Cancel</Button>
            )}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Blocking now</CardTitle>
          <CardDescription>every blocker opens into its evidence</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          {blockers.length === 0 && (
            <p className="text-sm text-muted-foreground">
              {results.length === 0 ? 'no results yet' : 'no blockers in this run'}
            </p>
          )}
          {blockers.slice(0, 6).map((r) => (
            <button
              key={r.checkId}
              onClick={() => void s.openEvidence(r)}
              className="flex items-center gap-2 rounded-lg border border-border px-3 py-2 text-left text-sm hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring"
            >
              <StatusBadge status={r.status} />
              <span className="font-mono text-xs">{r.checkId}</span>
              <span className="truncate text-muted-foreground">{r.title}</span>
              <SeverityBadge severity={r.severity} />
            </button>
          ))}
          {blockers.length > 6 && (
            <Button variant="ghost" size="sm" onClick={() => onNavigate('Findings')}>
              all {blockers.length} blockers →
            </Button>
          )}
        </CardContent>
      </Card>

      <Card className="lg:col-span-2">
        <CardHeader>
          <CardTitle>What the verifier proved (by domain)</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {[...domains.entries()].map(([d, c]) => (
              <div key={d} className="rounded-lg border border-border px-3 py-2 text-sm">
                <div className="font-semibold">{d}</div>
                <div className="text-xs text-muted-foreground">
                  {c.pass} pass · {c.block} block · {c.warn} warn{c.other ? ` · ${c.other} other` : ''}
                </div>
              </div>
            ))}
            {domains.size === 0 && <p className="text-sm text-muted-foreground">run a verification to populate</p>}
          </div>
          {warnings.length > 0 && (
            <p className="mt-3 text-xs text-muted-foreground">{warnings.length} warning(s) — non-blocking, see Findings.</p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Projects</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          {s.projects.length === 0 && <p className="text-sm text-muted-foreground">none registered yet</p>}
          {s.projects.map((p) => (
            <div key={p.id} className="rounded-lg border border-border px-3 py-2 text-sm">
              <div className="font-medium">{p.name}</div>
              <div className="truncate text-xs text-muted-foreground">{p.path}</div>
              <div className="text-xs text-muted-foreground">last run: {p.lastRunId ?? '—'}</div>
            </div>
          ))}
          <Button variant="outline" size="sm" onClick={() => onNavigate('History')}>View history</Button>
        </CardContent>
      </Card>
    </div>
  )
}

function Stat({ label, value, danger }: { label: string; value: number; danger?: boolean }) {
  return (
    <div className="rounded-lg border border-border px-2 py-1 text-center">
      <div className={`text-lg font-bold ${danger && value > 0 ? 'text-red-500' : ''}`}>{value}</div>
      <div className="text-[10px] uppercase text-muted-foreground">{label}</div>
    </div>
  )
}
