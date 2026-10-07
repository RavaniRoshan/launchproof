import { useEffect, useState } from 'react'
import type { AppServices } from '../App'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { api, type Verdict } from '../api'

interface HistoryRow {
  runId: string
  verdict: Verdict | 'ERROR' | '?'
  project?: string
  finishedAt?: string
}

export function History({ s, onNavigate }: { s: AppServices; onNavigate: (t: 'Dashboard' | 'Verification' | 'Findings' | 'Workspace' | 'History' | 'Settings') => void }) {
  const [rows, setRows] = useState<HistoryRow[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const load = async () => {
      try {
        const { recent } = await api.runs()
        const out: HistoryRow[] = []
        for (const id of recent.slice(0, 20)) {
          try {
            const rep = await api.report(id)
            out.push({
              runId: rep.run?.id ?? id,
              verdict: rep.run?.verdict ?? rep.verdict ?? '?',
              project: rep.run?.projectPath,
              finishedAt: rep.run?.endedAt,
            })
          } catch {
            // orphaned dir without report: skipped, never shown as PASS
          }
        }
        setRows(out)
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e))
      }
    }
    void load()
  }, [s.report])

  return (
    <div className="grid gap-6 lg:grid-cols-3">
      <Card className="lg:col-span-2">
        <CardHeader>
          <CardTitle>Verification history</CardTitle>
          <CardDescription>survives application restart — stored locally under ~/.launchproof/runs</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          {error && <p className="text-sm text-red-500">{error}</p>}
          {rows === null && <p className="text-sm text-muted-foreground">loading…</p>}
          {rows?.length === 0 && <p className="text-sm text-muted-foreground">no runs yet</p>}
          {rows?.map((r) => (
            <div key={r.runId} className="flex flex-wrap items-center gap-3 rounded-lg border border-border px-3 py-2 text-sm">
              <span
                className={`rounded-full border px-2 py-0.5 text-xs font-bold ${
                  r.verdict === 'READY'
                    ? 'border-emerald-500 text-emerald-600 dark:text-emerald-400'
                    : r.verdict === 'BLOCKED'
                      ? 'border-red-500 text-red-600 dark:text-red-400'
                      : 'border-border text-muted-foreground'
                }`}
              >
                {r.verdict}
              </span>
              <span className="font-mono text-xs">{r.runId}</span>
              <span className="truncate text-xs text-muted-foreground">{r.project ?? ''}</span>
              <Button
                size="sm"
                variant="outline"
                className="ml-auto"
                onClick={() => {
                  void s.loadRun(r.runId).then(() => onNavigate('Findings'))
                }}
              >
                Open
              </Button>
            </div>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Registered projects</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          {s.projects.map((p) => (
            <div key={p.id} className="rounded-lg border border-border px-3 py-2 text-sm">
              <div className="font-medium">{p.name}</div>
              <div className="truncate text-xs text-muted-foreground">{p.path}</div>
            </div>
          ))}
          {s.projects.length === 0 && <p className="text-sm text-muted-foreground">none yet</p>}
        </CardContent>
      </Card>
    </div>
  )
}
