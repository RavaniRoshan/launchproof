import { useEffect, useState } from 'react'
import type { AppServices } from '../App'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { api } from '../api'

// Settings & policies: read-only daemon facts + product limits.
// No verification logic, no credential storage in the frontend.
export function Settings({ s }: { s: AppServices }) {
  const [checks, setChecks] = useState<Array<{ id: string; title: string; severity: string; cls: string; phase: string }>>([])

  useEffect(() => {
    void api.checks().then(({ checks }) => setChecks(checks)).catch(() => setChecks([]))
  }, [])

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>Check registry (policy surface)</CardTitle>
          <CardDescription>stable IDs owned by the engine — the UI only displays them</CardDescription>
        </CardHeader>
        <CardContent className="max-h-96 overflow-auto">
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-background text-left text-xs uppercase text-muted-foreground">
              <tr><th className="p-1">ID</th><th className="p-1">Class</th><th className="p-1">Severity</th><th className="p-1">Title</th></tr>
            </thead>
            <tbody>
              {checks.map((c) => (
                <tr key={c.id} className="border-t border-border">
                  <td className="p-1 font-mono text-xs">{c.id}</td>
                  <td className="p-1 text-xs">{c.cls}</td>
                  <td className="p-1 text-xs">{c.severity}</td>
                  <td className="p-1 text-xs">{c.title}</td>
                </tr>
              ))}
              {checks.length === 0 && (
                <tr><td colSpan={4} className="p-2 text-xs text-muted-foreground">daemon unreachable or loading…</td></tr>
              )}
            </tbody>
          </table>
        </CardContent>
      </Card>

      <div className="flex flex-col gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Limits (always on)</CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            <ul className="list-disc space-y-1 pl-5">
              <li>READY ≠ secure; coverage = executed checks only.</li>
              <li>SKIPPED / UNVERIFIED / ERROR are never passes.</li>
              <li>No production targets; no silent source edits.</li>
              <li>Evidence is scrubbed before persistence.</li>
              <li>Verdict computed by the daemon — the frontend never computes results.</li>
              <li>Agent credentials are never stored by the frontend.</li>
            </ul>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Daemon</CardTitle>
            <CardDescription>connection state (polls /health)</CardDescription>
          </CardHeader>
          <CardContent className="text-sm">
            {s.daemonError ? (
              <p className="text-red-500">error: {s.daemonError}</p>
            ) : (
              <p className="text-muted-foreground">connected · {s.agents.length} agent adapter(s) discovered</p>
            )}
            <p className="mt-2 text-xs text-muted-foreground">
              CLI parity: <code>launchproof verify &lt;path&gt;</code> runs the identical engine.
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
