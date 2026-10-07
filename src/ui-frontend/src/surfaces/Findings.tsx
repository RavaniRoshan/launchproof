import { useState } from 'react'
import type { AppServices } from '../App'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '../components/ui/dialog'
import { StatusBadge, SeverityBadge } from '../status'
import type { CheckResult } from '../api'

// Findings: structured interface per finding, evidence one action away,
// fix actions behind an explicit approval dialog (nothing runs silently).
export function Findings({ s }: { s: AppServices }) {
  const results = s.report?.results ?? []
  const findings = results.filter((r) => r.status === 'BLOCK' || r.status === 'WARN')
  const [fixTarget, setFixTarget] = useState<CheckResult | null>(null)
  const [agent, setAgent] = useState<'codex' | 'claude' | 'script'>('codex')
  const [preview, setPreview] = useState<{ instruction: string; note: string } | null>(null)
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState<string | null>(null)

  const loadPreview = async () => {
    if (!fixTarget || !s.runId) return
    setBusy(true)
    setNotice(null)
    try {
      const res = await api_fix(s.runId, fixTarget.checkId, agent, false)
      setPreview({ instruction: res.task?.instruction ?? res.instruction ?? '', note: res.note })
    } catch (e) {
      setNotice(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  const approve = async () => {
    if (!fixTarget || !s.runId) return
    setBusy(true)
    try {
      const res = await api_fix(s.runId, fixTarget.checkId, agent, true)
      setNotice(`${res.note}\n\nAfter the agent finishes, re-run launchproof verify --only ${fixTarget.checkId} — the agent's word is never evidence.`)
      setPreview(null)
    } catch (e) {
      setNotice(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle>Findings</CardTitle>
          <CardDescription>only BLOCK and WARN appear here — never a collapsed status</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          {findings.length === 0 && (
            <p className="text-sm text-muted-foreground">{results.length === 0 ? 'no run yet' : 'no findings in this run'}</p>
          )}
          {findings.map((r) => (
            <div key={r.checkId} className="rounded-xl border border-border p-4">
              <div className="flex flex-wrap items-center gap-2">
                <StatusBadge status={r.status} />
                <span className="font-mono text-sm font-semibold">{r.checkId}</span>
                <SeverityBadge severity={r.severity} />
                <span className="text-sm font-medium">{r.title}</span>
                {r.verificationClass && <span className="text-xs text-muted-foreground">class: {r.verificationClass}</span>}
                {r.agentLabel && <span className="text-xs text-muted-foreground">label: {r.agentLabel}</span>}
              </div>
              <p className="mt-2 text-sm text-muted-foreground">
                <strong>Observed:</strong> {r.observed ?? r.reason ?? '—'}
              </p>
              {r.expected && (
                <p className="text-sm text-muted-foreground"><strong>Expected:</strong> {r.expected}</p>
              )}
              {r.affectedSurface && r.affectedSurface.length > 0 && (
                <p className="text-xs text-muted-foreground">Surface: {r.affectedSurface.join(', ')}</p>
              )}
              {r.reproduction?.command && (
                <p className="mt-1 rounded bg-muted px-2 py-1 font-mono text-xs">{r.reproduction.command}</p>
              )}
              <div className="mt-3 flex flex-wrap gap-2">
                <Button size="sm" variant="outline" onClick={() => void s.openEvidence(r)}>
                  View evidence ({r.evidence.length})
                </Button>
                <Button size="sm" variant="secondary" onClick={() => { setFixTarget(r); setPreview(null); setNotice(null) }}>
                  Fix with agent…
                </Button>
                <Button size="sm" variant="ghost" onClick={() => setNotice(`${r.checkId}: accepted risk recorded for this session (stored where? local policy only in V1 — not persisted across runs)`)} title="Records a session-local acknowledgement; does not change the verdict">
                  Mark accepted risk
                </Button>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      <Dialog open={fixTarget !== null} onOpenChange={(open) => { if (!open) setFixTarget(null) }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Fix {fixTarget?.checkId} with an agent</DialogTitle>
            <DialogDescription>
              Scoped instruction from the daemon. The agent runs only after explicit approval, and the check is
              independently re-run afterwards.
            </DialogDescription>
          </DialogHeader>

          <div className="flex flex-col gap-3">
            <label className="text-sm">
              Agent
              <select
                value={agent}
                onChange={(e) => setAgent(e.target.value as typeof agent)}
                aria-label="Choose agent"
                className="mt-1 ml-2 h-8 rounded-lg border border-input bg-background px-2 text-sm"
              >
                <option value="codex">Codex {s.agents.find((a) => a.id === 'codex')?.available ? '' : '(unavailable)'}</option>
                <option value="claude">Claude Code {s.agents.find((a) => a.id === 'claude')?.available ? '' : '(unavailable)'}</option>
                <option value="script">script</option>
              </select>
            </label>

            {preview ? (
              <div className="rounded-lg border border-border bg-muted/40 p-3">
                <div className="mb-1 text-xs font-semibold uppercase text-muted-foreground">Scoped instruction (from daemon)</div>
                <pre className="max-h-64 overflow-auto whitespace-pre-wrap font-mono text-xs">{preview.instruction}</pre>
                <div className="mt-2 text-xs text-muted-foreground">{preview.note}</div>
              </div>
            ) : (
              !notice && <p className="text-sm text-muted-foreground">Preview the exact instruction before approving.</p>
            )}

            {notice && <pre className="whitespace-pre-wrap rounded-lg border border-border p-3 text-xs">{notice}</pre>}
          </div>

          <DialogFooter>
            <Button variant="ghost" onClick={() => setFixTarget(null)}>Cancel</Button>
            {!preview ? (
              <Button onClick={() => void loadPreview()} disabled={busy}>Preview instruction</Button>
            ) : (
              <Button onClick={() => void approve()} disabled={busy} aria-label="Approve agent source modification">
                Approve &amp; run agent
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

async function api_fix(runId: string, checkId: string, agent: string, approve: boolean) {
  const res = await fetch(`/api/runs/${runId}/fix`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ checkId, agentId: agent, approve }),
  })
  const body = await res.json()
  if (!res.ok) throw new Error(body.error ?? `HTTP ${res.status}`)
  return body as { task?: { instruction?: string }; instruction?: string; note: string }
}
