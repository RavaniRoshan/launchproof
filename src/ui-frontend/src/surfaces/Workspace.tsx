import { useMemo, useRef, useEffect } from 'react'
import type { AppServices } from '../App'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { StatusBadge } from '../status'
import type { RunEvent } from '../api'

// AI Workspace: agent rail + structured verification stream.
// Events stay structured — each RunEvent type renders as its own card kind.
// The daemon stream IS the source of truth; nothing here invents agent output.
const EVENT_TITLES: Record<RunEvent['type'], string> = {
  'run.started': 'Verification started',
  'run.finished': 'Verification finished',
  'run.cancelled': 'Verification cancelled',
  'run.error': 'Verification error',
  'phase.started': 'Phase started',
  'phase.finished': 'Phase finished',
  'check.started': 'Check executing',
  'check.finished': 'Check result',
  'evidence.created': 'Evidence collected',
  log: 'Daemon log',
  'agent.finding': 'Verifier agent finding',
}

function EventCard({ ev, onOpenEvidence }: { ev: RunEvent; onOpenEvidence: AppServices['openEvidence'] }) {
  const kind = ev.result ? 'result' : ev.type === 'log' ? 'log' : 'lifecycle'
  return (
    <div
      className={`rounded-xl border p-3 ${
        ev.result?.status === 'BLOCK'
          ? 'border-red-500/50'
          : kind === 'log'
            ? 'border-border bg-muted/30'
            : 'border-border'
      }`}
      data-event={ev.type}
    >
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="secondary" className="text-[10px] uppercase">{EVENT_TITLES[ev.type]}</Badge>
        {ev.phase && <span className="text-xs text-muted-foreground">phase: {ev.phase}</span>}
        <span className="ml-auto text-xs tabular-nums text-muted-foreground">{new Date(ev.at).toLocaleTimeString()}</span>
      </div>

      {ev.result && (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <StatusBadge status={ev.result.status} />
          <span className="font-mono text-sm font-semibold">{ev.result.checkId}</span>
          <span className="text-sm">{ev.result.title}</span>
          <button
            className="ml-auto text-xs underline underline-offset-2 hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring"
            onClick={() => onOpenEvidence(ev.result!)}
          >
            open evidence →
          </button>
        </div>
      )}
      {ev.result && (
        <p className="mt-1 text-xs text-muted-foreground">
          {ev.result.status === 'PASS' ? ev.result.observed : (ev.result.reason ?? ev.result.observed)}
        </p>
      )}
      {ev.message && <p className="mt-1 font-mono text-xs text-muted-foreground">{ev.message}</p>}
    </div>
  )
}

export function Workspace({ s }: { s: AppServices }) {
  const feedRef = useRef<HTMLDivElement>(null)
  const events = useMemo(() => s.events, [s.events])

  useEffect(() => {
    const el = feedRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [events.length])

  const agents = s.agents

  return (
    <div className="grid gap-6 lg:grid-cols-[260px_1fr]">
      <Card>
        <CardHeader>
          <CardTitle>Agent rail</CardTitle>
          <CardDescription>live status from daemon capability discovery</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <div className="rounded-lg border border-border px-3 py-2" data-agent="verifier">
            <div className="flex items-center gap-2 text-sm font-semibold">
              Verification Agent
              <Badge variant="outline" className="text-[10px]">{s.report?.run?.status === 'running' ? 'streaming' : 'idle'}</Badge>
            </div>
            <p className="text-xs text-muted-foreground">
              independent verifier · fresh context · claims are never evidence
            </p>
          </div>
          {agents.map((a) => (
            <div key={a.id} className="rounded-lg border border-border px-3 py-2" data-agent={a.id}>
              <div className="flex items-center gap-2 text-sm font-semibold">
                {a.id === 'codex' ? 'Codex' : a.id === 'claude' ? 'Claude Code' : 'Script runner'}
                <Badge variant={a.available ? 'default' : 'secondary'} className="text-[10px]">
                  {a.available ? 'connected' : 'unavailable'}
                </Badge>
              </div>
              <p className="text-xs text-muted-foreground">
                {a.available ? `tools: ${a.tools.join(', ') || 'none reported'}` : `gaps: ${a.gaps.join('; ') || 'not reported'}`}
              </p>
              {!a.available && <p className="text-[11px] text-amber-600 dark:text-amber-400">capability gap recorded — not invented</p>}
            </div>
          ))}
          {agents.length === 0 && <p className="text-sm text-muted-foreground">daemon capability discovery pending…</p>}
        </CardContent>
      </Card>

      <Card className="min-h-[60vh] flex flex-col">
        <CardHeader>
          <CardTitle>Verification stream</CardTitle>
          <CardDescription>
            structured daemon events rendered as typed cards — never flattened to plain chat text
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-1 flex-col gap-3" ref={feedRef}>
          <div className="rounded-xl border border-border bg-muted/20 p-3 text-sm">
            <div className="mb-1 flex items-center gap-2">
              <Badge variant="outline" className="text-[10px] uppercase">Verification Agent</Badge>
              <span className="text-xs text-muted-foreground">session context</span>
            </div>
            <p className="text-muted-foreground">
              Independent verification session. Builder transcript is not shared with this agent. Everything below is
              emitted by the local daemon during run {s.runId ?? '—'}; select a result card to inspect its evidence.
            </p>
          </div>

          {events.map((ev, i) => (
            <EventCard key={`${ev.at}-${i}`} ev={ev} onOpenEvidence={s.openEvidence} />
          ))}

          {events.length === 1 && events[0]?.type === 'run.started' && (
            <p className="text-sm text-muted-foreground">waiting for daemon phase events…</p>
          )}
          {events.length === 0 && (
            <p className="text-sm text-muted-foreground">no events — start a verification from the Dashboard.</p>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
