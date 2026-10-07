import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  api,
  openRunStream,
  type AgentCapabilities,
  type CheckResult,
  type EvidenceRecord,
  type ProjectRecord,
  type RunEvent,
  type RunRecord,
  type RunReport,
  type Verdict,
} from './api'
import { VerdictBadge } from './status'
import { Button } from './components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from './components/ui/card'
import { Skeleton } from './components/ui/skeleton'
import { Dashboard } from './surfaces/Dashboard'
import { Verification } from './surfaces/Verification'
import { Findings } from './surfaces/Findings'
import { Workspace } from './surfaces/Workspace'
import { History } from './surfaces/History'
import { Settings } from './surfaces/Settings'
import { EvidenceDrawer } from './surfaces/EvidenceDrawer'

const TABS = [
  'Dashboard',
  'Verification',
  'Findings',
  'Workspace',
  'History',
  'Settings',
] as const
type Tab = (typeof TABS)[number]

export interface AppServices {
  report: RunReport | null
  runId: string | null
  events: RunEvent[]
  evidence: EvidenceRecord[]
  agents: AgentCapabilities[]
  projects: ProjectRecord[]
  daemonError: string | null
  openEvidence: (refs: CheckResult | EvidenceRecord[]) => void
  startVerify: (path: string, profile: string, strict: boolean) => Promise<void>
  cancelRun: () => Promise<void>
  refreshProjects: () => Promise<void>
  loadRun: (runId: string) => Promise<void>
}

export function App() {
  const [tab, setTab] = useState<Tab>('Dashboard')
  const [health, setHealth] = useState<{ ok: boolean; version: string; runs: number } | null>(null)
  const [daemonError, setDaemonError] = useState<string | null>(null)
  const [projects, setProjects] = useState<ProjectRecord[]>([])
  const [agents, setAgents] = useState<AgentCapabilities[]>([])
  const [report, setReport] = useState<RunReport | null>(null)
  const [runId, setRunId] = useState<string | null>(null)
  const [events, setEvents] = useState<RunEvent[]>([])
  const [evidence, setEvidence] = useState<EvidenceRecord[]>([])
  const [evidenceOpen, setEvidenceOpen] = useState(false)
  const [evidenceTarget, setEvidenceTarget] = useState<EvidenceRecord[] | null>(null)
  const [busy, setBusy] = useState(false)

  const refreshProjects = useCallback(async () => {
    try {
      const { projects } = await api.projects()
      setProjects(projects)
    } catch (e) {
      setDaemonError(e instanceof Error ? e.message : String(e))
    }
  }, [])

  useEffect(() => {
    let alive = true
    const load = async () => {
      try {
        const h = await api.health()
        if (alive) {
          setHealth({ ok: h.ok, version: h.version, runs: h.runs })
          setDaemonError(null)
        }
        const [{ projects }, { agents }] = await Promise.all([api.projects(), api.agents()])
        if (alive) {
          setProjects(projects)
          setAgents(agents)
        }
        const { recent } = await api.runs()
        const latest = recent[0]
        if (alive && latest) {
          const rep = await api.report(latest)
          if (alive) {
            setRunId(rep.run?.id ?? latest)
            setReport(rep)
            const ev = await api.evidenceList(latest).catch(() => ({ evidence: [] as EvidenceRecord[] }))
            if (alive) setEvidence(ev.evidence)
          }
        }
      } catch (e) {
        if (alive) setDaemonError(e instanceof Error ? e.message : String(e))
      }
    }
    void load()
    const t = setInterval(load, 15000)
    return () => {
      alive = false
      clearInterval(t)
    }
  }, [])

  const startVerify = useCallback(
    async (path: string, profile: string, strict: boolean) => {
      setBusy(true)
      setDaemonError(null)
      try {
        const { run } = await api.verify(path, profile, strict)
        setRunId(run.id)
        setReport({ run, results: [] })
        setEvents([{ type: 'run.started', runId: run.id, at: run.startedAt ?? new Date().toISOString() }])
        setEvidence([])
        setTab('Verification')
        await refreshProjects()
        openRunStream(
          run.id,
          (ev) => {
            setEvents((prev) => [...prev, ev])
            setReport((prev) => {
              if (!prev) return prev
              const next: RunReport = { ...prev, run: prev.run ? { ...prev.run } : undefined }
              if (ev.type === 'phase.started' && ev.phase && next.run) {
                next.run.phases = next.run.phases.map((p) => (p.id === ev.phase ? { ...p, status: 'running' } : p))
              }
              if (ev.type === 'phase.finished' && ev.phase && next.run) {
                next.run.phases = next.run.phases.map((p) => (p.id === ev.phase ? { ...p, status: 'done' } : p))
              }
              if (ev.type === 'check.finished' && ev.result) {
                const without = next.results.filter((r) => r.checkId !== ev.result!.checkId)
                next.results = [...without, ev.result]
              }
              return next
            })
          },
          () => {
            void (async () => {
              try {
                const rep = await api.report(run.id)
                setReport(rep)
                const ev = await api.evidenceList(run.id).catch(() => ({ evidence: [] as EvidenceRecord[] }))
                setEvidence(ev.evidence)
              } catch (e) {
                setDaemonError(e instanceof Error ? e.message : String(e))
              }
            })()
          },
        )
      } catch (e) {
        setDaemonError(e instanceof Error ? e.message : String(e))
      } finally {
        setBusy(false)
      }
    },
    [refreshProjects],
  )

  const cancelRun = useCallback(async () => {
    if (!runId) return
    try {
      await api.cancel(runId)
    } catch (e) {
      setDaemonError(e instanceof Error ? e.message : String(e))
    }
  }, [runId])

  const loadRun = useCallback(async (id: string) => {
    try {
      const rep = await api.report(id)
      setRunId(rep.run?.id ?? id)
      setReport(rep)
      const ev = await api.evidenceList(id).catch(() => ({ evidence: [] as EvidenceRecord[] }))
      setEvidence(ev.evidence)
      setEvents([])
    } catch (e) {
      setDaemonError(e instanceof Error ? e.message : String(e))
    }
  }, [])

  const openEvidence = useCallback(
    async (target: CheckResult | EvidenceRecord[]) => {
      if (Array.isArray(target)) {
        setEvidenceTarget(target)
        setEvidenceOpen(true)
        return
      }
      const refs = target.evidence ?? []
      const resolved: EvidenceRecord[] = []
      for (const ref of refs) {
        const hit = evidence.find((e) => e.id === ref.id)
        if (hit) resolved.push(hit)
        else if (runId) {
          try {
            const { evidence: one } = await api.evidenceOne(runId, ref.id)
            resolved.push(one)
          } catch { /* record unavailable: viewer shows what exists */ }
        }
      }
      setEvidenceTarget(resolved)
      setEvidenceOpen(true)
    },
    [evidence, runId],
  )

  const services: AppServices = useMemo(
    () => ({
      report,
      runId,
      events,
      evidence,
      agents,
      projects,
      daemonError,
      openEvidence,
      startVerify,
      cancelRun,
      refreshProjects,
      loadRun,
    }),
    [report, runId, events, evidence, agents, projects, daemonError, openEvidence, startVerify, cancelRun, refreshProjects, loadRun],
  )

  const verdict: Verdict | undefined = report?.run?.verdict ?? report?.verdict

  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground">
      <header className="sticky top-0 z-40 flex items-center gap-4 border-b border-border bg-background/95 px-6 py-3 backdrop-blur">
        <h1 className="text-base font-bold tracking-widest">LAUNCHPROOF</h1>
        <span className="text-xs text-muted-foreground">
          {daemonError
            ? `daemon: ${daemonError}`
            : health
              ? `daemon ok · v${health.version} · ${health.runs} active`
              : 'daemon: …'}
        </span>
        <div className="ml-auto flex items-center gap-3">
          {busy && <Skeleton className="h-5 w-20" aria-label="verification starting" />}
          <VerdictBadge verdict={verdict} />
        </div>
      </header>

      <nav aria-label="Primary" className="flex gap-1 border-b border-border px-6 py-2">
        {TABS.map((t) => (
          <Button
            key={t}
            variant={tab === t ? 'secondary' : 'ghost'}
            size="sm"
            aria-current={tab === t ? 'page' : undefined}
            onClick={() => setTab(t)}
          >
            {t}
          </Button>
        ))}
      </nav>

      <main className="flex-1 p-6" id="main-content">
        {tab === 'Dashboard' && <Dashboard s={services} onNavigate={setTab} />}
        {tab === 'Verification' && <Verification s={services} />}
        {tab === 'Findings' && <Findings s={services} />}
        {tab === 'Workspace' && <Workspace s={services} />}
        {tab === 'History' && <History s={services} onNavigate={setTab} />}
        {tab === 'Settings' && <Settings s={services} />}
      </main>

      <footer className="border-t border-border px-6 py-3 text-xs text-muted-foreground">
        LaunchProof answers “ready to launch under the contract?”, never “secure”. SKIPPED / UNVERIFIED / ERROR are not
        passes. Verdict computed by the daemon — never by this UI.
      </footer>

      <EvidenceDrawer
        open={evidenceOpen}
        records={evidenceTarget ?? []}
        onClose={() => setEvidenceOpen(false)}
      />
    </div>
  )
}
