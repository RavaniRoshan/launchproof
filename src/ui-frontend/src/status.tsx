// LaunchProof design layer: one status/severity vocabulary, one visual meaning.
// Status is never conveyed by color alone — every badge carries its text label.
import { cn } from './lib/utils'
import type { CheckStatus, Severity, Verdict } from './api'

const STATUS_STYLES: Record<CheckStatus, string> = {
  PASS: 'bg-emerald-100 text-emerald-900 dark:bg-emerald-950 dark:text-emerald-300',
  BLOCK: 'bg-red-100 text-red-900 dark:bg-red-950 dark:text-red-300',
  WARN: 'bg-amber-100 text-amber-900 dark:bg-amber-950 dark:text-amber-300',
  SKIPPED: 'bg-zinc-100 text-zinc-600 dark:bg-zinc-900 dark:text-zinc-400',
  UNVERIFIED: 'bg-zinc-100 text-zinc-600 dark:bg-zinc-900 dark:text-zinc-400',
  ERROR: 'bg-red-100 text-red-900 dark:bg-red-950 dark:text-red-300',
}

const STATUS_GLYPH: Record<CheckStatus, string> = {
  PASS: '✓', BLOCK: '✕', WARN: '!', SKIPPED: '→', UNVERIFIED: '?', ERROR: '⊗',
}

export function StatusBadge({ status, className }: { status: CheckStatus; className?: string }) {
  return (
    <span
      role="status"
      aria-label={`status ${status}`}
      className={cn(
        'inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-semibold tracking-wide',
        STATUS_STYLES[status],
        className,
      )}
    >
      <span aria-hidden className="text-[10px] leading-none">{STATUS_GLYPH[status]}</span>
      {status}
    </span>
  )
}

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: 'border-red-500/60 text-red-600 dark:text-red-400',
  major: 'border-amber-500/60 text-amber-600 dark:text-amber-400',
  minor: 'border-sky-500/60 text-sky-600 dark:text-sky-400',
  info: 'border-zinc-500/60 text-zinc-500',
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      aria-label={`severity ${severity}`}
      className={cn('inline-flex items-center rounded border px-1.5 py-0.5 text-[11px] font-medium uppercase', SEVERITY_STYLES[severity])}
    >
      {severity}
    </span>
  )
}

export function VerdictBadge({ verdict, className }: { verdict: Verdict | undefined; className?: string }) {
  if (!verdict) {
    return <span className={cn('rounded-full border border-border px-3 py-1 text-sm font-bold text-muted-foreground', className)}>NO VERDICT</span>
  }
  return (
    <span
      role="status"
      aria-label={`launch verdict ${verdict}`}
      className={cn(
        'rounded-full border px-4 py-1 text-sm font-bold tracking-widest',
        verdict === 'READY'
          ? 'border-emerald-500 text-emerald-600 dark:text-emerald-400'
          : 'border-red-500 text-red-600 dark:text-red-400',
        className,
      )}
    >
      {verdict}
    </span>
  )
}
