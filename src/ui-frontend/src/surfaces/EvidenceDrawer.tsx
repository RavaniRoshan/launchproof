import type { EvidenceRecord } from '../api'
import { Drawer, DrawerContent, DrawerHeader, DrawerTitle, DrawerDescription } from '../components/ui/drawer'
import { Badge } from '../components/ui/badge'

// Evidence viewer: conclusion first, expand into the underlying proof.
// Structured evidence stays structured (JSON pretty-printed, not flattened).
export function EvidenceDrawer({
  open,
  records,
  onClose,
}: {
  open: boolean
  records: EvidenceRecord[]
  onClose: () => void
}) {
  return (
    <Drawer open={open} onOpenChange={(o) => { if (!o) onClose() }}>
      <DrawerContent className="max-h-[85vh]">
        <DrawerHeader>
          <DrawerTitle>Evidence</DrawerTitle>
          <DrawerDescription>
            {records.length === 0
              ? 'No evidence records available for this selection.'
              : `${records.length} record(s) · scrubbed before persistence · replayable where noted`}
          </DrawerDescription>
        </DrawerHeader>

        <div className="flex flex-col gap-4 overflow-y-auto px-6 pb-8">
          {records.map((rec) => (
            <details
              key={rec.id}
              open
              className="group rounded-xl border border-border"
              data-evidence={rec.id}
            >
              <summary className="cursor-pointer rounded-xl px-4 py-3 text-sm font-medium focus-visible:ring-2 focus-visible:ring-ring">
                <span className="mr-2 font-mono text-xs text-muted-foreground">{rec.id}</span>
                {rec.title}
                <span className="ml-2">
                  <Badge variant="outline" className="text-[10px]">{rec.category}</Badge>
                </span>
                {rec.scrubbed && (
                  <span className="ml-2 text-[10px] text-amber-600 dark:text-amber-400" title="Secrets redacted before persistence">
                    SCRUBBED
                  </span>
                )}
              </summary>
              <div className="border-t border-border px-4 py-3">
                <div className="mb-2 grid gap-1 text-xs text-muted-foreground sm:grid-cols-2">
                  <span>check: <span className="font-mono">{rec.checkId}</span></span>
                  <span>created: {new Date(rec.createdAt).toLocaleString()}</span>
                  <span className="sm:col-span-2">sha256: <span className="font-mono break-all">{rec.sha256.slice(0, 32)}…</span></span>
                </div>
                <pre className="max-h-80 overflow-auto rounded-lg bg-muted/40 p-3 font-mono text-xs leading-relaxed">
                  {JSON.stringify(rec.data, null, 2)}
                </pre>
                {rec.replay && (
                  <div className="mt-2">
                    <div className="text-xs font-semibold uppercase text-muted-foreground">Replay</div>
                    <code className="rounded bg-muted px-2 py-1 text-xs">{rec.replay}</code>
                  </div>
                )}
              </div>
            </details>
          ))}
        </div>
      </DrawerContent>
    </Drawer>
  )
}
