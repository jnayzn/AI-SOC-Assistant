import { useMemo, useState } from "react"

import { PlaybookCard } from "@/components/PlaybookCard"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { resolvePlaybooks } from "@/data/playbookCatalog"
import type { PlaybookAction } from "@/types/analysis"

export function PlaybookActions({ actions }: { actions?: PlaybookAction[] | null }) {
  // Accordion state: only one playbook can be expanded at a time.
  const [openId, setOpenId] = useState<string | null>(null)

  // Enrich the lightweight backend playbook actions with full SOC response
  // detail from the structured catalog. Memoized so ids stay stable across
  // re-renders (which keeps the open/closed accordion state correct).
  const playbooks = useMemo(() => resolvePlaybooks(actions ?? []), [actions])

  if (!playbooks.length) return null

  return (
    <Card className="border-brand-100 dark:border-brand-900/40">
      <CardHeader>
        <CardTitle>Automated Playbooks</CardTitle>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          Recommended SOC response actions for this incident, ranked by priority. Click a playbook to view its full
          response procedure.
        </p>
      </CardHeader>
      <CardContent>
        <div className="flex flex-col gap-2">
          {playbooks.map((playbook) => (
            <PlaybookCard
              key={playbook.id}
              playbook={playbook}
              isOpen={openId === playbook.id}
              onToggle={() => setOpenId((current) => (current === playbook.id ? null : playbook.id))}
            />
          ))}
        </div>
      </CardContent>
    </Card>
  )
}
