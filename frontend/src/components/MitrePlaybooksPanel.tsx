import { useEffect, useState } from "react"
import { BookOpen, ChevronDown, ExternalLink } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { cn } from "@/lib/utils"
import { fetchMitrePlaybook } from "@/services/api"
import type { MitreTechniqueDetail } from "@/types/analysis"
import type { MitrePlaybook } from "@/types/mitrePlaybook"

const SECTIONS: { key: keyof MitrePlaybook; label: string }[] = [
  { key: "log_sources", label: "Log Sources to Investigate" },
  { key: "key_indicators", label: "Key Indicators" },
  { key: "questions", label: "Questions for Analysis" },
  { key: "escalation", label: "Decision for Escalation" },
  { key: "l1_steps", label: "Additional Analysis Steps (L1)" },
  { key: "t2_actions", label: "T2 Analyst Actions" },
  { key: "containment", label: "Containment & Further Analysis" },
]

function PlaybookItem({ playbook }: { playbook: MitrePlaybook }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="rounded-lg border border-gray-100 dark:border-slate-800">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center justify-between gap-2 px-3 py-2.5 text-left"
      >
        <span className="flex flex-wrap items-center gap-2">
          <Badge className="bg-brand-50 text-brand-700 dark:bg-brand-900/30 dark:text-brand-300">{playbook.ttp}</Badge>
          <span className="text-sm font-semibold text-slate-800 dark:text-slate-100">{playbook.name}</span>
          <Badge className="bg-gray-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300">{playbook.tactic}</Badge>
        </span>
        <ChevronDown className={cn("h-4 w-4 shrink-0 text-slate-400 transition-transform", open && "rotate-180")} />
      </button>
      {open && (
        <div className="space-y-3 border-t border-gray-100 px-3 py-3 dark:border-slate-800">
          {SECTIONS.map(({ key, label }) => {
            const items = playbook[key]
            if (!Array.isArray(items) || items.length === 0) return null
            return (
              <div key={key}>
                <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
                  {label}
                </p>
                <ul className="list-inside list-disc space-y-1 text-sm leading-relaxed text-slate-600 dark:text-slate-300">
                  {items.map((it, i) => (
                    <li key={i}>{it}</li>
                  ))}
                </ul>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

export function MitrePlaybooksPanel({ techniques }: { techniques: MitreTechniqueDetail[] }) {
  const ids = Array.from(new Set((techniques ?? []).map((t) => t.id))).filter(Boolean)
  const key = ids.join(",")
  const [playbooks, setPlaybooks] = useState<MitrePlaybook[]>([])
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    let cancelled = false
    if (ids.length === 0) {
      setPlaybooks([])
      return
    }
    setLoading(true)
    Promise.all(ids.map((id) => fetchMitrePlaybook(id).catch(() => null))).then((results) => {
      if (cancelled) return
      const found: MitrePlaybook[] = []
      const seen = new Set<string>()
      for (const p of results) {
        if (p && !seen.has(p.ttp)) {
          seen.add(p.ttp)
          found.push(p)
        }
      }
      setPlaybooks(found)
      setLoading(false)
    })
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key])

  if (ids.length === 0) return null
  if (!loading && playbooks.length === 0) return null

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <BookOpen className="h-4 w-4 shrink-0 text-brand-600 dark:text-brand-400" />
          MITRE ATT&amp;CK Triage Playbooks
        </CardTitle>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          L1/L2 triage guidance for each detected technique — drafts to adapt to your SOC.{" "}
          <a
            href="https://github.com/CodeByHarri/MITRE-ATT_CK-Playbooks"
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-0.5 text-brand-600 hover:underline dark:text-brand-400"
          >
            Source <ExternalLink className="h-3 w-3" />
          </a>
        </p>
      </CardHeader>
      <CardContent>
        {loading ? (
          <p className="text-sm text-slate-400 dark:text-slate-500">Loading playbooks…</p>
        ) : (
          <div className="flex flex-col gap-2">
            {playbooks.map((p) => (
              <PlaybookItem key={p.ttp} playbook={p} />
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
