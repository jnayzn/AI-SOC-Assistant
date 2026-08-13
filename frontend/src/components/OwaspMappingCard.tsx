import type { ReactNode } from "react"
import { ShieldAlert } from "lucide-react"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { OWASP_CATALOG } from "@/data/owaspCatalog"
import type { OwaspMapping } from "@/types/analysis"

function normalizeCode(id: string): string {
  const full = id.match(/A\d{2}:\d{4}/)
  if (full) return full[0]
  const short = id.match(/A\d{2}/)
  return short ? `${short[0]}:2021` : id
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <p className="text-xs font-semibold text-slate-700 dark:text-slate-200">{label}</p>
      <p className="mt-0.5 text-sm leading-relaxed text-slate-600 dark:text-slate-300">{children}</p>
    </div>
  )
}

export function OwaspMappingCard({ mappings }: { mappings: OwaspMapping[] }) {
  if (!mappings.length) return null

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 shrink-0 text-cyan-600 dark:text-cyan-400" />
          OWASP Mapping
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex flex-col gap-3">
          {mappings.map((mapping) => {
            const ref = OWASP_CATALOG[normalizeCode(mapping.id)]
            return (
              <div
                key={mapping.id}
                className="rounded-lg border border-cyan-100 bg-cyan-50/60 p-3 dark:border-cyan-900/40 dark:bg-cyan-900/10"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <Badge className="bg-cyan-100 text-cyan-800 dark:bg-cyan-900/40 dark:text-cyan-200">
                    {mapping.id}
                  </Badge>
                  <span className="text-sm font-semibold text-cyan-900 dark:text-cyan-200">{mapping.name}</span>
                </div>

                {mapping.reason && (
                  <p className="mt-1.5 text-xs italic text-slate-500 dark:text-slate-400">{mapping.reason}</p>
                )}

                {ref && (
                  <div className="mt-2.5 space-y-2.5">
                    <Field label="Attack Vector:">{ref.attackVector}</Field>
                    <Field label="Description:">{ref.description}</Field>
                    <Field label="Impact:">{ref.impact}</Field>
                    <Field label="Recommendation:">{ref.recommendation}</Field>
                    <div>
                      <p className="text-xs font-semibold text-slate-700 dark:text-slate-200">References:</p>
                      <ul className="mt-0.5 list-inside list-disc text-sm text-slate-600 dark:text-slate-300">
                        {ref.references.map((r) => (
                          <li key={r}>{r}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </CardContent>
    </Card>
  )
}
