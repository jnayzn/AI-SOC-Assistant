import { AlertTriangle, BookOpen, Check, ShieldAlert, X } from "lucide-react"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { cn } from "@/lib/utils"
import type { ExplainabilityItem, OwaspMapping } from "@/types/analysis"

export function ExplainableAICard({
  items,
  owaspMappings,
  riskFactors,
  knowledgeSources,
}: {
  items: ExplainabilityItem[]
  owaspMappings?: OwaspMapping[] | null
  riskFactors?: string[] | null
  knowledgeSources?: string[] | null
}) {
  if (!items.length) return null
  return (
    <Card className="border-brand-100 dark:border-brand-900/40">
      <CardHeader>
        <CardTitle>Explainable AI</CardTitle>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          Deterministic signal checklist backing this verdict, independent of the LLM narrative.
        </p>
      </CardHeader>
      <CardContent className="space-y-5">
        <ul className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          {items.map((item) => (
            <li
              key={item.label}
              className={cn(
                "flex items-center gap-2 rounded-lg px-3 py-2 text-sm",
                item.matched
                  ? "bg-green-50 text-green-700 dark:bg-green-900/20 dark:text-green-300"
                  : "bg-gray-50 text-slate-400 dark:bg-slate-800/60 dark:text-slate-500",
              )}
            >
              {item.matched ? (
                <Check className="h-4 w-4 shrink-0" />
              ) : (
                <X className="h-4 w-4 shrink-0" />
              )}
              {item.label}
            </li>
          ))}
        </ul>

        {riskFactors && riskFactors.length > 0 && (
          <div>
            <h4 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-amber-600 dark:text-amber-400">
              <AlertTriangle className="h-3.5 w-3.5" />
              Risk Factors
            </h4>
            <ul className="space-y-1.5">
              {riskFactors.map((factor) => (
                <li
                  key={factor}
                  className="rounded-lg bg-amber-50 px-3 py-1.5 text-sm text-amber-800 dark:bg-amber-900/20 dark:text-amber-300"
                >
                  {factor}
                </li>
              ))}
            </ul>
          </div>
        )}

        {owaspMappings && owaspMappings.length > 0 && (
          <div>
            <h4 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-cyan-700 dark:text-cyan-400">
              <ShieldAlert className="h-3.5 w-3.5" />
              OWASP Mapping
            </h4>
            <ul className="space-y-1.5">
              {owaspMappings.map((mapping) => (
                <li
                  key={mapping.id}
                  className="rounded-lg border border-cyan-100 bg-cyan-50/60 px-3 py-2 text-sm dark:border-cyan-900/40 dark:bg-cyan-900/10"
                >
                  <span className="font-semibold text-cyan-800 dark:text-cyan-300">
                    {mapping.id} &middot; {mapping.name}
                  </span>
                  <p className="mt-0.5 text-xs text-slate-600 dark:text-slate-400">{mapping.reason}</p>
                </li>
              ))}
            </ul>
          </div>
        )}

        {knowledgeSources && knowledgeSources.length > 0 && (
          <div>
            <h4 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
              <BookOpen className="h-3.5 w-3.5" />
              Knowledge Sources
            </h4>
            <div className="flex flex-wrap gap-1.5">
              {knowledgeSources.map((source) => (
                <span
                  key={source}
                  className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-600 dark:bg-slate-800 dark:text-slate-300"
                >
                  {source}
                </span>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
