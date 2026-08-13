import type { LucideIcon } from "lucide-react"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import type { TopItem } from "@/types/analysis"

/** Compact ranked bar-list card used on the SOC Dashboard for the Top-N
 * breakdowns (IOC types, countries, malware families, MITRE techniques,
 * OWASP categories). Purely presentational -- all counts are computed
 * server-side in StatsService/AnalysisRepository. */
export function TopListCard({
  title,
  icon: Icon,
  items,
  emptyLabel = "No data yet.",
}: {
  title: string
  icon?: LucideIcon
  items: TopItem[]
  emptyLabel?: string
}) {
  const max = items.length > 0 ? Math.max(...items.map((i) => i.count)) : 0

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          {Icon && <Icon className="h-4 w-4 text-slate-400" />}
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {items.length === 0 ? (
          <p className="text-sm text-slate-400">{emptyLabel}</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {items.map((item) => (
              <li key={item.label} className="flex flex-col gap-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="truncate font-medium text-slate-600 dark:text-slate-300" title={item.label}>
                    {item.label}
                  </span>
                  <span className="shrink-0 text-slate-400">{item.count}</span>
                </div>
                <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                  <div
                    className="h-full rounded-full bg-brand-500"
                    style={{ width: `${max > 0 ? (item.count / max) * 100 : 0}%` }}
                  />
                </div>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}
