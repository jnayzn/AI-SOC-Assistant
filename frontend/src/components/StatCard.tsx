import type { LucideIcon } from "lucide-react"

import { Card, CardContent } from "@/components/ui/card"
import { cn } from "@/lib/utils"

export function StatCard({
  label,
  value,
  icon: Icon,
  accent = "text-brand-600",
  subtitle,
}: {
  label: string
  value: string | number
  icon: LucideIcon
  accent?: string
  /** Optional short caption clarifying which analysis dimension this KPI is
   * derived from (e.g. "By threat category" vs "By severity"), so users can
   * see at a glance that Dashboard counters map onto real, distinct fields
   * on the underlying analysis records rather than the Content Type
   * selector. */
  subtitle?: string
}) {
  return (
    <Card>
      <CardContent className="flex items-center justify-between p-5">
        <div>
          <p className="text-sm font-medium text-slate-500 dark:text-slate-400">{label}</p>
          <p className="mt-1 text-2xl font-bold text-slate-800 dark:text-slate-100">{value}</p>
          {subtitle && <p className="mt-0.5 text-xs text-slate-400 dark:text-slate-500">{subtitle}</p>}
        </div>
        <div className={cn("rounded-full bg-gray-100 p-3 dark:bg-slate-800", accent)}>
          <Icon className="h-6 w-6" />
        </div>
      </CardContent>
    </Card>
  )
}
