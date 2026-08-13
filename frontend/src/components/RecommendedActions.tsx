import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { cn } from "@/lib/utils"
import type { RecommendationsGrouped } from "@/types/analysis"

const GROUPS: { key: keyof RecommendationsGrouped; label: string; className: string }[] = [
  { key: "immediate", label: "Immediate", className: "border-red-200 dark:border-red-900/40" },
  { key: "investigate", label: "Investigate", className: "border-yellow-200 dark:border-yellow-900/40" },
  { key: "contain", label: "Contain", className: "border-orange-200 dark:border-orange-900/40" },
  { key: "recover", label: "Recover", className: "border-green-200 dark:border-green-900/40" },
]

export function RecommendedActions({
  grouped,
  fallbackFlat,
}: {
  grouped: RecommendationsGrouped | null | undefined
  fallbackFlat: string[]
}) {
  const hasGrouped = grouped && GROUPS.some((g) => grouped[g.key]?.length)

  if (!hasGrouped && !fallbackFlat.length) return null

  return (
    <Card>
      <CardHeader>
        <CardTitle>Recommended Actions</CardTitle>
      </CardHeader>
      <CardContent>
        {hasGrouped ? (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            {GROUPS.map((g) => {
              const items = grouped?.[g.key] ?? []
              if (!items.length) return null
              return (
                <div key={g.key} className={cn("rounded-lg border p-3", g.className)}>
                  <h5 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
                    {g.label}
                  </h5>
                  <ul className="list-inside list-disc text-sm text-slate-600 dark:text-slate-300">
                    {items.map((r) => (
                      <li key={r}>{r}</li>
                    ))}
                  </ul>
                </div>
              )
            })}
          </div>
        ) : (
          <ul className="list-inside list-disc text-sm text-slate-600 dark:text-slate-300">
            {fallbackFlat.map((r) => (
              <li key={r}>{r}</li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}
