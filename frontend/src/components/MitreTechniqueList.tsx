import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import type { MitreTechniqueDetail } from "@/types/analysis"

export function MitreTechniqueList({
  techniques,
  fallbackFlat,
}: {
  techniques: MitreTechniqueDetail[]
  fallbackFlat: string[]
}) {
  if (!techniques.length && !fallbackFlat.length) return null

  return (
    <Card>
      <CardHeader>
        <CardTitle>MITRE ATT&amp;CK Techniques</CardTitle>
      </CardHeader>
      <CardContent>
        {techniques.length > 0 ? (
          <div className="flex flex-col gap-3">
            {techniques.map((t) => (
              <div
                key={t.id}
                className="rounded-lg border border-gray-100 p-3 dark:border-slate-800"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <Badge className="bg-brand-50 text-brand-700 dark:bg-brand-900/30 dark:text-brand-300">
                    {t.id}
                  </Badge>
                  <span className="text-sm font-semibold text-slate-800 dark:text-slate-100">{t.name}</span>
                  <Badge className="bg-gray-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                    {t.tactic_id} &middot; {t.tactic_name}
                  </Badge>
                </div>
                <p className="mt-1.5 text-sm text-slate-600 dark:text-slate-300">{t.description}</p>
              </div>
            ))}
          </div>
        ) : (
          <div className="flex flex-wrap gap-2">
            {fallbackFlat.map((t) => (
              <span
                key={t}
                className="rounded-md bg-brand-50 px-2 py-1 text-xs font-medium text-brand-700 dark:bg-brand-900/30 dark:text-brand-300"
              >
                {t}
              </span>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
