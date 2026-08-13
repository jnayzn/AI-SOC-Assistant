import { useEffect, useState } from "react"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { cn } from "@/lib/utils"
import { fetchMitreMatrix } from "@/services/api"
import type { MitreMatrixTactic, MitreTechniqueDetail } from "@/types/analysis"

export function MitreMatrix({ detectedTechniques }: { detectedTechniques: MitreTechniqueDetail[] }) {
  const [tactics, setTactics] = useState<MitreMatrixTactic[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(false)

  useEffect(() => {
    let cancelled = false
    fetchMitreMatrix()
      .then((data) => {
        if (!cancelled) setTactics(data.tactics)
      })
      .catch(() => {
        if (!cancelled) setError(true)
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [])

  const detectedIds = new Set(detectedTechniques.map((t) => t.id))
  const detectedById = new Map(detectedTechniques.map((t) => [t.id, t]))

  if (loading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>MITRE ATT&amp;CK Matrix</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-slate-400">Loading matrix...</p>
        </CardContent>
      </Card>
    )
  }

  if (error || tactics.length === 0) return null

  return (
    <Card className="border-brand-100 dark:border-brand-900/40">
      <CardHeader>
        <CardTitle>MITRE ATT&amp;CK Matrix</CardTitle>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          Full tactic-by-technique matrix. Techniques detected in this analysis are highlighted.
        </p>
      </CardHeader>
      <CardContent>
        <div className="flex gap-3 overflow-x-auto pb-2">
          {tactics.map((tactic) => (
            <div key={tactic.id} className="min-w-[180px] flex-1">
              <div className="mb-2 rounded-md bg-slate-100 px-2 py-1.5 text-center text-xs font-semibold uppercase tracking-wide text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                {tactic.name}
                <div className="text-[10px] font-normal text-slate-400">{tactic.id}</div>
              </div>
              <div className="flex flex-col gap-1.5">
                {tactic.techniques.map((technique) => {
                  const isDetected = detectedIds.has(technique.id)
                  const detail = detectedById.get(technique.id)
                  return (
                    <div
                      key={technique.id}
                      title={detail?.description ?? technique.description}
                      className={cn(
                        "rounded-md border px-2 py-1.5 text-[11px] transition-all",
                        isDetected
                          ? "animate-pulse border-red-300 bg-red-50 font-semibold text-red-700 shadow-sm dark:border-red-800 dark:bg-red-900/30 dark:text-red-300"
                          : "border-slate-100 bg-white text-slate-500 dark:border-slate-800 dark:bg-slate-900/40 dark:text-slate-400",
                      )}
                    >
                      <span className="font-mono text-[10px] opacity-70">{technique.id}</span>
                      <div>{technique.name}</div>
                    </div>
                  )
                })}
                {tactic.techniques.length === 0 && (
                  <div className="rounded-md border border-dashed border-slate-100 px-2 py-1.5 text-center text-[10px] text-slate-300 dark:border-slate-800">
                    No mapped techniques
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}
