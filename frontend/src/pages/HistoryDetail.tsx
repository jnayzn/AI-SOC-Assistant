import { useEffect, useState } from "react"
import { Link, useParams } from "react-router-dom"
import { ArrowLeft } from "lucide-react"

import { AnalysisResult } from "@/components/AnalysisResult"
import { Button } from "@/components/ui/button"
import { useCopilotContext } from "@/context/CopilotContext"
import { fetchHistoryItem } from "@/services/api"
import type { AnalysisResponse } from "@/types/analysis"

export default function HistoryDetail() {
  const { id } = useParams<{ id: string }>()
  const [result, setResult] = useState<AnalysisResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const { setCurrentAnalysis } = useCopilotContext()

  useEffect(() => {
    if (!id) return
    fetchHistoryItem(id)
      .then(setResult)
      .catch(() => setError("Analysis not found."))
  }, [id])

  // Keep the global AI SOC Copilot grounded in whatever analysis is
  // currently shown here, and clear it again when leaving this page.
  useEffect(() => {
    setCurrentAnalysis(result ?? null)
    return () => setCurrentAnalysis(null)
  }, [result, setCurrentAnalysis])

  return (
    <div className="flex flex-col gap-6">
      <Link to="/history">
        <Button variant="ghost" size="sm">
          <ArrowLeft className="h-4 w-4" /> Back to History
        </Button>
      </Link>
      {error && <p className="text-sm text-red-500">{error}</p>}
      {result ? <AnalysisResult result={result} /> : !error && <p className="text-sm text-slate-400">Loading...</p>}
    </div>
  )
}
