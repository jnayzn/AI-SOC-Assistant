import { useEffect } from "react"

import { AnalysisForm } from "@/components/AnalysisForm"
import { AnalysisResult } from "@/components/AnalysisResult"
import { useCopilotContext } from "@/context/CopilotContext"
import { useAnalyze } from "@/hooks/useAnalyze"

export default function Analyzer() {
  const { result, isLoading, error, analyze } = useAnalyze()
  const { setCurrentAnalysis } = useCopilotContext()

  // Keep the global AI SOC Copilot grounded in whatever analysis is
  // currently shown here, and clear it again when leaving this page.
  useEffect(() => {
    setCurrentAnalysis(result ?? null)
    return () => setCurrentAnalysis(null)
  }, [result, setCurrentAnalysis])

  function handleSubmit(content: string, inputType: string) {
    analyze({ content, input_type: inputType }).catch(() => {
      /* error already captured in hook state */
    })
  }

  return (
    <div className="flex flex-col gap-6">
      <h1 className="text-xl font-bold text-slate-800 dark:text-slate-100">Analyzer</h1>

      {/* Section A: full-width input / analysis control */}
      <AnalysisForm onSubmit={handleSubmit} isLoading={isLoading} />

      {error && <p className="text-sm text-red-500">{error}</p>}

      {result ? (
        <AnalysisResult result={result} />
      ) : (
        !error && (
          <p className="text-sm text-slate-400">Results will appear here after you run an analysis.</p>
        )
      )}
    </div>
  )
}
