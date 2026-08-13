import { createContext, useContext, useMemo, useState, type ReactNode } from "react"

import type { AnalysisResponse } from "@/types/analysis"

interface CopilotContextValue {
  /** The Analysis record currently displayed on screen (Analyzer result or
   * History detail), or null when the analyst isn't viewing a specific
   * analysis. Lets the global AI SOC Copilot widget ground its answers in
   * whatever the analyst is actually looking at. Purely additive. */
  currentAnalysis: AnalysisResponse | null
  setCurrentAnalysis: (analysis: AnalysisResponse | null) => void
  /** Convenience accessor for the current analysis id (kept for the grounded
   * indicator and the copilot request payload). */
  currentAnalysisId: string | null
}

const CopilotContext = createContext<CopilotContextValue | undefined>(undefined)

export function CopilotProvider({ children }: { children: ReactNode }) {
  const [currentAnalysis, setCurrentAnalysis] = useState<AnalysisResponse | null>(null)
  const value = useMemo<CopilotContextValue>(
    () => ({
      currentAnalysis,
      setCurrentAnalysis,
      currentAnalysisId: currentAnalysis?.id ?? null,
    }),
    [currentAnalysis],
  )
  return <CopilotContext.Provider value={value}>{children}</CopilotContext.Provider>
}

export function useCopilotContext(): CopilotContextValue {
  const ctx = useContext(CopilotContext)
  if (!ctx) throw new Error("useCopilotContext must be used within a CopilotProvider")
  return ctx
}
