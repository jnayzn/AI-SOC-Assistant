import { useCallback, useState } from "react"

import { analyzeContent } from "@/services/api"
import type { AnalysisResponse, AnalyzeRequest } from "@/types/analysis"

export function useAnalyze() {
  const [result, setResult] = useState<AnalysisResponse | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const analyze = useCallback(async (payload: AnalyzeRequest) => {
    setIsLoading(true)
    setError(null)
    try {
      const data = await analyzeContent(payload)
      setResult(data)
      return data
    } catch (err: unknown) {
      const message =
        (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ||
        "Analysis failed. Please try again."
      setError(message)
      throw err
    } finally {
      setIsLoading(false)
    }
  }, [])

  const reset = useCallback(() => {
    setResult(null)
    setError(null)
  }, [])

  return { result, isLoading, error, analyze, reset }
}
