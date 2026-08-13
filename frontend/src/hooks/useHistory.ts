import { useCallback, useEffect, useState } from "react"

import { deleteHistoryItem, fetchHistory } from "@/services/api"
import type { HistoryQueryParams, PaginatedAnalyses } from "@/types/analysis"

export function useHistory(params: HistoryQueryParams) {
  const [data, setData] = useState<PaginatedAnalyses | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const {
    page = 1,
    page_size: pageSize = 10,
    search,
    classification,
    risk_level: riskLevel,
    sort_by: sortBy = "created_at",
    sort_order: sortOrder = "desc",
  } = params

  const load = useCallback(async () => {
    setIsLoading(true)
    setError(null)
    try {
      const result = await fetchHistory({
        page,
        page_size: pageSize,
        search: search || undefined,
        classification,
        risk_level: riskLevel,
        sort_by: sortBy,
        sort_order: sortOrder,
      })
      setData(result)
    } catch {
      setError("Failed to load history.")
    } finally {
      setIsLoading(false)
    }
  }, [page, pageSize, search, classification, riskLevel, sortBy, sortOrder])

  useEffect(() => {
    load()
  }, [load])

  const remove = useCallback(
    async (id: string) => {
      await deleteHistoryItem(id)
      await load()
    },
    [load],
  )

  return { data, isLoading, error, reload: load, remove }
}
