import { Download, Search } from "lucide-react"
import type { FormEvent } from "react"
import { useState } from "react"

import { HistoryTable } from "@/components/HistoryTable"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { CardSkeleton } from "@/components/ui/skeleton"
import { useHistory } from "@/hooks/useHistory"
import { exportHistoryCsvUrl, exportHistoryXlsxUrl } from "@/services/api"
import type { HistoryQueryParams } from "@/types/analysis"

const PAGE_SIZE = 10

export default function History() {
  const [page, setPage] = useState(1)
  const [searchInput, setSearchInput] = useState("")
  const [search, setSearch] = useState("")
  const [sortBy, setSortBy] = useState<NonNullable<HistoryQueryParams["sort_by"]>>("created_at")
  const [sortOrder, setSortOrder] = useState<NonNullable<HistoryQueryParams["sort_order"]>>("desc")

  const { data, isLoading, error, remove } = useHistory({
    page,
    page_size: PAGE_SIZE,
    search,
    sort_by: sortBy,
    sort_order: sortOrder,
  })

  const handleSortChange = (key: NonNullable<HistoryQueryParams["sort_by"]>) => {
    if (key === sortBy) {
      setSortOrder((prev) => (prev === "asc" ? "desc" : "asc"))
    } else {
      setSortBy(key)
      setSortOrder("desc")
    }
  }

  const handleSearchSubmit = (e: FormEvent) => {
    e.preventDefault()
    setPage(1)
    setSearch(searchInput.trim())
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-xl font-bold text-slate-800 dark:text-slate-100">History</h1>
        <div className="flex flex-wrap gap-2">
          <a href={exportHistoryCsvUrl({ search: search || undefined })} target="_blank" rel="noreferrer">
            <Button variant="outline" size="sm">
              <Download className="h-4 w-4" /> Export CSV
            </Button>
          </a>
          <a href={exportHistoryXlsxUrl({ search: search || undefined })} target="_blank" rel="noreferrer">
            <Button variant="outline" size="sm">
              <Download className="h-4 w-4" /> Export Excel (.xlsx)
            </Button>
          </a>
        </div>
      </div>

      <form onSubmit={handleSearchSubmit} className="flex max-w-md items-center gap-2">
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <input
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder="Search by summary or content..."
            className="w-full rounded-lg border border-gray-200 bg-white py-2 pl-9 pr-3 text-sm text-slate-700 outline-none transition-colors focus:border-brand-500 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-200"
          />
        </div>
        <Button type="submit" size="sm">
          Search
        </Button>
      </form>

      <Card>
        <CardContent className="p-5">
          {isLoading && <CardSkeleton lines={6} />}
          {error && <p className="text-sm text-red-500">{error}</p>}
          {data && (
            <>
              <HistoryTable
                items={data.items}
                onDelete={remove}
                sortBy={sortBy}
                sortOrder={sortOrder}
                onSortChange={handleSortChange}
              />
              <div className="mt-4 flex items-center justify-between text-sm text-slate-500">
                <span>
                  Page {data.page} &middot; {data.total} total analyses
                </span>
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                    Previous
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={page * data.page_size >= data.total}
                    onClick={() => setPage((p) => p + 1)}
                  >
                    Next
                  </Button>
                </div>
              </div>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
