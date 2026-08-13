import { ArrowDown, ArrowUp, Download, Eye, Trash2 } from "lucide-react"
import { Link } from "react-router-dom"

import { ClassificationBadge } from "@/components/ClassificationBadge"
import { RiskBadge } from "@/components/RiskBadge"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import { exportHistoryItemUrl } from "@/services/api"
import type { AnalysisListItem, HistoryQueryParams } from "@/types/analysis"

interface HistoryTableProps {
  items: AnalysisListItem[]
  onDelete: (id: string) => void
  sortBy: NonNullable<HistoryQueryParams["sort_by"]>
  sortOrder: NonNullable<HistoryQueryParams["sort_order"]>
  onSortChange: (sortBy: NonNullable<HistoryQueryParams["sort_by"]>) => void
}

function SortableHeader({
  label,
  sortKey,
  sortBy,
  sortOrder,
  onSortChange,
}: {
  label: string
  sortKey: NonNullable<HistoryQueryParams["sort_by"]>
  sortBy: NonNullable<HistoryQueryParams["sort_by"]>
  sortOrder: NonNullable<HistoryQueryParams["sort_order"]>
  onSortChange: (sortBy: NonNullable<HistoryQueryParams["sort_by"]>) => void
}) {
  const active = sortBy === sortKey
  return (
    <th className="py-2 pr-4 font-medium">
      <button
        type="button"
        onClick={() => onSortChange(sortKey)}
        className={cn(
          "flex items-center gap-1 hover:text-brand-600 dark:hover:text-brand-400",
          active && "text-brand-600 dark:text-brand-400",
        )}
      >
        {label}
        {active && (sortOrder === "asc" ? <ArrowUp className="h-3 w-3" /> : <ArrowDown className="h-3 w-3" />)}
      </button>
    </th>
  )
}

export function HistoryTable({ items, onDelete, sortBy, sortOrder, onSortChange }: HistoryTableProps) {
  if (items.length === 0) {
    return <p className="py-10 text-center text-sm text-slate-400">No analyses yet. Run one from the Analyzer page.</p>
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="border-b border-gray-200 text-slate-500 dark:border-slate-800 dark:text-slate-400">
          <tr>
            <th className="py-2 pr-4 font-medium">Incident ID</th>
            <SortableHeader label="Timestamp" sortKey="created_at" sortBy={sortBy} sortOrder={sortOrder} onSortChange={onSortChange} />
            <SortableHeader label="Classification" sortKey="classification" sortBy={sortBy} sortOrder={sortOrder} onSortChange={onSortChange} />
            <SortableHeader label="Severity" sortKey="risk_level" sortBy={sortBy} sortOrder={sortOrder} onSortChange={onSortChange} />
            <SortableHeader label="Confidence" sortKey="confidence" sortBy={sortBy} sortOrder={sortOrder} onSortChange={onSortChange} />
            <SortableHeader label="Risk Score" sortKey="risk_score" sortBy={sortBy} sortOrder={sortOrder} onSortChange={onSortChange} />
            <th className="py-2 pr-4 font-medium">Summary</th>
            <th className="py-2 pr-4 text-right font-medium">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100 dark:divide-slate-800">
          {items.map((item) => (
            <tr key={item.id} className="transition-colors hover:bg-gray-50 dark:hover:bg-slate-800/40">
              <td className="py-3 pr-4 font-mono text-xs text-slate-400">{item.id.slice(0, 8)}</td>
              <td className="py-3 pr-4 whitespace-nowrap text-slate-500 dark:text-slate-400">
                {new Date(item.created_at).toLocaleString()}
              </td>
              <td className="py-3 pr-4">
                <ClassificationBadge classification={item.classification} />
              </td>
              <td className="py-3 pr-4">
                <RiskBadge risk={item.risk_level} />
              </td>
              <td className="py-3 pr-4">{item.confidence}%</td>
              <td className="py-3 pr-4">{item.risk_score ?? "—"}</td>
              <td className="max-w-xs truncate py-3 pr-4 text-slate-600 dark:text-slate-300">{item.summary}</td>
              <td className="py-3 pr-4">
                <div className="flex justify-end gap-2">
                  <Link to={`/history/${item.id}`}>
                    <Button variant="ghost" size="icon" aria-label="View">
                      <Eye className="h-4 w-4" />
                    </Button>
                  </Link>
                  <a href={exportHistoryItemUrl(item.id)} target="_blank" rel="noreferrer">
                    <Button variant="ghost" size="icon" aria-label="Download PDF">
                      <Download className="h-4 w-4" />
                    </Button>
                  </a>
                  <Button variant="ghost" size="icon" aria-label="Delete" onClick={() => onDelete(item.id)}>
                    <Trash2 className="h-4 w-4 text-red-500" />
                  </Button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
