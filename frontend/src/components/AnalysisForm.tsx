import { FormEvent, useState } from "react"
import { Loader2, ScanSearch } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"

const INPUT_TYPES = [
  { value: "email", label: "Phishing Email" },
  { value: "soc_alert", label: "SOC Alert" },
  { value: "windows_log", label: "Windows Event Log" },
  { value: "linux_log", label: "Linux Log" },
  { value: "other", label: "Other Security Text" },
]

export function AnalysisForm({
  onSubmit,
  isLoading,
}: {
  onSubmit: (content: string, inputType: string) => void
  isLoading: boolean
}) {
  const [content, setContent] = useState("")
  const [inputType, setInputType] = useState("email")

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!content.trim()) return
    onSubmit(content, inputType)
  }

  return (
    <Card>
      <CardContent className="p-5">
        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-end">
            <div className="w-full sm:w-64">
              <label className="mb-1 block text-sm font-medium text-slate-600 dark:text-slate-300">
                Content type
              </label>
              <select
                value={inputType}
                onChange={(e) => setInputType(e.target.value)}
                className="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-800"
              >
                {INPUT_TYPES.map((t) => (
                  <option key={t.value} value={t.value}>
                    {t.label}
                  </option>
                ))}
              </select>
            </div>
            <Button type="submit" disabled={isLoading || !content.trim()} className="w-full sm:w-auto">
              {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <ScanSearch className="h-4 w-4" />}
              {isLoading ? "Analyzing..." : "Analyze"}
            </Button>
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-600 dark:text-slate-300">
              Paste a phishing email, SOC alert, or log entry
            </label>
            <textarea
              value={content}
              onChange={(e) => setContent(e.target.value)}
              rows={6}
              placeholder="Paste raw email headers/body, alert JSON, or log lines here..."
              className="w-full resize-y rounded-lg border border-gray-300 bg-white px-3 py-2 font-mono text-sm dark:border-slate-700 dark:bg-slate-800"
            />
          </div>
        </form>
      </CardContent>
    </Card>
  )
}
