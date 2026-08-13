import { useState } from "react"
import { Check, Copy } from "lucide-react"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import type { IOCResult } from "@/types/analysis"

type Row = { type: string; value: string }

function toRows(iocs: IOCResult): Row[] {
  return [
    ...iocs.ips.map((value) => ({ type: "IP Address", value })),
    ...iocs.domains.map((value) => ({ type: "Domain", value })),
    ...iocs.urls.map((value) => ({ type: "URL", value })),
    ...iocs.emails.map((value) => ({ type: "Email", value })),
    ...iocs.hashes.map((value) => ({ type: "Hash", value })),
  ]
}

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <Button
      variant="ghost"
      size="icon"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value)
          setCopied(true)
          setTimeout(() => setCopied(false), 1500)
        } catch {
          // clipboard unavailable, ignore silently
        }
      }}
      aria-label={`Copy ${value}`}
    >
      {copied ? <Check className="h-4 w-4 text-green-600" /> : <Copy className="h-4 w-4" />}
    </Button>
  )
}

export function IOCTable({ iocs }: { iocs: IOCResult }) {
  const rows = toRows(iocs)
  if (!rows.length) return null

  return (
    <Card>
      <CardHeader>
        <CardTitle>Extracted Indicators of Compromise (IOCs)</CardTitle>
      </CardHeader>
      <CardContent className="overflow-x-auto">
        <table className="w-full min-w-[480px] border-collapse text-sm">
          <thead>
            <tr className="border-b border-gray-100 text-left text-xs uppercase tracking-wide text-slate-400 dark:border-slate-800">
              <th className="py-2 pr-3 font-medium">Type</th>
              <th className="py-2 pr-3 font-medium">Value</th>
              <th className="py-2 pr-3 font-medium">Reputation</th>
              <th className="py-2 font-medium">Copy</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr
                key={`${row.type}-${row.value}`}
                className="border-b border-gray-50 last:border-0 dark:border-slate-800/60"
              >
                <td className="py-2 pr-3 text-slate-500 dark:text-slate-400">{row.type}</td>
                <td className="break-all py-2 pr-3 font-mono text-xs text-slate-700 dark:text-slate-200">
                  {row.value}
                </td>
                <td className="py-2 pr-3">
                  <span className="rounded-full bg-gray-100 px-2 py-0.5 text-xs text-slate-500 dark:bg-slate-800 dark:text-slate-400">
                    Unknown
                  </span>
                </td>
                <td className="py-2">
                  <CopyButton value={row.value} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </CardContent>
    </Card>
  )
}
