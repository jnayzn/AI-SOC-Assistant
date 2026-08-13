import { ShieldAlert, ShieldCheck } from "lucide-react"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import type { SigmaMatch } from "@/types/analysis"

export function SigmaRuleMatch({ sigma }: { sigma: SigmaMatch | null | undefined }) {
  if (!sigma) return null
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          {sigma.matched ? (
            <ShieldAlert className="h-4 w-4 text-red-500" />
          ) : (
            <ShieldCheck className="h-4 w-4 text-green-500" />
          )}
          Sigma Rule Match
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-2">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-slate-700 dark:text-slate-200">{sigma.rule_name}</span>
          <Badge
            className={
              sigma.matched
                ? "bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300"
                : "bg-gray-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400"
            }
          >
            {sigma.matched ? "Matched" : "No Match"}
          </Badge>
        </div>
        {sigma.matched_indicators.length > 0 && (
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Matched keywords: {sigma.matched_indicators.join(", ")}
          </p>
        )}
      </CardContent>
    </Card>
  )
}
