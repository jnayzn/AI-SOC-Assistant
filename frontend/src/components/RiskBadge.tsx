import { cn } from "@/lib/utils"
import { Badge } from "@/components/ui/badge"
import type { RiskLevel } from "@/types/analysis"

const RISK_STYLES: Record<RiskLevel, string> = {
  Low: "bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300",
  Medium: "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-300",
  High: "bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300",
  Critical: "bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300",
}

export function RiskBadge({ risk, className }: { risk: RiskLevel; className?: string }) {
  return <Badge className={cn(RISK_STYLES[risk], className)}>{risk}</Badge>
}
