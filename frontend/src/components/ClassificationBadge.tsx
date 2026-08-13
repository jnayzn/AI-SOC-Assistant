import { cn } from "@/lib/utils"
import { Badge } from "@/components/ui/badge"
import type { ThreatClassification } from "@/types/analysis"

const CLASSIFICATION_STYLES: Record<ThreatClassification, string> = {
  Benign: "bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300",
  Spam: "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300",
  Suspicious: "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-300",
  Phishing: "bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300",
  Malware: "bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300",
  "Credential Theft": "bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300",
  "Business Email Compromise": "bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300",
  "Data Exfiltration": "bg-red-200 text-red-800 dark:bg-red-900/60 dark:text-red-200",
  Unknown: "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300",
}

export function ClassificationBadge({
  classification,
  className,
}: {
  classification: ThreatClassification
  className?: string
}) {
  return <Badge className={cn(CLASSIFICATION_STYLES[classification], className)}>{classification}</Badge>
}
