import { cn } from "@/lib/utils"

interface ProgressBarProps {
  value: number
  max?: number
  colorClassName?: string
  trackClassName?: string
  className?: string
}

export function ProgressBar({
  value,
  max = 100,
  colorClassName = "bg-brand-500",
  trackClassName = "bg-gray-100 dark:bg-slate-800",
  className,
}: ProgressBarProps) {
  const pct = Math.max(0, Math.min(100, (value / max) * 100))
  return (
    <div className={cn("h-2 w-full overflow-hidden rounded-full", trackClassName, className)}>
      <div
        className={cn("h-full rounded-full transition-all duration-500", colorClassName)}
        style={{ width: `${pct}%` }}
        role="progressbar"
        aria-valuenow={value}
        aria-valuemin={0}
        aria-valuemax={max}
      />
    </div>
  )
}
