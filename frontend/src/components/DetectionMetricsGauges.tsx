import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import type { DetectionMetrics } from "@/types/analysis"

function Gauge({ label, value, colorClassName }: { label: string; value: number; colorClassName: string }) {
  const radius = 34
  const circumference = 2 * Math.PI * radius
  const pct = Math.max(0, Math.min(100, value))
  const offset = circumference - (pct / 100) * circumference

  return (
    <div className="flex flex-col items-center gap-2">
      <svg width="88" height="88" viewBox="0 0 88 88" className="-rotate-90">
        <circle cx="44" cy="44" r={radius} strokeWidth="8" className="fill-none stroke-gray-100 dark:stroke-slate-800" />
        <circle
          cx="44"
          cy="44"
          r={radius}
          strokeWidth="8"
          strokeLinecap="round"
          className={`fill-none ${colorClassName} transition-all duration-700`}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
        />
      </svg>
      <div className="-mt-14 text-center">
        <span className="text-lg font-bold text-slate-800 dark:text-slate-100">{pct}%</span>
      </div>
      <span className="mt-8 text-center text-xs text-slate-500 dark:text-slate-400">{label}</span>
    </div>
  )
}

export function DetectionMetricsGauges({ metrics }: { metrics: DetectionMetrics | null | undefined }) {
  if (!metrics) return null
  return (
    <Card>
      <CardHeader>
        <CardTitle>Detection Metrics</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex flex-wrap justify-around gap-4">
          <Gauge label="Detection Confidence" value={metrics.detection_confidence} colorClassName="stroke-brand-500" />
          <Gauge label="Malicious Probability" value={metrics.malicious_probability} colorClassName="stroke-red-500" />
          <Gauge label="Suspicious Probability" value={metrics.suspicious_probability} colorClassName="stroke-yellow-500" />
          <Gauge
            label="False Positive Probability"
            value={metrics.false_positive_probability}
            colorClassName="stroke-green-500"
          />
        </div>
      </CardContent>
    </Card>
  )
}
