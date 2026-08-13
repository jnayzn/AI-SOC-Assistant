import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import {
  chartLegendWrapperStyle,
  chartTooltipContentStyle,
  chartTooltipItemStyle,
  chartTooltipLabelStyle,
} from "@/lib/chartTheme"
import type { WeeklyStatItem } from "@/types/analysis"

export function WeeklyStatsChart({ data }: { data: WeeklyStatItem[] }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Weekly Statistics</CardTitle>
      </CardHeader>
      <CardContent className="h-72">
        {data.length === 0 ? (
          <p className="text-sm text-slate-400">No data yet. Run an analysis to populate this chart.</p>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data}>
              <CartesianGrid strokeDasharray="3 3" className="stroke-gray-200 dark:stroke-slate-800" />
              <XAxis dataKey="date" fontSize={12} />
              <YAxis fontSize={12} allowDecimals={false} />
              <Tooltip
                contentStyle={chartTooltipContentStyle}
                labelStyle={chartTooltipLabelStyle}
                itemStyle={chartTooltipItemStyle}
                cursor={{ fill: "var(--chart-tooltip-border)", opacity: 0.3 }}
              />
              <Legend wrapperStyle={chartLegendWrapperStyle} />
              <Bar dataKey="total" fill="#3b82f6" name="Total" radius={[4, 4, 0, 0]} />
              <Bar dataKey="phishing" fill="#ea580c" name="Phishing" radius={[4, 4, 0, 0]} />
              <Bar dataKey="malware" fill="#dc2626" name="Malware" radius={[4, 4, 0, 0]} />
              <Bar dataKey="critical" fill="#7f1d1d" name="Critical" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  )
}
