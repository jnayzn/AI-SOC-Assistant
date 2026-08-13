import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { chartTooltipContentStyle, chartTooltipItemStyle, chartTooltipLabelStyle } from "@/lib/chartTheme"
import type { RiskDistributionItem } from "@/types/analysis"

const COLORS: Record<string, string> = {
  Low: "#16a34a",
  Medium: "#ca8a04",
  High: "#ea580c",
  Critical: "#dc2626",
}

export function RiskDistributionChart({ data }: { data: RiskDistributionItem[] }) {
  const chartData = data.map((d) => ({ name: d.risk_level, value: d.count }))

  return (
    <Card>
      <CardHeader>
        <CardTitle>Risk Distribution</CardTitle>
      </CardHeader>
      <CardContent className="h-72">
        {chartData.length === 0 ? (
          <p className="text-sm text-slate-400">No data yet. Run an analysis to populate this chart.</p>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie data={chartData} dataKey="value" nameKey="name" innerRadius={55} outerRadius={90} paddingAngle={3}>
                {chartData.map((entry) => (
                  <Cell key={entry.name} fill={COLORS[entry.name] || "#64748b"} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={chartTooltipContentStyle}
                labelStyle={chartTooltipLabelStyle}
                itemStyle={chartTooltipItemStyle}
              />
            </PieChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  )
}
