import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { chartTooltipContentStyle, chartTooltipItemStyle, chartTooltipLabelStyle } from "@/lib/chartTheme"
import type { ClassificationDistributionItem } from "@/types/analysis"

export function ClassificationDistributionChart({ data }: { data: ClassificationDistributionItem[] }) {
  const chartData = data.map((d) => ({ name: d.classification, value: d.count }))

  return (
    <Card>
      <CardHeader>
        <CardTitle>Classification Breakdown</CardTitle>
      </CardHeader>
      <CardContent className="h-72">
        {chartData.length === 0 ? (
          <p className="text-sm text-slate-400">No data yet. Run an analysis to populate this chart.</p>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData} layout="vertical" margin={{ left: 24 }}>
              <CartesianGrid strokeDasharray="3 3" className="stroke-gray-200 dark:stroke-slate-800" />
              <XAxis type="number" fontSize={12} allowDecimals={false} />
              <YAxis type="category" dataKey="name" fontSize={12} width={140} />
              <Tooltip
                contentStyle={chartTooltipContentStyle}
                labelStyle={chartTooltipLabelStyle}
                itemStyle={chartTooltipItemStyle}
                cursor={{ fill: "var(--chart-tooltip-border)", opacity: 0.3 }}
              />
              <Bar dataKey="value" fill="#3b82f6" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  )
}
