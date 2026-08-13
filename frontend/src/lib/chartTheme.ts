// Shared Recharts styling helpers so tooltips/legends follow the app's
// light/dark theme instead of the library's hardcoded white defaults.
// Recharts renders these as plain DOM nodes (not a portal), so CSS custom
// properties defined on `:root` / `.dark` in index.css cascade correctly.
export const chartTooltipContentStyle: React.CSSProperties = {
  backgroundColor: "var(--chart-tooltip-bg)",
  borderColor: "var(--chart-tooltip-border)",
  borderRadius: 8,
  boxShadow: "0 4px 12px rgba(0,0,0,0.12)",
  fontSize: 12,
}

export const chartTooltipLabelStyle: React.CSSProperties = {
  color: "var(--chart-tooltip-text)",
  fontWeight: 600,
  marginBottom: 4,
}

export const chartTooltipItemStyle: React.CSSProperties = {
  color: "var(--chart-tooltip-text)",
}

export const chartLegendWrapperStyle: React.CSSProperties = {
  color: "var(--chart-legend-text)",
  fontSize: 12,
}
