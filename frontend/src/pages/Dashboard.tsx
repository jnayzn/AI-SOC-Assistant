import { AlertTriangle, Bug, CalendarClock, Fish, Gauge, Globe2, ListChecks, Percent, ShieldQuestion, Swords, Timer } from "lucide-react"

import { CardSkeleton, StatCardSkeleton } from "@/components/ui/skeleton"

import { ClassificationDistributionChart } from "@/components/ClassificationDistributionChart"
import { MonthlyStatsChart } from "@/components/MonthlyStatsChart"
import { RiskDistributionChart } from "@/components/RiskDistributionChart"
import { StatCard } from "@/components/StatCard"
import { TopListCard } from "@/components/TopListCard"
import { WeeklyStatsChart } from "@/components/WeeklyStatsChart"
import { useStats } from "@/hooks/useStats"

export default function Dashboard() {
  const { stats, isLoading, error } = useStats()

  if (isLoading) {
    return (
      <div className="flex flex-col gap-6">
        <h1 className="text-xl font-bold text-slate-800 dark:text-slate-100">Dashboard</h1>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <StatCardSkeleton key={i} />
          ))}
        </div>
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <CardSkeleton lines={5} />
          <CardSkeleton lines={5} />
        </div>
      </div>
    )
  }
  if (error) return <p className="text-sm text-red-500">{error}</p>
  if (!stats) return null

  return (
    <div className="flex flex-col gap-6">
      <h1 className="text-xl font-bold text-slate-800 dark:text-slate-100">Dashboard</h1>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="Total Analyses" value={stats.total_analyses} icon={ListChecks} accent="text-brand-600" />
        <StatCard
          label="Phishing Detected"
          value={stats.phishing_detected}
          icon={Fish}
          accent="text-orange-500"
          subtitle="By threat category"
        />
        <StatCard
          label="Malware Detected"
          value={stats.malware_detected}
          icon={Bug}
          accent="text-red-500"
          subtitle="By threat category"
        />
        <StatCard
          label="Critical Alerts"
          value={stats.critical_alerts}
          icon={AlertTriangle}
          accent="text-red-600"
          subtitle="By severity"
        />
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <StatCard label="Average Risk Score" value={`${stats.avg_risk_score}/100`} icon={Gauge} accent="text-purple-500" />
        <StatCard label="Average Confidence" value={`${stats.avg_confidence}%`} icon={Percent} accent="text-brand-600" />
      </div>

      {/* SOC health: real-time operational KPIs derived from the same
          Analysis records (today's volume, average triage latency, and the
          detection engine's average false-positive probability). */}
      <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">SOC Health</h2>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatCard
          label="Analyses Today"
          value={stats.analyses_today}
          icon={CalendarClock}
          accent="text-brand-600"
        />
        <StatCard
          label="Avg Triage Latency"
          value={`${(stats.avg_latency_ms / 1000).toFixed(1)}s`}
          icon={Timer}
          accent="text-slate-500"
        />
        <StatCard
          label="False Positive Rate"
          value={`${(stats.false_positive_rate * 100).toFixed(1)}%`}
          icon={ShieldQuestion}
          accent="text-yellow-500"
        />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <RiskDistributionChart data={stats.risk_distribution} />
        <ClassificationDistributionChart data={stats.classification_distribution} />
      </div>

      <WeeklyStatsChart data={stats.weekly_stats} />
      <MonthlyStatsChart data={stats.monthly_stats} />

      {/* Top-N breakdowns: at-a-glance ranking of the most common IOC types,
          source countries, malware families, MITRE techniques, and OWASP
          categories across every analysis on record. */}
      <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
        Top Breakdowns
      </h2>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <TopListCard title="Top IOC Types" icon={ListChecks} items={stats.top_ioc_types} />
        <TopListCard title="Top Source Countries" icon={Globe2} items={stats.top_countries} />
        <TopListCard title="Top Malware Families" icon={Bug} items={stats.top_malware_families} />
      </div>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <TopListCard title="Top MITRE Techniques" icon={Swords} items={stats.top_mitre_techniques} />
        <TopListCard title="Top OWASP Categories" icon={AlertTriangle} items={stats.top_owasp_categories} />
      </div>
    </div>
  )
}
