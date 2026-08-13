import { Download, Gauge as GaugeIcon, Timer } from "lucide-react"

import { AttackTimeline } from "@/components/AttackTimeline"
import { ClassificationBadge } from "@/components/ClassificationBadge"
import { DetectionMetricsGauges } from "@/components/DetectionMetricsGauges"
import { ExplainableAICard } from "@/components/ExplainableAICard"
import { IOCTable } from "@/components/IOCTable"
import { PlaybookActions } from "@/components/PlaybookActions"
import { LocalAnalysisPanel, ThreatIntelPanel } from "@/components/ThreatIntelPanel"
import { IntelOwlResults } from "@/components/IntelOwlResults"
import { MitreMatrix } from "@/components/MitreMatrix"
import { MitrePlaybooksPanel } from "@/components/MitrePlaybooksPanel"
import { OwaspMappingCard } from "@/components/OwaspMappingCard"
import { RecommendedActions } from "@/components/RecommendedActions"
import { RiskBadge } from "@/components/RiskBadge"
import { SigmaRuleMatch } from "@/components/SigmaRuleMatch"
import { ThreatTags } from "@/components/ThreatTags"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { ProgressBar } from "@/components/ui/progress"
import { exportHistoryItemUrl } from "@/services/api"
import type { AnalysisResponse } from "@/types/analysis"

const RISK_SCORE_COLOR: Record<string, string> = {
  Low: "bg-green-500",
  Medium: "bg-yellow-500",
  High: "bg-orange-500",
  Critical: "bg-red-500",
}

export function AnalysisResult({ result }: { result: AnalysisResponse }) {
  const hasIocs =
    result.iocs.ips.length ||
    result.iocs.domains.length ||
    result.iocs.urls.length ||
    result.iocs.emails.length ||
    result.iocs.hashes.length

  const riskScore = result.risk_score ?? undefined
  const durationSeconds = (result.latency_ms / 1000).toFixed(1)
  const topIndicators = result.indicators.slice(0, 6)

  return (
    <div className="flex flex-col gap-6">
      {/* Section B: Primary verdict - full width, high-level at-a-glance summary */}
      <Card className="border-brand-100 dark:border-brand-900/40">
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle>Analysis Verdict</CardTitle>
          <a href={exportHistoryItemUrl(result.id)} target="_blank" rel="noreferrer">
            <Button variant="outline" size="sm">
              <Download className="h-4 w-4" /> Export PDF
            </Button>
          </a>
        </CardHeader>
        <CardContent className="flex flex-col gap-5">
          <div className="flex flex-wrap items-center gap-5">
            <div>
              <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-slate-400 dark:text-slate-500">
                Verdict
              </p>
              <ClassificationBadge classification={result.classification} />
            </div>
            <div>
              <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-slate-400 dark:text-slate-500">
                Severity
              </p>
              <RiskBadge risk={result.risk_level} />
            </div>
            <span className="flex items-center gap-1 text-sm text-slate-500 dark:text-slate-400">
              <Timer className="h-3.5 w-3.5" /> {durationSeconds}s
            </span>
            <span className="text-sm text-slate-400">&middot; {result.model_used}</span>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {riskScore !== undefined && (
              <div className="lg:col-span-2">
                <div className="mb-1 flex items-center justify-between text-xs font-medium text-slate-500 dark:text-slate-400">
                  <span className="flex items-center gap-1">
                    <GaugeIcon className="h-3.5 w-3.5" /> Risk Score
                  </span>
                  <span>{riskScore}/100</span>
                </div>
                <ProgressBar value={riskScore} colorClassName={RISK_SCORE_COLOR[result.risk_level]} />
              </div>
            )}
            <div className="lg:col-span-2">
              <div className="mb-1 flex items-center justify-between text-xs font-medium text-slate-500 dark:text-slate-400">
                <span>Confidence</span>
                <span>{result.confidence}%</span>
              </div>
              <ProgressBar value={result.confidence} colorClassName="bg-brand-500" />
            </div>
          </div>

          {result.threat_tags && result.threat_tags.length > 0 && (
            <div>
              <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-slate-400 dark:text-slate-500">
                Threat Category
              </p>
              <ThreatTags tags={result.threat_tags} />
            </div>
          )}

          <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
            <section className="lg:col-span-2">
              <h4 className="mb-1 text-sm font-semibold text-slate-700 dark:text-slate-200">Executive Summary</h4>
              <p className="text-sm text-slate-600 dark:text-slate-300">{result.summary}</p>
            </section>

            {topIndicators.length > 0 && (
              <section>
                <h4 className="mb-1 text-sm font-semibold text-slate-700 dark:text-slate-200">Key Indicators</h4>
                <ul className="list-inside list-disc text-sm text-slate-600 dark:text-slate-300">
                  {topIndicators.map((i) => (
                    <li key={i}>{i}</li>
                  ))}
                </ul>
              </section>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Section C: detailed analysis - full width dashboard grid */}
      <div className="flex flex-col gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Detailed Explanation</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="whitespace-pre-line text-sm text-slate-600 dark:text-slate-300">{result.explanation}</p>
          </CardContent>
        </Card>

        {(result.explainability?.length ?? 0) > 0 || (result.owasp_mappings?.length ?? 0) > 0 ? (
          <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
            {result.explainability && result.explainability.length > 0 && (
              <ExplainableAICard
                items={result.explainability}
                owaspMappings={result.owasp_mappings}
                riskFactors={result.risk_factors}
                knowledgeSources={result.knowledge_sources}
              />
            )}
            <OwaspMappingCard mappings={result.owasp_mappings ?? []} />
          </div>
        ) : null}

        {(result.mitre_details?.length ?? 0) > 0 && <MitreMatrix detectedTechniques={result.mitre_details ?? []} />}
        {(result.mitre_details?.length ?? 0) > 0 && <MitrePlaybooksPanel techniques={result.mitre_details ?? []} />}

        {result.playbook_actions && result.playbook_actions.length > 0 && (
          <PlaybookActions actions={result.playbook_actions} />
        )}

        {(result.attack_timeline?.length ?? 0) > 0 ||
        result.recommendations_grouped ||
        result.recommendations.length > 0 ? (
          <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
            {result.attack_timeline && result.attack_timeline.length > 0 && (
              <AttackTimeline steps={result.attack_timeline} />
            )}
            <RecommendedActions grouped={result.recommendations_grouped} fallbackFlat={result.recommendations} />
          </div>
        ) : null}

        {result.sigma_match || result.detection_metrics ? (
          <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
            <SigmaRuleMatch sigma={result.sigma_match} />
            <DetectionMetricsGauges metrics={result.detection_metrics} />
          </div>
        ) : null}

        {!!hasIocs && <IOCTable iocs={result.iocs} />}

        <div>
          <h3 className="mb-3 text-sm font-semibold text-slate-700 dark:text-slate-200">Threat Intelligence</h3>
          <div className="flex flex-col gap-4">
            <ThreatIntelPanel threatIntel={result.threat_intel} />
            <IntelOwlResults analysisId={result.id} />
            <LocalAnalysisPanel threatIntel={result.threat_intel} />
          </div>
        </div>
      </div>
    </div>
  )
}
