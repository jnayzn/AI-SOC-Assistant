import { AlertTriangle, ExternalLink, MapPin, ShieldAlert, ShieldCheck, ShieldQuestion } from "lucide-react"

import { ExternalIntelPlaceholder } from "@/components/ExternalIntelPlaceholder"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import type { LocalIocFinding, ThreatIntelEnrichment, ThreatIntelFinding, ThreatIntelVerdict } from "@/types/analysis"

const VERDICT_STYLE: Record<ThreatIntelVerdict, { icon: typeof ShieldCheck; className: string; label: string }> = {
  Malicious: { icon: ShieldAlert, className: "text-red-600 dark:text-red-400", label: "Malicious" },
  Suspicious: { icon: AlertTriangle, className: "text-orange-500 dark:text-orange-400", label: "Suspicious" },
  Harmless: { icon: ShieldCheck, className: "text-green-600 dark:text-green-400", label: "Harmless" },
  Unknown: { icon: ShieldQuestion, className: "text-slate-400 dark:text-slate-500", label: "Unknown" },
}

function FindingRow({ finding }: { finding: ThreatIntelFinding }) {
  const style = VERDICT_STYLE[finding.verdict] ?? VERDICT_STYLE.Unknown
  const Icon = style.icon
  const metaParts = [
    finding.country,
    finding.asn,
    finding.malware_family ? `Family: ${finding.malware_family}` : null,
    finding.blacklist_count != null ? `${finding.blacklist_count} blacklist hit(s)` : null,
    finding.reverse_dns,
    finding.last_seen ? `Last seen ${finding.last_seen}` : null,
  ].filter(Boolean)
  return (
    <div className="flex items-start justify-between gap-3 border-b border-slate-100 py-2 last:border-b-0 dark:border-slate-800">
      <div className="flex min-w-0 items-start gap-2">
        <Icon className={`mt-0.5 h-4 w-4 shrink-0 ${style.className}`} />
        <div className="min-w-0">
          <p className="truncate text-xs font-medium text-slate-700 dark:text-slate-200" title={finding.indicator}>
            {finding.indicator}
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            {finding.error ? finding.error : finding.summary}
          </p>
          {metaParts.length > 0 && (
            <p className="mt-0.5 flex items-center gap-1 text-[11px] text-slate-400 dark:text-slate-500">
              <MapPin className="h-3 w-3 shrink-0" />
              {metaParts.join(" \u00b7 ")}
            </p>
          )}
        </div>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        <span className={`text-xs font-semibold ${style.className}`}>{style.label}</span>
        {finding.detail_url && (
          <a href={finding.detail_url} target="_blank" rel="noreferrer" className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">
            <ExternalLink className="h-3.5 w-3.5" />
          </a>
        )}
      </div>
    </div>
  )
}

function LocalFindingRow({ finding }: { finding: LocalIocFinding }) {
  return (
    <div className="flex items-start justify-between gap-3 border-b border-slate-100 py-2 last:border-b-0 dark:border-slate-800">
      <div className="min-w-0">
        <p className="truncate text-xs font-medium text-slate-700 dark:text-slate-200" title={finding.indicator}>
          {finding.indicator}
          <span className="ml-1.5 rounded bg-slate-100 px-1.5 py-0.5 text-[10px] uppercase text-slate-500 dark:bg-slate-800 dark:text-slate-400">
            {finding.indicator_type}
          </span>
        </p>
        <p className="text-xs text-slate-500 dark:text-slate-400">{finding.notes.join(" \u00b7 ")}</p>
      </div>
      <div className="shrink-0 text-right">
        <p className="text-xs font-semibold text-slate-600 dark:text-slate-300">{finding.risk_level}</p>
        <p className="text-[11px] text-slate-400 dark:text-slate-500">Score {finding.threat_score}</p>
      </div>
    </div>
  )
}

function SourceCard({
  name,
  configured,
  findings,
}: {
  name: "VirusTotal" | "Shodan" | "AbuseIPDB"
  configured: boolean
  findings: ThreatIntelFinding[]
}) {
  if (!configured) {
    return <ExternalIntelPlaceholder name={name} />
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm text-slate-700 dark:text-slate-200">{name}</CardTitle>
      </CardHeader>
      <CardContent>
        {findings.length > 0 ? (
          <div className="flex flex-col">
            {findings.map((finding) => (
              <FindingRow key={`${finding.source}-${finding.indicator}`} finding={finding} />
            ))}
          </div>
        ) : (
          <p className="text-xs text-slate-400 dark:text-slate-500">
            No matching indicators were found in this analysis to look up.
          </p>
        )}
      </CardContent>
    </Card>
  )
}

export function ThreatIntelPanel({ threatIntel }: { threatIntel?: ThreatIntelEnrichment | null }) {
  const virustotalConfigured = threatIntel?.virustotal_configured ?? false
  const shodanConfigured = threatIntel?.shodan_configured ?? false
  const abuseipdbConfigured = threatIntel?.abuseipdb_configured ?? false
  const findings = threatIntel?.findings ?? []

  const virustotalFindings = findings.filter((f) => f.source === "VirusTotal")
  const shodanFindings = findings.filter((f) => f.source === "Shodan")
  const abuseipdbFindings = findings.filter((f) => f.source === "AbuseIPDB")

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
      <SourceCard name="VirusTotal" configured={virustotalConfigured} findings={virustotalFindings} />
      <SourceCard name="Shodan" configured={shodanConfigured} findings={shodanFindings} />
      <SourceCard name="AbuseIPDB" configured={abuseipdbConfigured} findings={abuseipdbFindings} />
    </div>
  )
}

// Local Analysis is exported separately so the Threat Intelligence layout can
// place it as the very last section, after the IntelOwl panel. Business logic
// and data are unchanged — only its position in the DOM moved.
export function LocalAnalysisPanel({ threatIntel }: { threatIntel?: ThreatIntelEnrichment | null }) {
  const localFindings = threatIntel?.local_findings ?? []
  if (localFindings.length === 0) return null

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm text-slate-700 dark:text-slate-200">Local Analysis (always-on fallback)</CardTitle>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          Zero-dependency heuristics computed for every IOC, independent of external API keys.
        </p>
      </CardHeader>
      <CardContent>
        <div className="flex flex-col">
          {localFindings.map((finding) => (
            <LocalFindingRow key={`${finding.indicator_type}-${finding.indicator}`} finding={finding} />
          ))}
        </div>
      </CardContent>
    </Card>
  )
}
