export type ThreatClassification =
  | "Benign"
  | "Spam"
  | "Suspicious"
  | "Phishing"
  | "Malware"
  | "Credential Theft"
  | "Business Email Compromise"
  | "Data Exfiltration"
  | "Unknown"

export type RiskLevel = "Low" | "Medium" | "High" | "Critical"

export interface IOCResult {
  ips: string[]
  domains: string[]
  urls: string[]
  emails: string[]
  hashes: string[]
}

export interface MitreTechniqueDetail {
  id: string
  name: string
  tactic_id: string
  tactic_name: string
  description: string
}

export interface MitreMatrixTactic {
  id: string
  name: string
  techniques: MitreTechniqueDetail[]
}

export interface MitreMatrixResponse {
  tactics: MitreMatrixTactic[]
}

export interface ExplainabilityItem {
  label: string
  matched: boolean
}

export interface RecommendationsGrouped {
  immediate: string[]
  investigate: string[]
  contain: string[]
  recover: string[]
}

export interface SigmaMatch {
  rule_name: string
  matched: boolean
  matched_indicators: string[]
}

export interface DetectionMetrics {
  detection_confidence: number
  malicious_probability: number
  suspicious_probability: number
  false_positive_probability: number
}

export type ThreatIntelVerdict = "Malicious" | "Suspicious" | "Harmless" | "Unknown"

export interface ThreatIntelFinding {
  source: "VirusTotal" | "Shodan" | "AbuseIPDB"
  indicator: string
  indicator_type: "ip" | "domain" | "url" | "hash"
  verdict: ThreatIntelVerdict
  summary: string
  detail_url?: string | null
  malicious_engines?: number | null
  total_engines?: number | null
  error?: string | null
  checked_at: string
  from_cache?: boolean
  country?: string | null
  asn?: string | null
  reverse_dns?: string | null
  malware_family?: string | null
  blacklist_count?: number | null
  first_seen?: string | null
  last_seen?: string | null
}

export interface LocalIocFinding {
  indicator: string
  indicator_type: "ip" | "domain" | "url" | "hash" | "email"
  risk_level: RiskLevel
  threat_score: number
  confidence: number
  ip_class?: string | null
  tld?: string | null
  hash_algorithm?: string | null
  notes: string[]
}

export interface ThreatIntelEnrichment {
  virustotal_configured: boolean
  shodan_configured: boolean
  abuseipdb_configured: boolean
  findings: ThreatIntelFinding[]
  local_findings: LocalIocFinding[]
}

export interface OwaspMapping {
  id: string
  name: string
  reason: string
}

export interface PlaybookAction {
  // The backend serializes the action name as `action`; `title`/`description`
  // are kept optional for backward compatibility with earlier frontend code.
  action?: string
  title?: string
  description?: string
  priority: "Critical" | "High" | "Medium" | "Low"
  category: string
}

export interface AnalysisResponse {
  id: string
  input_text: string
  input_type: string
  classification: ThreatClassification
  risk_level: RiskLevel
  confidence: number
  summary: string
  explanation: string
  recommendations: string[]
  indicators: string[]
  mitre_techniques: string[]
  iocs: IOCResult
  model_used: string
  latency_ms: number
  created_at: string

  // Analyzer-page enrichment (may be null/undefined for older records)
  risk_score?: number | null
  threat_tags?: string[] | null
  mitre_details?: MitreTechniqueDetail[] | null
  attack_timeline?: string[] | null
  explainability?: ExplainabilityItem[] | null
  recommendations_grouped?: RecommendationsGrouped | null
  sigma_match?: SigmaMatch | null
  detection_metrics?: DetectionMetrics | null
  threat_intel?: ThreatIntelEnrichment | null
  owasp_mappings?: OwaspMapping[] | null
  risk_factors?: string[] | null
  knowledge_sources?: string[] | null
  playbook_actions?: PlaybookAction[] | null
}

export interface AnalysisListItem {
  id: string
  input_type: string
  classification: ThreatClassification
  risk_level: RiskLevel
  confidence: number
  summary: string
  created_at: string
  risk_score?: number | null
}

export interface PaginatedAnalyses {
  total: number
  page: number
  page_size: number
  items: AnalysisListItem[]
}

export interface RiskDistributionItem {
  risk_level: string
  count: number
}

export interface ClassificationDistributionItem {
  classification: string
  count: number
}

export interface WeeklyStatItem {
  date: string
  total: number
  phishing: number
  malware: number
  critical: number
}

export interface MonthlyStatItem {
  month: string
  total: number
  phishing: number
  malware: number
  critical: number
}

export interface TopItem {
  label: string
  count: number
}

export interface StatsResponse {
  total_analyses: number
  phishing_detected: number
  malware_detected: number
  critical_alerts: number
  avg_risk_score: number
  avg_confidence: number
  risk_distribution: RiskDistributionItem[]
  classification_distribution: ClassificationDistributionItem[]
  weekly_stats: WeeklyStatItem[]
  analyses_today: number
  avg_latency_ms: number
  false_positive_rate: number
  monthly_stats: MonthlyStatItem[]
  top_ioc_types: TopItem[]
  top_countries: TopItem[]
  top_malware_families: TopItem[]
  top_mitre_techniques: TopItem[]
  top_owasp_categories: TopItem[]
}

export interface AnalyzeRequest {
  content: string
  input_type?: string
}

export interface CopilotChatMessage {
  role: "user" | "assistant"
  content: string
}

/** Structured snapshot of the analysis currently on screen, sent to the
 * copilot so it can ground its answer in the actual incident. Mirrors the
 * fields called out in the SOC Copilot spec. All optional so it degrades
 * gracefully for older records that lack enrichment. */
export interface CopilotIncidentContext {
  analysisId?: string | null
  verdict?: string | null
  severity?: string | null
  riskScore?: number | null
  confidence?: number | null
  threatCategories?: string[] | null
  executiveSummary?: string | null
  detailedExplanation?: string | null
  keyIndicators?: string[] | null
  explainableSignals?: string[] | null
  mitreTechniques?: string[] | null
  iocs?: IOCResult | null
  originalContent?: string | null
  sender?: string | null
  urls?: string[] | null
  domains?: string[] | null
}

export interface CopilotChatRequest {
  message: string
  history: CopilotChatMessage[]
  analysis_id?: string | null
  incident_context?: CopilotIncidentContext | null
}

export interface CopilotChatResponse {
  reply: string
  grounded_in_analysis_id?: string | null
}

export interface HistoryQueryParams {
  page?: number
  page_size?: number
  classification?: string
  risk_level?: string
  search?: string
  sort_by?: "created_at" | "confidence" | "risk_score" | "classification" | "risk_level"
  sort_order?: "asc" | "desc"
}
