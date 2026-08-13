// IntelOwl threat-intelligence types. Mirror of backend app/schemas/intelowl.py.
export type IntelOwlObservableType = "ip" | "domain" | "url" | "hash" | "generic"
export type IntelOwlStatus = "PENDING" | "RUNNING" | "COMPLETED" | "FAILED" | "TIMEOUT"
export type IntelOwlVerdict = "malicious" | "suspicious" | "clean" | "unknown"

export interface IntelOwlAnalyzerResult {
  name: string
  status: string
  summary?: string | null
}

export interface IntelOwlReputation {
  score?: number | null
  classification: string
}

export interface IntelOwlNormalizedResult {
  observable: string
  type: string
  status: IntelOwlStatus
  verdict: IntelOwlVerdict
  reputation: IntelOwlReputation
  analyzers: IntelOwlAnalyzerResult[]
  connectors: IntelOwlAnalyzerResult[]
  threat_intelligence: Record<string, unknown>[]
  dns: Record<string, unknown>
  whois: Record<string, unknown>
  reputation_sources: string[]
  job_id?: string | null
  job_url?: string | null
  raw_result: Record<string, unknown>
}

export interface IntelOwlScanRequest {
  observable: string
  observable_type: IntelOwlObservableType
  tlp?: string
  analysis_id?: string | null
  playbook?: string | null
  force?: boolean
}

export interface IntelOwlScanResponse {
  job_id?: string | null
  status: IntelOwlStatus
  observable: string
  observable_type: string
  scan_id: string
  verdict?: string | null
  cached: boolean
  analysis_id?: string | null
}

export interface IntelOwlScanRecord {
  id: string
  analysis_id?: string | null
  observable: string
  observable_type: string
  intelowl_job_id?: string | null
  status: IntelOwlStatus
  verdict?: IntelOwlVerdict | null
  analyzers?: IntelOwlAnalyzerResult[] | null
  connectors?: IntelOwlAnalyzerResult[] | null
  normalized_result?: IntelOwlNormalizedResult | null
  raw_result?: Record<string, unknown> | null
  error?: string | null
  created_at: string
  completed_at?: string | null
}

export interface IntelOwlBulkScanResponse {
  analysis_id: string
  total_iocs: number
  launched: IntelOwlScanResponse[]
}

export interface IntelOwlHealth {
  configured: boolean
  reachable: boolean
  authenticated: boolean
  url?: string | null
  detail?: string | null
}
