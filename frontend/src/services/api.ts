import axios from "axios"

import type {
  AnalysisResponse,
  AnalyzeRequest,
  CopilotChatRequest,
  CopilotChatResponse,
  HistoryQueryParams,
  MitreMatrixResponse,
  PaginatedAnalyses,
  StatsResponse,
} from "@/types/analysis"

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000/api/v1"

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 120000,
})

apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem("access_token")
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

export async function analyzeContent(payload: AnalyzeRequest): Promise<AnalysisResponse> {
  const { data } = await apiClient.post<AnalysisResponse>("/analyze", payload)
  return data
}

export async function fetchHistory(params: HistoryQueryParams): Promise<PaginatedAnalyses> {
  const { data } = await apiClient.get<PaginatedAnalyses>("/history", { params })
  return data
}

export async function fetchHistoryItem(id: string): Promise<AnalysisResponse> {
  const { data } = await apiClient.get<AnalysisResponse>(`/history/${id}`)
  return data
}

export async function deleteHistoryItem(id: string): Promise<void> {
  await apiClient.delete(`/history/${id}`)
}

export function exportHistoryItemUrl(id: string): string {
  return `${API_BASE_URL}/history/${id}/export`
}

function _historyExportQuery(
  params: Omit<HistoryQueryParams, "page" | "page_size" | "sort_by" | "sort_order">,
): string {
  const query = new URLSearchParams()
  if (params.classification) query.set("classification", params.classification)
  if (params.risk_level) query.set("risk_level", params.risk_level)
  if (params.search) query.set("search", params.search)
  const qs = query.toString()
  return qs ? `?${qs}` : ""
}

export function exportHistoryCsvUrl(params: Omit<HistoryQueryParams, "page" | "page_size" | "sort_by" | "sort_order">): string {
  return `${API_BASE_URL}/history/export/csv${_historyExportQuery(params)}`
}

// Real XLSX export (proper column widths, date/number formatting, frozen
// header) -- use this instead of CSV when the sheet needs to look correct
// when opened directly in Excel.
export function exportHistoryXlsxUrl(
  params: Omit<HistoryQueryParams, "page" | "page_size" | "sort_by" | "sort_order">,
): string {
  return `${API_BASE_URL}/history/export/xlsx${_historyExportQuery(params)}`
}

export async function fetchStats(): Promise<StatsResponse> {
  const { data } = await apiClient.get<StatsResponse>("/stats")
  return data
}

export async function fetchMitreMatrix(): Promise<MitreMatrixResponse> {
  const { data } = await apiClient.get<MitreMatrixResponse>("/knowledge/mitre-matrix")
  return data
}

export async function sendCopilotMessage(payload: CopilotChatRequest): Promise<CopilotChatResponse> {
  const { data } = await apiClient.post<CopilotChatResponse>("/copilot/chat", payload)
  return data
}

// === IntelOwl Threat Intelligence enrichment ===
// Append this block to frontend/src/services/api.ts (the apply_integration.py
// script does this automatically). It reuses the existing `apiClient` axios
// instance so it inherits the same base URL and Bearer auth interceptor.
import type {
  IntelOwlBulkScanResponse,
  IntelOwlHealth,
  IntelOwlNormalizedResult,
  IntelOwlScanRecord,
  IntelOwlScanRequest,
  IntelOwlScanResponse,
} from "@/types/intelowl"
import type { MitrePlaybook } from "@/types/mitrePlaybook"

export async function checkIntelOwlHealth(): Promise<IntelOwlHealth> {
  const { data } = await apiClient.get<IntelOwlHealth>("/intelowl/health")
  return data
}

export async function submitIntelOwlScan(
  payload: IntelOwlScanRequest,
): Promise<IntelOwlScanResponse> {
  const { data } = await apiClient.post<IntelOwlScanResponse>("/intelowl/scan", payload)
  return data
}

export async function getIntelOwlJob(jobId: string): Promise<IntelOwlScanRecord> {
  const { data } = await apiClient.get<IntelOwlScanRecord>(`/intelowl/jobs/${jobId}`)
  return data
}

export async function getIntelOwlResults(jobId: string): Promise<IntelOwlNormalizedResult> {
  const { data } = await apiClient.get<IntelOwlNormalizedResult>(`/intelowl/results/${jobId}`)
  return data
}

export async function scanAnalysisIocs(
  analysisId: string,
  opts?: { tlp?: string; force?: boolean },
): Promise<IntelOwlBulkScanResponse> {
  const { data } = await apiClient.post<IntelOwlBulkScanResponse>(
    `/intelowl/scan/analysis/${analysisId}`,
    null,
    { params: { tlp: opts?.tlp ?? "CLEAR", force: opts?.force ?? false } },
  )
  return data
}

export async function listIntelOwlScans(
  analysisId: string,
  refresh = true,
): Promise<IntelOwlScanRecord[]> {
  const { data } = await apiClient.get<IntelOwlScanRecord[]>(
    `/intelowl/analysis/${analysisId}`,
    { params: { refresh } },
  )
  return data
}

// === MITRE ATT&CK triage playbooks (served from the backend) ===
export async function fetchMitrePlaybook(ttp: string): Promise<MitrePlaybook> {
  const { data } = await apiClient.get<MitrePlaybook>(
    `/playbooks/mitre/${encodeURIComponent(ttp)}`,
  )
  return data
}
