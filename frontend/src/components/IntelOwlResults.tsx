import { useCallback, useEffect, useRef, useState } from "react"
import {
  checkIntelOwlHealth,
  listIntelOwlScans,
  scanAnalysisIocs,
} from "@/services/api"
import type { IntelOwlScanRecord } from "@/types/intelowl"
import { IntelOwlAnalysis } from "./IntelOwlAnalysis"

const NON_TERMINAL = new Set(["PENDING", "RUNNING"])

const STATUS_META: Record<string, { emoji: string; label: string; dot: string }> = {
  PENDING: { emoji: "\u23F3", label: "Pending", dot: "bg-slate-400" },
  RUNNING: { emoji: "🔄", label: "Running", dot: "bg-sky-400 animate-pulse" },
  COMPLETED: { emoji: "\u2713", label: "Completed", dot: "bg-emerald-400" },
  FAILED: { emoji: "\u2715", label: "Failed", dot: "bg-red-400" },
  TIMEOUT: { emoji: "\u26A0", label: "Timeout", dot: "bg-amber-400" },
}

const VERDICT_META: Record<string, { emoji: string; text: string }> = {
  malicious: { emoji: "\uD83D\uDD34", text: "text-red-400" },
  suspicious: { emoji: "\uD83D\uDFE0", text: "text-amber-400" },
  clean: { emoji: "\uD83D\uDFE2", text: "text-emerald-400" },
  unknown: { emoji: "\u26AA", text: "text-slate-400" },
}

// Threat Intelligence enrichment panel backed by the user's real IntelOwl
// instance. Auto-launches a scan for the analysis IOCs on mount, then polls
// until every job reaches a terminal state. Hides itself when IntelOwl is not
// configured on the backend so the rest of the UI is unaffected.
export function IntelOwlResults({ analysisId }: { analysisId: string }) {
  const [scans, setScans] = useState<IntelOwlScanRecord[]>([])
  const [configured, setConfigured] = useState<boolean | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<IntelOwlScanRecord | null>(null)
  const [rescanning, setRescanning] = useState(false)
  const startedRef = useRef(false)
  const pollTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)

  const refresh = useCallback(async (): Promise<IntelOwlScanRecord[]> => {
    try {
      const data = await listIntelOwlScans(analysisId, true)
      setScans(data)
      setError(null)
      return data
    } catch {
      setError("Could not load IntelOwl results.")
      return []
    }
  }, [analysisId])

  // Poll open jobs until they reach a terminal state (used after a re-scan).
  const startPolling = useCallback(() => {
    const tick = async () => {
      const data = await refresh()
      if (data.some((s) => NON_TERMINAL.has(s.status))) {
        pollTimer.current = setTimeout(tick, 5000)
      }
    }
    if (pollTimer.current) clearTimeout(pollTimer.current)
    pollTimer.current = setTimeout(tick, 5000)
  }, [refresh])

  // Force a brand-new IntelOwl job for every IOC, bypassing the backend cache.
  const rescan = useCallback(async () => {
    setRescanning(true)
    setError(null)
    try {
      await scanAnalysisIocs(analysisId, { tlp: "CLEAR", force: true })
      const data = await refresh()
      if (data.some((s) => NON_TERMINAL.has(s.status))) startPolling()
    } catch {
      setError("Re-scan failed — check that IntelOwl is reachable.")
    } finally {
      setRescanning(false)
    }
  }, [analysisId, refresh, startPolling])

  useEffect(
    () => () => {
      if (pollTimer.current) clearTimeout(pollTimer.current)
    },
    [],
  )

  useEffect(() => {
    let cancelled = false
    let timer: ReturnType<typeof setTimeout> | undefined

    const poll = async () => {
      if (cancelled) return
      const data = await refresh()
      if (!cancelled && data.some((s) => NON_TERMINAL.has(s.status))) {
        timer = setTimeout(poll, 5000)
      }
    }

    const boot = async () => {
      try {
        const health = await checkIntelOwlHealth()
        if (cancelled) return
        setConfigured(health.configured)
        if (!health.configured) {
          setLoading(false)
          return
        }
        if (!startedRef.current) {
          startedRef.current = true
          try {
            await scanAnalysisIocs(analysisId, { tlp: "CLEAR" })
          } catch {
            // enrichment is best-effort; existing scans still load below
          }
        }
        const data = await refresh()
        if (cancelled) return
        setLoading(false)
        if (data.some((s) => NON_TERMINAL.has(s.status))) {
          timer = setTimeout(poll, 5000)
        }
      } catch {
        if (!cancelled) {
          setConfigured(false)
          setLoading(false)
        }
      }
    }

    void boot()
    return () => {
      cancelled = true
      if (timer) clearTimeout(timer)
    }
  }, [analysisId, refresh])

  // Do not render anything when IntelOwl is not configured on the backend.
  if (configured === false) return null

  return (
    <section className="mt-6 rounded-2xl border border-slate-700/60 bg-slate-900/40 p-5 backdrop-blur">
      <div className="mb-4 flex items-center justify-between gap-3">
        <div>
          <h3 className="flex items-center gap-2 text-base font-semibold text-white">
            🦉 IntelOwl Threat Intelligence
          </h3>
          <p className="text-xs text-slate-400">Live enrichment from your IntelOwl instance</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => void rescan()}
            disabled={rescanning}
            title="Force a brand-new IntelOwl job for every IOC (bypasses the 1h cache)"
            className="rounded-lg border border-amber-500/60 px-3 py-1.5 text-xs text-amber-200 hover:bg-amber-500/10 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {rescanning ? "♻ Re-scanning…" : "♻ Re-scan (force)"}
          </button>
          <button
            onClick={() => void refresh()}
            className="rounded-lg border border-slate-600 px-3 py-1.5 text-xs text-slate-200 hover:bg-slate-800"
          >
            🔄 Refresh
          </button>
        </div>
      </div>

      {loading && <p className="text-sm text-slate-400">Loading enrichment…</p>}
      {error && <p className="text-sm text-red-400">{error}</p>}
      {!loading && !error && scans.length === 0 && (
        <p className="text-sm text-slate-400">No observables to enrich for this analysis yet.</p>
      )}

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {scans.map((scan) => {
          const status = STATUS_META[scan.status] ?? STATUS_META.PENDING
          const verdict = VERDICT_META[(scan.verdict ?? "unknown").toLowerCase()] ?? VERDICT_META.unknown
          const analyzers = scan.normalized_result?.analyzers ?? scan.analyzers ?? []
          return (
            <div key={scan.id} className="flex flex-col rounded-xl border border-slate-700/60 bg-slate-800/40 p-4">
              <div className="flex items-center justify-between gap-2">
                <span className={`h-2.5 w-2.5 rounded-full ${status.dot}`} title={status.label} />
                <span className="rounded bg-slate-700/60 px-2 py-0.5 text-[10px] uppercase tracking-wide text-slate-300">
                  {scan.observable_type}
                </span>
              </div>
              <p className="mt-2 break-all font-mono text-sm text-slate-100" title={scan.observable}>
                {scan.observable}
              </p>
              <div className="mt-2 flex items-center gap-2 text-sm">
                <span>{status.emoji}</span>
                <span className="text-slate-300">{status.label}</span>
                <span className="ml-auto flex items-center gap-1">
                  <span>{verdict.emoji}</span>
                  <span className={verdict.text}>{(scan.verdict ?? "unknown")}</span>
                </span>
              </div>

              {analyzers.length > 0 && (
                <ul className="mt-3 space-y-0.5">
                  {analyzers.slice(0, 4).map((a, i) => (
                    <li key={`${a.name}-${i}`} className="flex items-center gap-1.5 text-xs text-slate-400">
                      <span>{a.status === "SUCCESS" ? "\u2705" : a.status === "FAILED" ? "\u274C" : "\u2022"}</span>
                      <span className="truncate">{a.name}</span>
                    </li>
                  ))}
                  {analyzers.length > 4 && (
                    <li className="text-xs text-slate-500">+{analyzers.length - 4} more</li>
                  )}
                </ul>
              )}

              <div className="mt-3 flex gap-2">
                <button
                  onClick={() => setSelected(scan)}
                  className="flex-1 rounded-lg border border-slate-600 px-2 py-1 text-xs text-slate-200 hover:bg-slate-700"
                >
                  View Details
                </button>
                <button
                  onClick={() => void refresh()}
                  className="rounded-lg border border-slate-600 px-2 py-1 text-xs text-slate-200 hover:bg-slate-700"
                  title="Refresh"
                >
                  🔄
                </button>
              </div>
            </div>
          )
        })}
      </div>

      {selected && <IntelOwlAnalysis record={selected} onClose={() => setSelected(null)} />}
    </section>
  )
}
