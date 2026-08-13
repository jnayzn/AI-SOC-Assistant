import { useState } from "react"
import type { IntelOwlScanRecord } from "@/types/intelowl"

const VERDICT_EMOJI: Record<string, string> = {
  malicious: "\uD83D\uDD34",
  suspicious: "\uD83D\uDFE0",
  clean: "\uD83D\uDFE2",
  unknown: "\u26AA",
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  if (value === null || value === undefined || value === "") return null
  return (
    <div className="flex flex-col gap-1 border-b border-slate-700/40 py-2 last:border-0 sm:flex-row sm:gap-4">
      <span className="w-40 shrink-0 text-xs font-semibold uppercase tracking-wide text-slate-400">{label}</span>
      <span className="text-sm text-slate-100 break-all">{value}</span>
    </div>
  )
}

// Readable, SOC-friendly detail view for one IntelOwl scan. Rendered inside a
// modal by IntelOwlResults. Raw JSON is hidden behind a toggle by default.
export function IntelOwlAnalysis({
  record,
  onClose,
}: {
  record: IntelOwlScanRecord
  onClose: () => void
}) {
  const [showRaw, setShowRaw] = useState(false)
  const norm = record.normalized_result ?? null
  const verdict = (record.verdict ?? "unknown").toLowerCase()
  const analyzers = norm?.analyzers ?? record.analyzers ?? []
  const rep = norm?.reputation

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="max-h-[85vh] w-full max-w-2xl overflow-y-auto rounded-2xl border border-slate-700 bg-slate-900/95 p-6 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-4 flex items-start justify-between gap-4">
          <div>
            <h3 className="text-lg font-semibold text-white">
              {VERDICT_EMOJI[verdict] ?? "\u26AA"} IntelOwl — {record.observable}
            </h3>
            <p className="text-xs text-slate-400">Threat Intelligence enrichment details</p>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg border border-slate-600 px-2 py-1 text-sm text-slate-300 hover:bg-slate-800"
          >
            Close
          </button>
        </div>

        <div className="rounded-xl bg-slate-800/40 px-4">
          <Row label="Observable" value={record.observable} />
          <Row label="Type" value={record.observable_type} />
          <Row label="Status" value={record.status} />
          <Row label="Verdict" value={`${VERDICT_EMOJI[verdict] ?? ""} ${verdict}`} />
          <Row
            label="Reputation"
            value={rep ? `${rep.classification}${rep.score != null ? ` (score ${rep.score})` : ""}` : null}
          />
          <Row
            label="Sources"
            value={norm?.reputation_sources?.length ? norm.reputation_sources.join(", ") : null}
          />
          <Row label="Job" value={norm?.job_url ? <a className="text-sky-400 underline" href={norm.job_url} target="_blank" rel="noreferrer">Open in IntelOwl</a> : record.intelowl_job_id} />
          <Row label="Error" value={record.error} />
        </div>

        {analyzers.length > 0 && (
          <div className="mt-4">
            <h4 className="mb-2 text-sm font-semibold text-slate-200">Analyzers</h4>
            <ul className="space-y-1">
              {analyzers.map((a, i) => (
                <li key={`${a.name}-${i}`} className="flex items-center justify-between rounded-lg bg-slate-800/40 px-3 py-1.5 text-sm">
                  <span className="text-slate-100">{a.name}</span>
                  <span className={`text-xs ${a.status === "SUCCESS" ? "text-emerald-400" : a.status === "FAILED" ? "text-red-400" : "text-slate-400"}`}>
                    {a.status}{a.summary ? ` — ${a.summary}` : ""}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {norm && (norm.dns && Object.keys(norm.dns).length > 0) && (
          <DetailBlock title="DNS" obj={norm.dns} />
        )}
        {norm && (norm.whois && Object.keys(norm.whois).length > 0) && (
          <DetailBlock title="WHOIS" obj={norm.whois} />
        )}
        {norm && norm.threat_intelligence?.length > 0 && (
          <div className="mt-4">
            <h4 className="mb-2 text-sm font-semibold text-slate-200">Threat Intelligence</h4>
            <ul className="space-y-1 text-sm text-slate-100">
              {norm.threat_intelligence.map((t, i) => (
                <li key={i} className="rounded-lg bg-slate-800/40 px-3 py-1.5">{JSON.stringify(t)}</li>
              ))}
            </ul>
          </div>
        )}

        <div className="mt-4">
          <button
            onClick={() => setShowRaw((v) => !v)}
            className="rounded-lg border border-slate-600 px-3 py-1 text-xs text-slate-300 hover:bg-slate-800"
          >
            {showRaw ? "Hide Raw JSON" : "Show Raw JSON"}
          </button>
          {showRaw && (
            <pre className="mt-2 max-h-72 overflow-auto rounded-lg bg-black/60 p-3 text-xs text-slate-300">
              {JSON.stringify(record.raw_result ?? norm?.raw_result ?? {}, null, 2)}
            </pre>
          )}
        </div>
      </div>
    </div>
  )
}

function DetailBlock({ title, obj }: { title: string; obj: Record<string, unknown> }) {
  return (
    <div className="mt-4">
      <h4 className="mb-2 text-sm font-semibold text-slate-200">{title}</h4>
      <pre className="max-h-52 overflow-auto rounded-lg bg-slate-800/40 p-3 text-xs text-slate-200">
        {JSON.stringify(obj, null, 2)}
      </pre>
    </div>
  )
}
