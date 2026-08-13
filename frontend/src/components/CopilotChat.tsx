import { useMemo, useState } from "react"
import { Bot, Loader2, MessageSquare, Send, X } from "lucide-react"

import { Button } from "@/components/ui/button"
import { useCopilotContext } from "@/context/CopilotContext"
import { sendCopilotMessage } from "@/services/api"
import type {
  AnalysisResponse,
  CopilotChatMessage,
  CopilotIncidentContext,
} from "@/types/analysis"

/** Build the structured incident context sent to the copilot so answers are
 * grounded in the analysis currently on screen (never generic). Mirrors the
 * fields the backend prioritises: Detailed Explanation, Key Indicators,
 * Explainable-AI signals, MITRE ATT&CK, verdict/severity/scores, IOCs and the
 * original analyzed content. */
function buildIncidentContext(analysis: AnalysisResponse): CopilotIncidentContext {
  const explainableSignals =
    analysis.explainability
      ?.filter((e) => e.matched)
      .map((e) => e.label)
      .filter(Boolean) ?? null

  const mitreTechniques =
    analysis.mitre_details && analysis.mitre_details.length > 0
      ? analysis.mitre_details.map((m) => `${m.id} ${m.name}`.trim())
      : (analysis.mitre_techniques ?? null)

  return {
    analysisId: analysis.id,
    verdict: analysis.classification,
    severity: analysis.risk_level,
    riskScore: analysis.risk_score ?? null,
    confidence: analysis.confidence,
    threatCategories: analysis.threat_tags ?? null,
    executiveSummary: analysis.summary,
    detailedExplanation: analysis.explanation,
    keyIndicators: analysis.indicators ?? null,
    explainableSignals,
    mitreTechniques,
    iocs: analysis.iocs ?? null,
    originalContent: analysis.input_text,
    sender: analysis.iocs?.emails?.[0] ?? null,
    urls: analysis.iocs?.urls ?? null,
    domains: analysis.iocs?.domains ?? null,
  }
}

/** Short list of which incident sections the copilot is drawing on, shown in
 * the grounding banner so the analyst knows the answer is incident-specific. */
function groundingSources(analysis: AnalysisResponse): string[] {
  const sources: string[] = []
  if (analysis.explanation) sources.push("Detailed Explanation")
  if (analysis.indicators?.length) sources.push("Key Indicators")
  if (analysis.explainability?.some((e) => e.matched)) sources.push("Explainable AI")
  if (analysis.mitre_details?.length || analysis.mitre_techniques?.length)
    sources.push("MITRE ATT&CK")
  return sources.slice(0, 4)
}

/** Global floating AI SOC Copilot chat widget. Mounted once in MainLayout so
 * it is available from every page. Purely additive: does not touch the
 * Analyzer/History/Dashboard pages or any existing routing/auth. Grounds its
 * answers in whichever analysis is currently on screen (if any), via
 * CopilotContext. */
export function CopilotChat() {
  const { currentAnalysis, currentAnalysisId } = useCopilotContext()
  const [open, setOpen] = useState(false)
  const [messages, setMessages] = useState<CopilotChatMessage[]>([])
  const [input, setInput] = useState("")
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [groundedId, setGroundedId] = useState<string | null>(null)

  const incidentContext = useMemo(
    () => (currentAnalysis ? buildIncidentContext(currentAnalysis) : null),
    [currentAnalysis],
  )
  const sources = useMemo(
    () => (currentAnalysis ? groundingSources(currentAnalysis) : []),
    [currentAnalysis],
  )

  async function handleSend() {
    const trimmed = input.trim()
    if (!trimmed || loading) return
    const nextHistory = [...messages, { role: "user", content: trimmed } as CopilotChatMessage]
    setMessages(nextHistory)
    setInput("")
    setLoading(true)
    setError(null)
    try {
      const res = await sendCopilotMessage({
        message: trimmed,
        history: messages,
        analysis_id: currentAnalysisId,
        // Send the actual current analysis, not just the question, so the
        // model can answer specifically about THIS incident.
        incident_context: incidentContext,
      })
      setMessages([...nextHistory, { role: "assistant", content: res.reply }])
      setGroundedId(res.grounded_in_analysis_id ?? null)
    } catch {
      setError("The copilot could not respond. Check your AI provider configuration and try again.")
    } finally {
      setLoading(false)
    }
  }

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="fixed bottom-5 right-5 z-50 flex h-12 w-12 items-center justify-center rounded-full bg-brand-600 text-white shadow-lg transition-transform hover:scale-105"
        aria-label="Open AI SOC Copilot"
      >
        <MessageSquare className="h-5 w-5" />
      </button>
    )
  }

  const grounded = Boolean(groundedId || currentAnalysisId)

  return (
    <div className="fixed bottom-5 right-5 z-50 flex h-[28rem] w-80 flex-col overflow-hidden rounded-xl border border-slate-200 bg-white shadow-2xl dark:border-slate-700 dark:bg-slate-900">
      <div className="flex items-center justify-between border-b border-slate-100 bg-brand-600 px-3 py-2 text-white dark:border-slate-800">
        <span className="flex items-center gap-2 text-sm font-semibold">
          <Bot className="h-4 w-4" /> AI SOC Copilot
        </span>
        <button onClick={() => setOpen(false)} aria-label="Close AI SOC Copilot">
          <X className="h-4 w-4" />
        </button>
      </div>

      {grounded && (
        <div className="border-b border-slate-100 bg-brand-50 px-3 py-1.5 dark:border-slate-800 dark:bg-slate-800/60">
          <p className="flex items-center gap-1 text-[11px] font-semibold text-brand-700 dark:text-brand-300">
            <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-500" />
            Grounded in current analysis
          </p>
          {sources.length > 0 && (
            <p className="mt-0.5 text-[10px] text-brand-600/80 dark:text-brand-300/70">
              Based on: {sources.join(" \u2022 ")}
            </p>
          )}
        </div>
      )}

      <div className="flex-1 space-y-3 overflow-y-auto p-3">
        {messages.length === 0 && (
          <p className="text-xs text-slate-400">
            {grounded
              ? "Ask about THIS incident \u2014 why it's phishing, which indicators triggered the verdict, the risk score, MITRE techniques, IOCs to block, or next steps."
              : "Open an analysis to ask incident-specific questions. You can still ask general SOC questions here."}
          </p>
        )}
        {messages.map((m, i) => (
          <div
            key={i}
            className={
              m.role === "user"
                ? "ml-auto max-w-[85%] whitespace-pre-wrap rounded-lg bg-brand-600 px-3 py-1.5 text-xs text-white"
                : "mr-auto max-w-[85%] whitespace-pre-wrap rounded-lg bg-slate-100 px-3 py-1.5 text-xs text-slate-700 dark:bg-slate-800 dark:text-slate-200"
            }
          >
            {m.content}
          </div>
        ))}
        {loading && (
          <div className="mr-auto flex items-center gap-1 text-xs text-slate-400">
            <Loader2 className="h-3 w-3 animate-spin" /> Thinking...
          </div>
        )}
        {error && <p className="text-xs text-red-500">{error}</p>}
      </div>

      <div className="flex items-center gap-2 border-t border-slate-100 p-2 dark:border-slate-800">
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") handleSend()
          }}
          placeholder="Ask the SOC copilot..."
          className="flex-1 rounded-md border border-slate-200 bg-transparent px-2 py-1.5 text-xs outline-none focus:border-brand-500 dark:border-slate-700"
        />
        <Button size="sm" onClick={handleSend} disabled={loading || !input.trim()}>
          <Send className="h-3.5 w-3.5" />
        </Button>
      </div>
    </div>
  )
}
