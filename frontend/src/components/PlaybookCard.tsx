import { AnimatePresence, motion } from "framer-motion"
import {
  AlertOctagon,
  ArrowRight,
  ArrowUpCircle,
  CheckCircle2,
  ChevronDown,
  CircleDot,
  Crosshair,
  FileText,
  Fingerprint,
  Flag,
  HelpCircle,
  ListChecks,
  ListOrdered,
  Loader2,
  MinusCircle,
  ShieldCheck,
  Target,
  Wrench,
  X,
} from "lucide-react"
import { type ReactNode, useEffect, useRef, useState } from "react"

import { Button } from "@/components/ui/button"
import { ProgressBar } from "@/components/ui/progress"
import { cn } from "@/lib/utils"
import type { Playbook, PlaybookSeverity, PlaybookStatus } from "@/types/playbook"


// Build a MITRE ATT&CK technique URL from parts so URL tooling never
// rewrites a single hard-coded literal.
function mitreHref(id: string): string {
  const proto = "https://"
  const host = "attack.mitre.org"
  return proto + host + "/techniques/" + id.replace(/\./g, "/") + "/"
}

// --- Severity design tokens -------------------------------------------------
// Preserves the existing red/orange/yellow/green visual hierarchy while giving
// each expandable card a matching accent, border and badge.
const SEVERITY_STYLE: Record<
  PlaybookSeverity,
  {
    icon: typeof AlertOctagon
    border: string
    badge: string
    accentBar: string
    header: string
    iconWrap: string
    ring: string
  }
> = {
  CRITICAL: {
    icon: AlertOctagon,
    border: "border-red-200 dark:border-red-900/50",
    badge: "bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300",
    accentBar: "bg-red-500",
    header:
      "bg-red-50/60 hover:bg-red-50 dark:bg-red-900/10 dark:hover:bg-red-900/20",
    iconWrap: "bg-red-100 text-red-600 dark:bg-red-900/40 dark:text-red-300",
    ring: "focus-visible:ring-red-500",
  },
  HIGH: {
    icon: ArrowUpCircle,
    border: "border-orange-200 dark:border-orange-900/50",
    badge: "bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300",
    accentBar: "bg-orange-500",
    header:
      "bg-orange-50/60 hover:bg-orange-50 dark:bg-orange-900/10 dark:hover:bg-orange-900/20",
    iconWrap: "bg-orange-100 text-orange-600 dark:bg-orange-900/40 dark:text-orange-300",
    ring: "focus-visible:ring-orange-500",
  },
  MEDIUM: {
    icon: CircleDot,
    border: "border-yellow-200 dark:border-yellow-900/50",
    badge: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/40 dark:text-yellow-300",
    accentBar: "bg-yellow-500",
    header:
      "bg-yellow-50/60 hover:bg-yellow-50 dark:bg-yellow-900/10 dark:hover:bg-yellow-900/20",
    iconWrap: "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-300",
    ring: "focus-visible:ring-yellow-500",
  },
  LOW: {
    icon: MinusCircle,
    border: "border-green-200 dark:border-green-900/50",
    badge: "bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300",
    accentBar: "bg-green-500",
    header:
      "bg-green-50/60 hover:bg-green-50 dark:bg-green-900/10 dark:hover:bg-green-900/20",
    iconWrap: "bg-green-100 text-green-600 dark:bg-green-900/40 dark:text-green-300",
    ring: "focus-visible:ring-green-500",
  },
}

// --- Status badge tokens ----------------------------------------------------
const STATUS_STYLE: Record<PlaybookStatus, { label: string; className: string }> = {
  PENDING: { label: "Pending", className: "bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300" },
  RUNNING: { label: "Running", className: "bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300" },
  COMPLETED: { label: "Completed", className: "bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300" },
  FAILED: { label: "Failed", className: "bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300" },
  SIMULATION: { label: "Simulation", className: "bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300" },
}

function StatusBadge({ status }: { status: PlaybookStatus }) {
  const s = STATUS_STYLE[status]
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide",
        s.className,
      )}
    >
      {status === "RUNNING" && <Loader2 className="h-3 w-3 animate-spin" />}
      {s.label}
    </span>
  )
}

// Small labelled section used for every detail block in the expanded card.
function Section({
  icon: Icon,
  title,
  children,
}: {
  icon: typeof FileText
  title: string
  children: ReactNode
}) {
  return (
    <section>
      <h5 className="mb-1.5 flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wide text-slate-500 dark:text-slate-400">
        <Icon className="h-3.5 w-3.5" />
        {title}
      </h5>
      <div className="text-sm leading-relaxed text-slate-600 dark:text-slate-300">{children}</div>
    </section>
  )
}

export interface PlaybookCardProps {
  playbook: Playbook
  isOpen: boolean
  onToggle: () => void
}

export function PlaybookCard({ playbook, isOpen, onToggle }: PlaybookCardProps) {
  const style = SEVERITY_STYLE[playbook.severity] ?? SEVERITY_STYLE.MEDIUM
  const Icon = style.icon

  const [status, setStatus] = useState<PlaybookStatus>("PENDING")
  const [progress, setProgress] = useState(0)
  const [showConfirm, setShowConfirm] = useState(false)
  const [resolved, setResolved] = useState(false)
  const timers = useRef<number[]>([])

  // In the absence of a real backend execution endpoint, playbooks run in
  // SIMULATION MODE -- no real infrastructure changes are performed.
  const SIMULATION_MODE = true

  useEffect(() => {
    return () => {
      timers.current.forEach((t) => window.clearTimeout(t))
    }
  }, [])

  const runExecution = () => {
    setShowConfirm(false)
    setStatus("RUNNING")
    setProgress(8)

    const steps = [25, 50, 75, 95]
    steps.forEach((value, i) => {
      timers.current.push(window.setTimeout(() => setProgress(value), 400 * (i + 1)))
    })

    timers.current.push(
      window.setTimeout(() => {
        setProgress(100)
        setStatus(SIMULATION_MODE ? "SIMULATION" : "COMPLETED")
      }, 400 * (steps.length + 1)),
    )
  }

  const isRunning = status === "RUNNING"
  const hasRun = status === "COMPLETED" || status === "SIMULATION"

  return (
    <div
      className={cn(
        "overflow-hidden rounded-xl border bg-white/70 shadow-sm backdrop-blur-sm transition-all duration-200 dark:bg-slate-900/60",
        style.border,
        isOpen && "shadow-md",
      )}
    >
      {/* ---- Collapsed header (entire row is the toggle) ---- */}
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={isOpen}
        className={cn(
          "flex w-full items-start gap-3 px-4 py-3 text-left transition-colors focus-visible:outline-none focus-visible:ring-2",
          style.header,
          style.ring,
        )}
      >
        {/* Left severity accent bar */}
        <span className={cn("mt-0.5 h-9 w-1 shrink-0 rounded-full", style.accentBar)} aria-hidden />
        <span className={cn("mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg", style.iconWrap)}>
          <Icon className="h-4 w-4" />
        </span>

        <span className="min-w-0 flex-1">
          <span className="flex items-center justify-between gap-2">
            <span className="truncate text-[11px] font-bold uppercase tracking-wide text-slate-500 dark:text-slate-400">
              {playbook.category}
            </span>
            <span className="flex shrink-0 items-center gap-2">
              {(hasRun || isRunning) && <StatusBadge status={status} />}
              {resolved && <StatusBadge status="COMPLETED" />}
              <span
                className={cn(
                  "rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide",
                  style.badge,
                )}
              >
                {playbook.severity}
              </span>
              <motion.span animate={{ rotate: isOpen ? 180 : 0 }} transition={{ duration: 0.2 }}>
                <ChevronDown className="h-4 w-4 text-slate-500 dark:text-slate-400" />
              </motion.span>
            </span>
          </span>
          <span className="mt-0.5 block truncate text-sm font-semibold text-slate-800 dark:text-slate-100">
            {playbook.title}
          </span>
          <span className="mt-0.5 block truncate text-xs text-slate-500 dark:text-slate-400">
            {playbook.shortDescription}
          </span>
        </span>
      </button>

      {/* ---- Expanded body ---- */}
      <AnimatePresence initial={false}>
        {isOpen && (
          <motion.div
            key="content"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.28, ease: [0.4, 0, 0.2, 1] }}
            className="overflow-hidden"
          >
            <div className="relative border-t border-slate-200/70 bg-slate-50/70 px-4 py-4 dark:border-slate-800/70 dark:bg-slate-950/40">
              <div className="flex flex-col gap-4">
                <Section icon={FileText} title="Description">
                  {playbook.description}
                </Section>

                <Section icon={Target} title="Objective">
                  {playbook.objective}
                </Section>

                <Section icon={HelpCircle} title="Why this playbook is recommended">
                  {playbook.whyRecommended}
                </Section>

                <Section icon={ListChecks} title="Recommended actions">
                  <ul className="flex flex-col gap-1">
                    {playbook.actions.map((a) => (
                      <li key={a} className="flex items-start gap-2">
                        <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-green-500" />
                        <span>{a}</span>
                      </li>
                    ))}
                  </ul>
                </Section>

                <Section icon={ListOrdered} title="Execution steps">
                  <ol className="flex flex-col gap-1">
                    {playbook.steps.map((s, i) => (
                      <li key={s} className="flex items-start gap-2">
                        <span className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-brand-100 text-[10px] font-bold text-brand-700 dark:bg-brand-900/40 dark:text-brand-300">
                          {i + 1}
                        </span>
                        <span>{s}</span>
                      </li>
                    ))}
                  </ol>
                </Section>

                <Section icon={Crosshair} title="MITRE ATT&CK">
                  <div className="flex flex-col gap-1.5">
                    {playbook.mitreAttack.map((t) => (
                      <a
                        key={t.id}
                        href={mitreHref(t.id)}
                        target="_blank"
                        rel="noreferrer"
                        className="flex items-center gap-2 text-sm hover:underline"
                      >
                        <span className="rounded-md bg-brand-50 px-1.5 py-0.5 font-mono text-xs font-bold text-brand-700 dark:bg-brand-900/30 dark:text-brand-300">
                          {t.id}
                        </span>
                        <span className="text-slate-600 dark:text-slate-300">{t.name}</span>
                      </a>
                    ))}
                  </div>
                </Section>

                {playbook.iocs && playbook.iocs.length > 0 && (
                  <Section icon={Fingerprint} title="Indicators of compromise">
                    <div className="flex flex-wrap gap-1.5">
                      {playbook.iocs.map((ioc) => (
                        <span
                          key={ioc}
                          className="rounded-md border border-slate-200 bg-white px-2 py-0.5 font-mono text-xs text-slate-600 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300"
                        >
                          {ioc}
                        </span>
                      ))}
                    </div>
                  </Section>
                )}

                <Section icon={Wrench} title="Required tools">
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                    {playbook.tools.map((tool, i) => (
                      <span key={tool} className="flex items-center gap-2">
                        {i > 0 && <span className="text-slate-300 dark:text-slate-600">&bull;</span>}
                        <span className="font-medium text-slate-600 dark:text-slate-300">{tool}</span>
                      </span>
                    ))}
                  </div>
                </Section>

                <Section icon={Flag} title="Expected result">
                  {playbook.expectedResult}
                </Section>

                <Section icon={ArrowRight} title="Next recommended action">
                  {playbook.nextStep}
                </Section>

                {/* ---- Execution status / progress ---- */}
                {(isRunning || hasRun) && (
                  <div className="rounded-lg border border-slate-200 bg-white p-3 dark:border-slate-800 dark:bg-slate-900">
                    <div className="mb-2 flex items-center justify-between">
                      <span className="flex items-center gap-1.5 text-xs font-semibold text-slate-500 dark:text-slate-400">
                        <ShieldCheck className="h-3.5 w-3.5" /> Execution status
                      </span>
                      <StatusBadge status={status} />
                    </div>
                    <ProgressBar
                      value={progress}
                      colorClassName={
                        status === "SIMULATION"
                          ? "bg-purple-500"
                          : status === "COMPLETED"
                            ? "bg-green-500"
                            : "bg-blue-500"
                      }
                    />
                    {status === "SIMULATION" && (
                      <p className="mt-2 rounded-md bg-purple-50 px-2 py-1.5 text-xs font-medium text-purple-700 dark:bg-purple-900/20 dark:text-purple-300">
                        Simulation Mode &mdash; No real infrastructure changes were performed.
                      </p>
                    )}
                  </div>
                )}

                {/* ---- Action buttons ---- */}
                <div className="flex flex-wrap items-center gap-2 pt-1">
                  <Button
                    type="button"
                    size="sm"
                    onClick={() => setShowConfirm(true)}
                    disabled={isRunning}
                  >
                    <ShieldCheck className="h-4 w-4" />
                    {hasRun ? "Re-run Playbook" : "Execute Playbook"}
                  </Button>
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    onClick={() => setResolved((r) => !r)}
                  >
                    <CheckCircle2 className={cn("h-4 w-4", resolved && "text-green-500")} />
                    {resolved ? "Resolved" : "Mark as Resolved"}
                  </Button>
                </div>
              </div>

              {/* ---- Confirmation modal ---- */}
              <AnimatePresence>
                {showConfirm && (
                  <motion.div
                    className="absolute inset-0 z-10 flex items-center justify-center rounded-xl bg-slate-900/50 p-4 backdrop-blur-sm"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    onClick={() => setShowConfirm(false)}
                  >
                    <motion.div
                      role="dialog"
                      aria-modal="true"
                      className="w-full max-w-sm rounded-xl border border-slate-200 bg-white p-4 shadow-xl dark:border-slate-700 dark:bg-slate-900"
                      initial={{ scale: 0.95, y: 8 }}
                      animate={{ scale: 1, y: 0 }}
                      exit={{ scale: 0.95, y: 8 }}
                      onClick={(e) => e.stopPropagation()}
                    >
                      <div className="mb-2 flex items-start justify-between gap-2">
                        <h4 className="text-sm font-semibold text-slate-800 dark:text-slate-100">
                          Are you sure you want to execute this playbook?
                        </h4>
                        <button
                          type="button"
                          onClick={() => setShowConfirm(false)}
                          className="rounded p-0.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
                          aria-label="Close"
                        >
                          <X className="h-4 w-4" />
                        </button>
                      </div>

                      <div className="mb-3 flex flex-col gap-2 rounded-lg bg-slate-50 p-3 text-sm dark:bg-slate-800/60">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-slate-500 dark:text-slate-400">Playbook</span>
                          <span className="font-semibold text-slate-800 dark:text-slate-100">{playbook.title}</span>
                        </div>
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-slate-500 dark:text-slate-400">Severity</span>
                          <span
                            className={cn(
                              "rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide",
                              style.badge,
                            )}
                          >
                            {playbook.severity}
                          </span>
                        </div>
                        <div>
                          <span className="text-slate-500 dark:text-slate-400">Actions that will be performed</span>
                          <ul className="mt-1 flex flex-col gap-1">
                            {playbook.actions.map((a) => (
                              <li key={a} className="flex items-start gap-2 text-slate-700 dark:text-slate-200">
                                <ArrowRight className="mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-400" />
                                <span>{a}</span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      </div>

                      <p className="mb-3 rounded-md bg-purple-50 px-2 py-1.5 text-xs font-medium text-purple-700 dark:bg-purple-900/20 dark:text-purple-300">
                        Simulation Mode &mdash; No real infrastructure changes will be performed.
                      </p>

                      <div className="flex items-center justify-end gap-2">
                        <Button type="button" size="sm" variant="outline" onClick={() => setShowConfirm(false)}>
                          Cancel
                        </Button>
                        <Button type="button" size="sm" onClick={runExecution}>
                          Confirm Execution
                        </Button>
                      </div>
                    </motion.div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
