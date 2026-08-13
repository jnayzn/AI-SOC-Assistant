// Structured data model for the interactive Automated Playbooks section.
// These types describe the enriched, expandable SOC playbook shown in
// PlaybookCard. They are intentionally decoupled from the lightweight
// `PlaybookAction` returned by the backend (title/priority/category) so the
// UI can present full incident-response detail without changing the API.

export type PlaybookSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"

// Lifecycle status for a playbook execution run.
export type PlaybookStatus = "PENDING" | "RUNNING" | "COMPLETED" | "FAILED" | "SIMULATION"

export interface MitreTechnique {
  id: string
  name: string
}

// The full, detailed playbook rendered inside an expandable card.
export interface Playbook {
  id: string
  category: string
  severity: PlaybookSeverity
  title: string
  shortDescription: string
  description: string
  objective: string
  whyRecommended: string
  actions: string[]
  steps: string[]
  mitreAttack: MitreTechnique[]
  iocs?: string[]
  tools: string[]
  expectedResult: string
  nextStep: string
  recommendedAction?: string
}

// Detail template stored in the catalog. Severity, category and title are
// supplied at resolve-time from the backend `PlaybookAction`, so a template
// only carries the rich response content.
export interface PlaybookTemplate {
  shortDescription: string
  description: string
  objective: string
  whyRecommended: string
  actions: string[]
  steps: string[]
  mitreAttack: MitreTechnique[]
  iocs?: string[]
  tools: string[]
  expectedResult: string
  nextStep: string
  recommendedAction?: string
}
