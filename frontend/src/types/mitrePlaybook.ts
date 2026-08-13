// Structured MITRE ATT&CK triage playbook served by the backend
// (GET /api/v1/playbooks/mitre/{ttp}). Sourced from the community repository
// CodeByHarri/MITRE-ATT_CK-Playbooks and parsed into these fields.

export interface MitrePlaybookSummary {
  ttp: string
  name: string
  tactic: string
}

export interface MitrePlaybook {
  ttp: string
  sub_ttp?: string | null
  name: string
  tactic: string
  log_sources: string[]
  key_indicators: string[]
  questions: string[]
  escalation: string[]
  l1_steps: string[]
  t2_actions: string[]
  containment: string[]
  source_file?: string | null
  markdown?: string | null
}
