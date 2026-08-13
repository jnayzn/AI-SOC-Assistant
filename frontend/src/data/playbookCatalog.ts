// Reusable, structured SOC playbook catalog.
//
// The backend (`/analyze`) returns a lightweight `PlaybookAction`
// ({ action/title, priority, category }) generated deterministically from the
// threat category + severity of an analysis. This catalog ENRICHES each of
// those actions with the full incident-response detail (objective, why it is
// recommended, execution steps, MITRE mapping, tools, expected result, ...)
// used by the interactive <PlaybookCard />.
//
// Details are defined here as data -- never hard-coded inside JSX -- so the
// same content can be reused, tested, and extended without touching the UI.

import type { PlaybookAction } from "@/types/analysis"
import type { MitreTechnique, Playbook, PlaybookSeverity, PlaybookTemplate } from "@/types/playbook"

// Central MITRE ATT&CK technique reference so ids/names stay consistent.
const MITRE: Record<string, string> = {
  T1021: "Remote Services",
  T1059: "Command and Scripting Interpreter",
  T1078: "Valid Accounts",
  T1110: "Brute Force",
  T1566: "Phishing",
  T1071: "Application Layer Protocol",
  T1041: "Exfiltration Over C2 Channel",
  T1048: "Exfiltration Over Alternative Protocol",
  T1003: "OS Credential Dumping",
  T1114: "Email Collection",
  T1547: "Boot or Logon Autostart Execution",
  T1053: "Scheduled Task/Job",
  T1562: "Impair Defenses",
  T1105: "Ingress Tool Transfer",
  T1136: "Create Account",
  T1098: "Account Manipulation",
  T1204: "User Execution",
  T1090: "Proxy",
  T1499: "Endpoint Denial of Service",
  T1657: "Financial Theft",
  T1583: "Acquire Infrastructure",
}

function mitre(...ids: string[]): MitreTechnique[] {
  return ids.map((id) => ({ id, name: MITRE[id] ?? "Technique" }))
}

// Normalize an action name into a stable catalog key.
function normalize(value: string): string {
  return value
    .toLowerCase()
    .replace(/&/g, " and ")
    .replace(/[^a-z0-9]+/g, " ")
    .trim()
}

function toSeverity(priority: string | undefined): PlaybookSeverity {
  switch ((priority ?? "").toLowerCase()) {
    case "critical":
      return "CRITICAL"
    case "high":
      return "HIGH"
    case "low":
      return "LOW"
    default:
      return "MEDIUM"
  }
}

// -----------------------------------------------------------------------------
// Detailed catalog. Keyed by normalized action name. Multiple aliases can map
// to the same template via `registerAliases` below.
// -----------------------------------------------------------------------------
const CATALOG: Record<string, PlaybookTemplate> = {}

function register(names: string[], template: PlaybookTemplate) {
  for (const name of names) CATALOG[normalize(name)] = template
}

register(["Isolate Host", "Isolate Affected Endpoint", "Isolate Endpoint"], {
  shortDescription: "Isolate the compromised endpoint from the network.",
  description:
    "Isolate the compromised endpoint to prevent lateral movement and additional compromise while forensic evidence is preserved.",
  objective:
    "Prevent the attacker from communicating with other systems while preserving volatile and on-disk evidence.",
  whyRecommended:
    "The affected endpoint shows indicators of compromise and may be actively communicating with malicious infrastructure.",
  actions: [
    "Identify affected endpoint",
    "Isolate endpoint from the network",
    "Block malicious IP/domain",
    "Preserve forensic evidence",
    "Collect relevant logs",
  ],
  steps: [
    "Identify the affected endpoint.",
    "Validate the security alert.",
    "Isolate the endpoint using the EDR.",
    "Block malicious network indicators.",
    "Collect logs and forensic evidence.",
    "Start investigation and eradication.",
  ],
  mitreAttack: mitre("T1021", "T1059"),
  iocs: ["Suspicious outbound C2 connections", "Unknown persistence entries", "Anomalous process execution"],
  tools: ["EDR", "SIEM", "Firewall", "Threat Intelligence"],
  expectedResult:
    "The compromised endpoint is isolated and the attacker can no longer communicate with the internal network.",
  nextStep: "Continue with investigation and eradication.",
  recommendedAction: "Isolate the endpoint immediately.",
})

register(["Run Defender / EDR Scan", "Run EDR Scan", "Run Defender Scan"], {
  shortDescription: "Run a full EDR / antivirus scan on the affected host.",
  description:
    "Trigger a full endpoint detection and response scan to detect, quarantine and remove malicious binaries and artifacts.",
  objective: "Detect and remove malware and confirm the full scope of infection on the host.",
  whyRecommended:
    "Malware indicators were observed, so an authoritative endpoint scan is required to eradicate the threat.",
  actions: [
    "Update EDR/AV signatures",
    "Launch full-disk scan",
    "Quarantine detected artifacts",
    "Review scan detections",
  ],
  steps: [
    "Ensure EDR/AV definitions are up to date.",
    "Launch a full-disk scan on the endpoint.",
    "Quarantine or remove detected malicious files.",
    "Review detections and correlate with alerts.",
    "Re-scan to confirm the host is clean.",
  ],
  mitreAttack: mitre("T1059", "T1105"),
  iocs: ["Known-malicious file hashes", "Suspicious binaries in temp paths", "Tampered security tooling"],
  tools: ["EDR", "Antivirus", "SIEM"],
  expectedResult: "Malicious artifacts are detected and quarantined and the host is confirmed clean.",
  nextStep: "Verify persistence mechanisms and monitor for reinfection.",
  recommendedAction: "Run a full EDR scan on the affected host.",
})

register(["Collect Memory Image", "Collect Endpoint Evidence", "Capture Memory"], {
  shortDescription: "Capture volatile memory and endpoint evidence for forensics.",
  description:
    "Acquire a forensic image of volatile memory (and key artifacts) before the system state changes, to support investigation.",
  objective: "Preserve volatile evidence that would otherwise be lost on reboot or remediation.",
  whyRecommended:
    "Active malicious activity is suspected; memory frequently contains injected code, credentials and C2 artifacts.",
  actions: [
    "Prepare forensic tooling",
    "Capture RAM image",
    "Hash and store evidence",
    "Document chain of custody",
  ],
  steps: [
    "Connect approved forensic tooling to the host.",
    "Capture a full memory image.",
    "Generate cryptographic hashes of the image.",
    "Store evidence in the secure evidence locker.",
    "Record and maintain chain of custody.",
  ],
  mitreAttack: mitre("T1003", "T1059"),
  iocs: ["Injected process memory", "In-memory credential material", "Reflectively loaded modules"],
  tools: ["Forensic Suite", "EDR", "Evidence Storage"],
  expectedResult: "A verified memory image is preserved with a documented chain of custody.",
  nextStep: "Analyze the memory image and collect a disk image.",
  recommendedAction: "Capture a memory image before remediation.",
})

register(["Collect Disk Image"], {
  shortDescription: "Acquire a forensic disk image of the affected host.",
  description: "Create a bit-for-bit forensic image of the endpoint disk for deep offline analysis.",
  objective: "Preserve on-disk evidence for detailed timeline and artifact analysis.",
  whyRecommended: "On-disk artifacts are required to reconstruct the attack and support any investigation.",
  actions: ["Prepare imaging media", "Acquire disk image", "Hash and verify image", "Document chain of custody"],
  steps: [
    "Attach write-blocked imaging media.",
    "Acquire a full forensic disk image.",
    "Verify the image hash against the source.",
    "Store the image securely.",
    "Update the chain of custody record.",
  ],
  mitreAttack: mitre("T1059", "T1547"),
  iocs: ["Dropped malicious payloads", "Suspicious scheduled tasks", "Modified system binaries"],
  tools: ["Forensic Suite", "Evidence Storage"],
  expectedResult: "A verified forensic disk image is available for analysis.",
  nextStep: "Perform forensic timeline analysis.",
  recommendedAction: "Acquire a forensic disk image for analysis.",
})

register(["Verify Persistence Mechanisms", "Investigate Suspicious Process"], {
  shortDescription: "Hunt for persistence and suspicious process activity.",
  description:
    "Inspect autostart locations, scheduled tasks, services and running processes for attacker persistence and execution.",
  objective: "Identify and remove any mechanisms the attacker uses to survive reboots or re-establish access.",
  whyRecommended:
    "Suspicious process behavior was observed, which commonly accompanies persistence to maintain access.",
  actions: [
    "Enumerate autostart entries",
    "Review scheduled tasks & services",
    "Inspect suspicious processes",
    "Remove malicious persistence",
  ],
  steps: [
    "Enumerate registry Run keys and startup folders.",
    "Review scheduled tasks and services.",
    "Inspect the process tree for anomalous parents/children.",
    "Correlate findings with EDR telemetry.",
    "Remove confirmed malicious persistence.",
  ],
  mitreAttack: mitre("T1547", "T1053", "T1059"),
  iocs: ["Unknown Run-key entries", "Suspicious scheduled tasks", "Unsigned services"],
  tools: ["EDR", "Autoruns", "SIEM"],
  expectedResult: "All attacker persistence mechanisms are identified and removed.",
  nextStep: "Continue eradication and monitor for re-establishment.",
  recommendedAction: "Review and remove persistence mechanisms.",
})

register(["Block Sender Domain", "Block Malicious Domain", "Block Domain"], {
  shortDescription: "Block the malicious sender/domain across mail and web controls.",
  description:
    "Add the malicious domain to mail-gateway and web-proxy blocklists to prevent further delivery and callbacks.",
  objective: "Stop further malicious email delivery and outbound connections to the domain.",
  whyRecommended:
    "The domain is associated with malicious activity and continued communication increases risk.",
  actions: [
    "Add domain to mail gateway blocklist",
    "Add domain to web proxy blocklist",
    "Sinkhole or block DNS resolution",
    "Search for prior contact",
  ],
  steps: [
    "Confirm the domain is malicious via threat intel.",
    "Add the domain to the mail gateway blocklist.",
    "Add the domain to the web proxy / firewall.",
    "Block or sinkhole DNS resolution.",
    "Search the SIEM for prior communication.",
  ],
  mitreAttack: mitre("T1566", "T1071"),
  iocs: ["Malicious sender domain", "Lookalike/typosquat domain", "Newly registered domain"],
  tools: ["Mail Gateway", "Web Proxy", "Firewall", "Threat Intelligence"],
  expectedResult: "The malicious domain is blocked across email and network controls.",
  nextStep: "Search the SIEM for similar messages and notify affected users.",
  recommendedAction: "Block the malicious domain immediately.",
})

register(["Search SIEM for Similar Messages", "Search SIEM for Related Traffic"], {
  shortDescription: "Hunt the SIEM for related activity and blast radius.",
  description:
    "Pivot on the observed indicators to find related messages, hosts and traffic across the environment.",
  objective: "Determine the full scope and blast radius of the incident.",
  whyRecommended: "Related activity may affect additional users or hosts that are not yet identified.",
  actions: [
    "Build indicator search set",
    "Query SIEM across data sources",
    "Identify affected users/hosts",
    "Document scope",
  ],
  steps: [
    "Compile the confirmed indicators (IPs, domains, hashes, senders).",
    "Query the SIEM across email, endpoint and network logs.",
    "Identify additional affected users or hosts.",
    "Document the scope and update the incident.",
  ],
  mitreAttack: mitre("T1566", "T1071"),
  iocs: ["Repeated sender/subject patterns", "Shared malicious URLs", "Common C2 endpoints"],
  tools: ["SIEM", "Threat Intelligence"],
  expectedResult: "The full scope of related activity is identified and documented.",
  nextStep: "Contain any newly discovered affected assets.",
  recommendedAction: "Pivot on indicators to scope the incident.",
})

register(["Notify Affected Users", "Notify Security Team", "Notify System Administrator"], {
  shortDescription: "Notify the relevant stakeholders about the incident.",
  description:
    "Communicate the incident, its impact and required actions to the appropriate stakeholders in line with the comms plan.",
  objective: "Ensure stakeholders are informed and can take the required protective actions promptly.",
  whyRecommended:
    "Timely communication reduces impact and ensures coordinated response across teams and users.",
  actions: [
    "Identify stakeholders to notify",
    "Prepare incident notification",
    "Send via approved channel",
    "Track acknowledgements",
  ],
  steps: [
    "Identify the stakeholders that must be notified.",
    "Prepare a clear, factual notification.",
    "Send it through the approved communication channel.",
    "Track acknowledgements and required actions.",
    "Escalate if there is no timely response.",
  ],
  mitreAttack: mitre("T1566"),
  iocs: ["Confirmed user impact", "Reported suspicious messages"],
  tools: ["Ticketing / ITSM", "Email", "Collaboration Platform"],
  expectedResult: "Relevant stakeholders are informed and coordinated on next actions.",
  nextStep: "Proceed with containment and investigation tasks.",
  recommendedAction: "Notify the required stakeholders now.",
})

register(["Reset Affected Passwords", "Reset Password"], {
  shortDescription: "Force a password reset for the affected account(s).",
  description: "Invalidate potentially compromised credentials by forcing a secure password reset.",
  objective: "Prevent the attacker from continuing to use stolen credentials.",
  whyRecommended: "Credential theft indicators were observed and the current password may be compromised.",
  actions: [
    "Identify affected accounts",
    "Force password reset",
    "Revoke active sessions/tokens",
    "Verify recovery settings",
  ],
  steps: [
    "Identify all affected accounts.",
    "Force a password reset on each account.",
    "Revoke active sessions and refresh tokens.",
    "Review and correct account recovery settings.",
    "Confirm the user regains secure access.",
  ],
  mitreAttack: mitre("T1078", "T1110"),
  iocs: ["Impossible-travel logins", "Multiple failed then successful auth", "New MFA device"],
  tools: ["Identity Provider", "IAM Console", "SIEM"],
  expectedResult: "Compromised credentials are invalidated and access is restored securely.",
  nextStep: "Force MFA re-enrollment and review access logs.",
  recommendedAction: "Reset affected passwords immediately.",
})

register(["Force MFA Re-enrollment", "Enforce Account Lockout / MFA", "Enforce Account Lockout"], {
  shortDescription: "Force MFA re-enrollment / enforce lockout controls.",
  description:
    "Require re-enrollment of multi-factor authentication and enforce lockout controls to remove attacker-registered factors.",
  objective: "Remove any attacker-controlled MFA methods and strengthen authentication.",
  whyRecommended:
    "Attackers frequently register their own MFA methods to maintain access after credential theft.",
  actions: [
    "Revoke existing MFA methods",
    "Force MFA re-enrollment",
    "Enforce lockout thresholds",
    "Verify legitimate enrollment",
  ],
  steps: [
    "Review registered MFA methods for the account.",
    "Revoke all existing MFA methods.",
    "Force the user to re-enroll MFA securely.",
    "Enforce account lockout thresholds.",
    "Verify only legitimate factors are enrolled.",
  ],
  mitreAttack: mitre("T1078", "T1098"),
  iocs: ["Unexpected MFA device registration", "MFA fatigue prompts", "Suspicious auth locations"],
  tools: ["Identity Provider", "IAM Console"],
  expectedResult: "Only legitimate MFA methods remain and authentication is hardened.",
  nextStep: "Review authentication logs for further abuse.",
  recommendedAction: "Force MFA re-enrollment for the account.",
})

register(["Disable Compromised User Account", "Disable User Account", "Disable Compromised Account"], {
  shortDescription: "Disable the compromised user account.",
  description: "Immediately disable the compromised account to cut off attacker access.",
  objective: "Stop the attacker from using the compromised account.",
  whyRecommended: "The account shows signs of compromise and may be actively abused by the attacker.",
  actions: [
    "Identify compromised account",
    "Disable the account",
    "Revoke sessions and tokens",
    "Review recent account activity",
  ],
  steps: [
    "Confirm the account is compromised.",
    "Disable the account in the identity provider.",
    "Revoke active sessions and tokens.",
    "Review recent account activity and changes.",
    "Plan secure re-enablement once cleared.",
  ],
  mitreAttack: mitre("T1078", "T1098"),
  iocs: ["Anomalous account activity", "Impossible-travel logins", "Privilege changes"],
  tools: ["Identity Provider", "IAM Console", "SIEM"],
  expectedResult: "The compromised account is disabled and attacker access is revoked.",
  nextStep: "Reset credentials and review access logs.",
  recommendedAction: "Disable the compromised account now.",
})

register(["Disable Compromised Mailbox Rules"], {
  shortDescription: "Remove malicious mailbox and forwarding rules.",
  description:
    "Identify and remove attacker-created inbox rules and forwarding that hide activity or exfiltrate mail.",
  objective: "Stop covert mail forwarding and restore mailbox integrity.",
  whyRecommended:
    "Business email compromise commonly involves hidden inbox rules used to conceal fraud and exfiltrate email.",
  actions: [
    "Audit mailbox rules",
    "Remove malicious rules",
    "Disable auto-forwarding",
    "Review sent items",
  ],
  steps: [
    "Audit all inbox and transport rules for the mailbox.",
    "Remove malicious or unknown rules.",
    "Disable external auto-forwarding.",
    "Review sent items for fraudulent messages.",
    "Reset the account credentials.",
  ],
  mitreAttack: mitre("T1114", "T1078"),
  iocs: ["Hidden inbox rules", "External auto-forwarding", "Deleted-items concealment"],
  tools: ["Mail Platform Admin", "Identity Provider", "SIEM"],
  expectedResult: "Malicious mailbox rules are removed and covert forwarding is stopped.",
  nextStep: "Verify financial transactions and notify affected parties.",
  recommendedAction: "Remove malicious mailbox rules immediately.",
})

register(["Verify Financial Transactions"], {
  shortDescription: "Verify and, if needed, halt suspect financial transactions.",
  description:
    "Validate recent and pending financial transactions against a trusted out-of-band channel to detect fraud.",
  objective: "Detect and stop fraudulent payments resulting from the compromise.",
  whyRecommended:
    "BEC frequently targets payment redirection; transactions must be validated before funds are lost.",
  actions: [
    "Identify recent/pending transactions",
    "Verify via out-of-band contact",
    "Halt suspicious payments",
    "Engage finance & fraud teams",
  ],
  steps: [
    "List recent and pending financial transactions.",
    "Verify legitimacy via a trusted out-of-band channel.",
    "Place a hold on suspicious payments.",
    "Engage the finance and fraud teams.",
    "Coordinate recovery with the bank if needed.",
  ],
  mitreAttack: mitre("T1657", "T1114"),
  iocs: ["Changed bank details", "Urgent payment requests", "Spoofed executive emails"],
  tools: ["Finance System", "Ticketing / ITSM", "Phone (out-of-band)"],
  expectedResult: "Fraudulent transactions are identified and halted before loss occurs.",
  nextStep: "Document findings and notify stakeholders.",
  recommendedAction: "Verify all pending financial transactions now.",
})

register(["Block Outbound IP / Domain", "Block Source / Destination IP", "Block Malicious IP", "Block Source IP"], {
  shortDescription: "Block the malicious IP/domain at the network edge.",
  description:
    "Add the malicious network indicator to firewall and proxy blocklists to stop attacker communication.",
  objective: "Cut off command-and-control and data exfiltration channels.",
  whyRecommended:
    "The indicator is associated with malicious infrastructure and active communication increases risk.",
  actions: [
    "Confirm indicator is malicious",
    "Add firewall/proxy block",
    "Verify block is effective",
    "Search for prior connections",
  ],
  steps: [
    "Confirm the IP/domain is malicious via threat intel.",
    "Add a block rule at the firewall and proxy.",
    "Verify the block is active and effective.",
    "Search the SIEM for prior connections.",
    "Document the change for review.",
  ],
  mitreAttack: mitre("T1071", "T1041", "T1090"),
  iocs: ["Beaconing to known-bad IP", "Large outbound transfers", "Connections to newly seen domain"],
  tools: ["Firewall", "Web Proxy", "Threat Intelligence", "SIEM"],
  expectedResult: "Communication with the malicious indicator is blocked at the network edge.",
  nextStep: "Investigate affected hosts and data access logs.",
  recommendedAction: "Block the malicious network indicator now.",
})

register(["Investigate Data Access Logs"], {
  shortDescription: "Investigate data access to assess exfiltration.",
  description: "Review data access and transfer logs to determine what data was accessed or exfiltrated.",
  objective: "Quantify the data exposure and support notification and recovery decisions.",
  whyRecommended:
    "Data exfiltration indicators were observed; the scope of accessed data must be established.",
  actions: [
    "Identify sensitive data stores",
    "Review access & transfer logs",
    "Correlate with attacker activity",
    "Quantify exposure",
  ],
  steps: [
    "Identify the sensitive data stores in scope.",
    "Review data access and transfer logs.",
    "Correlate access with the attacker timeline.",
    "Quantify what data was accessed or exfiltrated.",
    "Document findings for legal/compliance.",
  ],
  mitreAttack: mitre("T1041", "T1048"),
  iocs: ["Bulk data reads", "Access from unusual accounts", "Large outbound transfers"],
  tools: ["SIEM", "DLP", "Cloud Audit Logs"],
  expectedResult: "The scope of data exposure is understood and documented.",
  nextStep: "Notify stakeholders and begin recovery.",
  recommendedAction: "Investigate data access logs to scope exposure.",
})

register(["Review Account Access Logs", "Review Authentication Logs", "Investigate Suspicious Login"], {
  shortDescription: "Review authentication and access logs for abuse.",
  description:
    "Analyze authentication and access logs to confirm suspicious logins and identify the attacker footprint.",
  objective: "Confirm unauthorized access and establish the attacker timeline.",
  whyRecommended:
    "A suspicious login pattern was detected and must be validated against historical authentication data.",
  actions: [
    "Collect authentication logs",
    "Identify anomalous logins",
    "Correlate source IPs/devices",
    "Build access timeline",
  ],
  steps: [
    "Collect authentication and access logs for the account.",
    "Identify anomalous logins (geo, device, time).",
    "Correlate source IPs and devices with threat intel.",
    "Build a timeline of unauthorized access.",
    "Escalate to containment if compromise is confirmed.",
  ],
  mitreAttack: mitre("T1078", "T1110"),
  iocs: ["Impossible-travel logins", "New/unknown devices", "Brute-force then success"],
  tools: ["SIEM", "Identity Provider", "Threat Intelligence"],
  expectedResult: "Suspicious access is confirmed or cleared and the timeline is documented.",
  nextStep: "Contain the account if compromise is confirmed.",
  recommendedAction: "Review authentication logs for anomalies.",
})

// -----------------------------------------------------------------------------
// Fallback generator: builds sensible, category-aware content for any action
// name that is not explicitly present in the catalog. This keeps the UI robust
// as the backend catalog evolves.
// -----------------------------------------------------------------------------
function buildFallback(title: string, category: string, severity: PlaybookSeverity): PlaybookTemplate {
  const cat = category.toLowerCase()
  const lowerTitle = title.toLowerCase()
  const sevWord = severity.toLowerCase()
  return {
    shortDescription: `${title} as part of the SOC response.`,
    description: `Perform "${title}" to support the ${cat} phase of the incident response for this ${sevWord}-severity alert.`,
    objective: `Reduce risk by completing "${title}" and advancing the ${cat} phase of the response.`,
    whyRecommended: `This action was recommended because the analysis produced ${sevWord}-severity indicators relevant to ${cat}.`,
    actions: [
      `Validate the alert relevant to "${title}"`,
      `Perform ${lowerTitle}`,
      "Document the outcome",
      "Update the incident record",
    ],
    steps: [
      "Validate the security alert and confirm scope.",
      `Prepare the tooling required to ${lowerTitle}.`,
      `Execute the "${title}" action.`,
      "Verify the action had the intended effect.",
      "Document the outcome in the incident record.",
    ],
    mitreAttack: mitre("T1059"),
    iocs: ["Alert-correlated indicators", "Anomalous activity in scope"],
    tools: ["SIEM", "EDR", "Threat Intelligence"],
    expectedResult: `"${title}" is completed and the ${cat} phase of the response advances.`,
    nextStep: "Proceed with the next recommended playbook.",
    recommendedAction: `${title}.`,
  }
}

// -----------------------------------------------------------------------------
// Public resolver: turns a backend PlaybookAction into a fully-detailed
// Playbook by looking up (or generating) its response content.
// -----------------------------------------------------------------------------
export function resolvePlaybook(raw: PlaybookAction, index: number): Playbook {
  // The backend serializes the action name as `action`; older/typed frontend
  // code used `title`. Support both so the UI never renders an empty header.
  const title = raw.title ?? raw.action ?? "SOC Response Playbook"
  const category = (raw.category ?? "Response").toUpperCase()
  const severity = toSeverity(raw.priority)
  const key = normalize(title)
  const template = CATALOG[key] ?? buildFallback(title, category, severity)

  return {
    id: `playbook-${String(index + 1).padStart(3, "0")}`,
    category,
    severity,
    title,
    ...template,
  }
}

export function resolvePlaybooks(actions: PlaybookAction[]): Playbook[] {
  return actions.map((a, i) => resolvePlaybook(a, i))
}
