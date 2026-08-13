// OWASP Top 10 (2021) reference catalog used to render the OWASP Mapping
// panel with professional, standardized detail. Keyed by OWASP category code.
export interface OwaspReference {
  attackVector: string
  description: string
  impact: string
  recommendation: string
  references: string[]
}

export const OWASP_CATALOG: Record<string, OwaspReference> = {
  "A01:2021": {
    "attackVector": "Abuse of missing or flawed authorization checks to access resources or perform actions outside intended permissions.",
    "description": "Attackers bypass access-control enforcement to view or modify other users' data, escalate privileges, or reach restricted functionality.",
    "impact": "Unauthorized data access, privilege escalation, data tampering, and full account or system compromise.",
    "recommendation": "Enforce deny-by-default authorization server-side, apply least privilege, validate resource ownership on every request, and log access-control failures.",
    "references": [
      "OWASP Top 10 — A01:2021",
      "OWASP Authorization Cheat Sheet"
    ]
  },
  "A02:2021": {
    "attackVector": "Interception or recovery of sensitive data protected by weak, misconfigured, or missing cryptography.",
    "description": "Attackers exploit cleartext transmission, weak algorithms, or poor key management to expose sensitive data such as credentials or PII.",
    "impact": "Exposure of sensitive data, credential theft, regulatory non-compliance, and loss of confidentiality.",
    "recommendation": "Encrypt data in transit and at rest with strong algorithms, enforce TLS, manage keys securely, and retire deprecated ciphers.",
    "references": [
      "OWASP Top 10 — A02:2021",
      "OWASP Transport Layer Security Cheat Sheet"
    ]
  },
  "A03:2021": {
    "attackVector": "Submission of untrusted input that is interpreted as commands or queries by an interpreter (SQL, OS, LDAP, etc.).",
    "description": "Attackers inject malicious payloads that the application executes, enabling data theft, manipulation, or remote code execution.",
    "impact": "Data breach, data loss or corruption, authentication bypass, and potential host compromise.",
    "recommendation": "Use parameterized queries, validate and sanitize input, apply allow-lists, and escape output for the target interpreter.",
    "references": [
      "OWASP Top 10 — A03:2021",
      "OWASP Injection Prevention Cheat Sheet"
    ]
  },
  "A04:2021": {
    "attackVector": "Exploitation of missing or ineffective security controls that stem from flawed design rather than implementation bugs.",
    "description": "Attackers abuse business logic and design gaps that were never protected by threat modeling or secure design patterns.",
    "impact": "Systemic weaknesses, business-logic abuse, and vulnerabilities that cannot be fully fixed by code patching alone.",
    "recommendation": "Apply threat modeling, secure design patterns, reference architectures, and explicit security requirements across the SDLC.",
    "references": [
      "OWASP Top 10 — A04:2021",
      "OWASP Threat Modeling Cheat Sheet"
    ]
  },
  "A05:2021": {
    "attackVector": "Exploitation of insecure default settings, verbose errors, open ports, or unhardened components.",
    "description": "Attackers leverage misconfigured services, unnecessary features, or missing hardening to gain access or disclose information.",
    "impact": "Unauthorized access, information disclosure, and a broadened attack surface across the environment.",
    "recommendation": "Harden and patch all components, disable unused features, enforce secure defaults, and automate configuration reviews.",
    "references": [
      "OWASP Top 10 — A05:2021",
      "OWASP Configuration Cheat Sheet"
    ]
  },
  "A06:2021": {
    "attackVector": "Exploitation of known vulnerabilities (CVEs) in outdated libraries, frameworks, or dependencies.",
    "description": "Attackers target unpatched third-party components with publicly available exploits to compromise the application.",
    "impact": "Remote code execution, data breach, and full system compromise via known exploit chains.",
    "recommendation": "Maintain a software inventory (SBOM), monitor for CVEs, patch promptly, and remove unused dependencies.",
    "references": [
      "OWASP Top 10 — A06:2021",
      "OWASP Dependency-Check"
    ]
  },
  "A07:2021": {
    "attackVector": "Abuse of weak authentication, credential stuffing, brute force, or session-management flaws.",
    "description": "Attackers compromise credentials or sessions to impersonate users, often via phishing, weak passwords, or missing MFA.",
    "impact": "Account takeover, unauthorized access, identity theft, and lateral movement.",
    "recommendation": "Enforce MFA, strong password policies, secure session handling, and protections against automated credential attacks.",
    "references": [
      "OWASP Top 10 — A07:2021",
      "OWASP Authentication Cheat Sheet"
    ]
  },
  "A08:2021": {
    "attackVector": "Injection of untrusted code or data through insecure CI/CD pipelines, software updates, or deserialization.",
    "description": "Attackers tamper with updates, dependencies, or serialized objects that the application trusts without verification.",
    "impact": "Supply-chain compromise, remote code execution, and unauthorized data or code modification.",
    "recommendation": "Verify integrity with digital signatures, secure the CI/CD pipeline, and avoid insecure deserialization of untrusted data.",
    "references": [
      "OWASP Top 10 — A08:2021",
      "OWASP Deserialization Cheat Sheet"
    ]
  },
  "A09:2021": {
    "attackVector": "Exploitation of insufficient logging and monitoring controls to execute malicious actions undetected.",
    "description": "Attackers leverage inadequate logging and monitoring to perform activities such as command-and-control (C2) communication and data exfiltration without triggering alerts.",
    "impact": "Delayed detection, data breach, loss of sensitive information, and regulatory non-compliance.",
    "recommendation": "Implement comprehensive logging, real-time monitoring, centralized log collection, and alerting for anomalous network behavior and suspicious outbound connections.",
    "references": [
      "OWASP Top 10 — A09:2021",
      "OWASP Logging Cheat Sheet"
    ]
  },
  "A10:2021": {
    "attackVector": "Coercion of the server into making unintended requests to internal or external resources via user-controlled URLs.",
    "description": "Attackers abuse server-side fetch functionality to reach internal services, cloud metadata endpoints, or other protected systems.",
    "impact": "Internal reconnaissance, access to sensitive metadata or credentials, and pivoting into internal networks.",
    "recommendation": "Validate and allow-list outbound destinations, block internal IP ranges, disable unused URL schemes, and enforce network segmentation.",
    "references": [
      "OWASP Top 10 — A10:2021",
      "OWASP SSRF Prevention Cheat Sheet"
    ]
  }
}
