import { describe, expect, it } from "vitest"
import { render, screen } from "@testing-library/react"

import { ThreatIntelPanel } from "@/components/ThreatIntelPanel"
import type { ThreatIntelEnrichment } from "@/types/analysis"

describe("ThreatIntelPanel", () => {
  it("shows a not-configured placeholder for every unconfigured source", () => {
    render(<ThreatIntelPanel threatIntel={null} />)

    expect(screen.getByText("VirusTotal")).toBeInTheDocument()
    expect(screen.getByText("Shodan")).toBeInTheDocument()
    expect(screen.getByText("AbuseIPDB")).toBeInTheDocument()
    expect(screen.getAllByText(/API key not configured/i)).toHaveLength(3)
  })

  it("renders a finding under the matching source card", () => {
    const threatIntel: ThreatIntelEnrichment = {
      virustotal_configured: false,
      shodan_configured: false,
      abuseipdb_configured: true,
      local_findings: [],
      findings: [
        {
          source: "AbuseIPDB",
          indicator: "1.2.3.4",
          indicator_type: "ip",
          verdict: "Malicious",
          summary: "Abuse confidence 90/100 from 42 report(s), US.",
          checked_at: "2025-01-01T00:00:00Z",
        },
      ],
    }

    render(<ThreatIntelPanel threatIntel={threatIntel} />)

    expect(screen.getByText("1.2.3.4")).toBeInTheDocument()
    expect(screen.getByText(/Abuse confidence 90\/100/)).toBeInTheDocument()
    expect(screen.getByText("Malicious")).toBeInTheDocument()
  })
})
