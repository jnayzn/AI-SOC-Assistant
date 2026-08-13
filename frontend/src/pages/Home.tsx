import { Link } from "react-router-dom"
import { ArrowRight, FileSearch, ShieldCheck } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"

export default function Home() {
  return (
    <div className="mx-auto flex max-w-3xl flex-col items-center gap-6 py-16 text-center">
      <div className="rounded-full bg-brand-50 p-4 dark:bg-brand-900/30">
        <ShieldCheck className="h-10 w-10 text-brand-600" />
      </div>
      <h1 className="text-3xl font-bold text-slate-800 dark:text-slate-100">
        AI-Powered Security Triage Assistant
      </h1>
      <p className="text-slate-500 dark:text-slate-400">
        Paste a phishing email, SOC alert, or system log and get an instant AI-driven threat
        classification, risk assessment, explanation, and recommended actions &mdash; built to
        help SOC analysts triage faster and with more consistency.
      </p>
      <Link to="/analyzer">
        <Button size="lg">
          <FileSearch className="h-4 w-4" /> Start Analyzing <ArrowRight className="h-4 w-4" />
        </Button>
      </Link>

      <div className="mt-8 grid w-full grid-cols-1 gap-4 text-left sm:grid-cols-3">
        <Card>
          <CardContent className="p-5">
            <h3 className="mb-1 font-semibold text-slate-800 dark:text-slate-100">Classify</h3>
            <p className="text-sm text-slate-500 dark:text-slate-400">
              Detects phishing, malware, BEC, credential theft, and more with a confidence score.
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-5">
            <h3 className="mb-1 font-semibold text-slate-800 dark:text-slate-100">Explain</h3>
            <p className="text-sm text-slate-500 dark:text-slate-400">
              Grounded reasoning citing concrete indicators and MITRE ATT&amp;CK techniques.
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-5">
            <h3 className="mb-1 font-semibold text-slate-800 dark:text-slate-100">Act</h3>
            <p className="text-sm text-slate-500 dark:text-slate-400">
              Actionable recommendations you can hand straight to SOC or the affected user.
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
