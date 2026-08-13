import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

export default function About() {
  return (
    <div className="flex max-w-2xl flex-col gap-6">
      <h1 className="text-xl font-bold text-slate-800 dark:text-slate-100">About</h1>
      <Card>
        <CardHeader>
          <CardTitle>AI-Powered Security Triage Assistant</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-3 text-sm text-slate-600 dark:text-slate-300">
          <p>
            This project was built as a cybersecurity internship deliverable. It demonstrates an
            end-to-end, production-style AI application that classifies phishing emails, SOC
            alerts, and security logs using a Large Language Model, with a FastAPI backend and a
            React + TypeScript dashboard inspired by Microsoft Security Copilot.
          </p>
          <p>
            <strong>Backend:</strong> Python 3.12, FastAPI, LangChain, OpenAI API, SQLAlchemy,
            Alembic, PostgreSQL.
          </p>
          <p>
            <strong>Frontend:</strong> React, TypeScript, Vite, Tailwind CSS, shadcn/ui-style
            components, Recharts.
          </p>
          <p>
            <strong>Security:</strong> input sanitization, prompt-injection/jailbreak heuristics,
            rate limiting, CORS, structured logging, and JWT-based authentication.
          </p>
        </CardContent>
      </Card>
    </div>
  )
}
