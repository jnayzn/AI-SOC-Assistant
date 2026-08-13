import { ShieldAlert } from "lucide-react"

import { ThemeToggle } from "@/components/ThemeToggle"

export function Navbar() {
  return (
    <header className="glass-surface sticky top-0 z-40 flex h-16 items-center justify-between border-b px-6 shadow-sm">
      <div className="flex items-center gap-2 text-slate-500 dark:text-slate-400">
        <ShieldAlert className="h-5 w-5 text-brand-600 drop-shadow-sm" />
        <span className="bg-gradient-to-r from-slate-700 to-brand-700 bg-clip-text text-sm font-semibold text-transparent dark:from-slate-200 dark:to-brand-400">
          AI-Powered Security Triage Assistant
        </span>
      </div>
      <div className="flex items-center gap-3">
        <ThemeToggle />
      </div>
    </header>
  )
}
