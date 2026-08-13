import { NavLink } from "react-router-dom"
import { BarChart3, FileSearch, History, Home, Info, Settings, ShieldCheck } from "lucide-react"

import { cn } from "@/lib/utils"

const NAV_ITEMS = [
  { to: "/", label: "Home", icon: Home, end: true },
  { to: "/dashboard", label: "Dashboard", icon: BarChart3 },
  { to: "/analyzer", label: "Analyzer", icon: FileSearch },
  { to: "/history", label: "History", icon: History },
  { to: "/settings", label: "Settings", icon: Settings },
  { to: "/about", label: "About", icon: Info },
]

export function Sidebar() {
  return (
    <aside className="glass-surface hidden w-60 shrink-0 border-r md:flex md:flex-col">
      <div className="flex items-center gap-2 px-5 py-5">
        <ShieldCheck className="h-7 w-7 text-brand-600 drop-shadow-sm" />
        <span className="text-sm font-bold leading-tight text-slate-800 dark:text-slate-100">
          Security Triage
          <br />
          Assistant
        </span>
      </div>
      <nav className="flex flex-1 flex-col gap-1 px-3">
        {NAV_ITEMS.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-all duration-200",
                isActive
                  ? "bg-gradient-to-r from-brand-50 to-brand-100/60 text-brand-700 shadow-sm dark:from-brand-900/40 dark:to-brand-900/10 dark:text-brand-300"
                  : "text-slate-600 hover:translate-x-0.5 hover:bg-gray-100 dark:text-slate-300 dark:hover:bg-slate-800",
              )
            }
          >
            <Icon className="h-4 w-4" />
            {label}
          </NavLink>
        ))}
      </nav>
      <div className="px-5 py-4 text-xs text-slate-400">v1.0.0 &middot; Enterprise SOC Build</div>
    </aside>
  )
}
