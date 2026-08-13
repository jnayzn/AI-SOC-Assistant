import { Outlet } from "react-router-dom"

import { CopilotChat } from "@/components/CopilotChat"
import { Navbar } from "@/components/Navbar"
import { Sidebar } from "@/components/Sidebar"
import { CopilotProvider } from "@/context/CopilotContext"

export default function MainLayout() {
  return (
    <CopilotProvider>
      <div className="flex h-screen w-full overflow-hidden">
        <Sidebar />
        <div className="flex min-w-0 flex-1 flex-col">
          <Navbar />
          <main className="flex-1 overflow-y-auto p-6">
            <Outlet />
          </main>
        </div>
        <CopilotChat />
      </div>
    </CopilotProvider>
  )
}
