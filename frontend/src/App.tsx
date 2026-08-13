import { Route, Routes } from "react-router-dom"

import MainLayout from "@/layouts/MainLayout"
import About from "@/pages/About"
import Analyzer from "@/pages/Analyzer"
import Dashboard from "@/pages/Dashboard"
import History from "@/pages/History"
import HistoryDetail from "@/pages/HistoryDetail"
import Home from "@/pages/Home"
import Settings from "@/pages/Settings"

export default function App() {
  return (
    <Routes>
      <Route element={<MainLayout />}>
        <Route index element={<Home />} />
        <Route path="dashboard" element={<Dashboard />} />
        <Route path="analyzer" element={<Analyzer />} />
        <Route path="history" element={<History />} />
        <Route path="history/:id" element={<HistoryDetail />} />
        <Route path="settings" element={<Settings />} />
        <Route path="about" element={<About />} />
      </Route>
    </Routes>
  )
}
