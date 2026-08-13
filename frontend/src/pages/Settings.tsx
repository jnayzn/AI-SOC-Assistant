import { useState } from "react"

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { useTheme } from "@/hooks/useTheme"

export default function Settings() {
  const { theme, toggleTheme } = useTheme()
  const [model, setModel] = useState(
    () => localStorage.getItem("preferred_model") || "gpt-4o-mini",
  )
  const [saved, setSaved] = useState(false)

  function handleSave() {
    localStorage.setItem("preferred_model", model)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  return (
    <div className="flex max-w-xl flex-col gap-6">
      <h1 className="text-xl font-bold text-slate-800 dark:text-slate-100">Settings</h1>

      <Card>
        <CardHeader>
          <CardTitle>Appearance</CardTitle>
        </CardHeader>
        <CardContent className="flex items-center justify-between">
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Current theme: <strong>{theme === "light" ? "Light" : "Dark"}</strong>
          </p>
          <Button variant="outline" onClick={toggleTheme}>
            Switch to {theme === "light" ? "Dark" : "Light"} Mode
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Model Preference</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <select
            value={model}
            onChange={(e) => setModel(e.target.value)}
            className="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-800"
          >
            <optgroup label="OpenAI (requires OPENAI_API_KEY)">
              <option value="gpt-4o-mini">gpt-4o-mini (fast, cost-effective)</option>
              <option value="gpt-4o">gpt-4o (higher accuracy)</option>
            </optgroup>
            <optgroup label="Ollama (local, no API key needed)">
              <option value="llama3.2-vision">llama3.2-vision (default, matches backend)</option>
              <option value="llama3.2">llama3.2 (lighter, text-only)</option>
              <option value="llama3.1">llama3.1</option>
              <option value="mistral">mistral</option>
            </optgroup>
          </select>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            This preference is stored locally for reference only. To actually change the
            model the backend uses, set <code>LLM_PROVIDER</code> and{" "}
            <code>OPENAI_MODEL</code> / <code>OLLAMA_MODEL</code> in <code>backend/.env</code>{" "}
            and restart the backend container.
          </p>
          <Button onClick={handleSave} className="self-start">
            {saved ? "Saved!" : "Save Preference"}
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}
