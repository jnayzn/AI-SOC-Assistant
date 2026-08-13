import { Lock } from "lucide-react"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

export function ExternalIntelPlaceholder({ name }: { name: string }) {
  return (
    <Card className="border-dashed">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-sm text-slate-500 dark:text-slate-400">
          <Lock className="h-4 w-4" /> {name}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <p className="text-xs text-slate-400 dark:text-slate-500">
          Unavailable &mdash; API key not configured.
        </p>
      </CardContent>
    </Card>
  )
}
