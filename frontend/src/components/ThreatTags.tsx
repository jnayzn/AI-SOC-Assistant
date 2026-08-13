import { Badge } from "@/components/ui/badge"

export function ThreatTags({ tags }: { tags: string[] }) {
  if (!tags.length) return null
  return (
    <div className="flex flex-wrap gap-2">
      {tags.map((tag) => (
        <Badge
          key={tag}
          className="bg-brand-50 text-brand-700 dark:bg-brand-900/30 dark:text-brand-300"
        >
          {tag}
        </Badge>
      ))}
    </div>
  )
}
