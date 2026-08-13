import { HTMLAttributes } from "react"

import { cn } from "@/lib/utils"

export function Skeleton({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn("animate-pulse rounded-md bg-gray-200 dark:bg-slate-800", className)}
      {...props}
    />
  )
}

export function CardSkeleton({ lines = 3 }: { lines?: number }) {
  return (
    <div className="rounded-xl border border-gray-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900">
      <Skeleton className="mb-4 h-4 w-1/3" />
      <div className="flex flex-col gap-2">
        {Array.from({ length: lines }).map((_, i) => (
          <Skeleton key={i} className="h-3 w-full" />
        ))}
      </div>
    </div>
  )
}

export function StatCardSkeleton() {
  return (
    <div className="flex items-center justify-between rounded-xl border border-gray-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900">
      <div className="flex flex-col gap-2">
        <Skeleton className="h-3 w-24" />
        <Skeleton className="h-6 w-16" />
      </div>
      <Skeleton className="h-12 w-12 rounded-full" />
    </div>
  )
}
