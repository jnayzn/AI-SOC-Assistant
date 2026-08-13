import { motion } from "framer-motion"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

export function AttackTimeline({ steps }: { steps: string[] }) {
  if (!steps.length) return null
  return (
    <Card>
      <CardHeader>
        <CardTitle>Attack Timeline</CardTitle>
      </CardHeader>
      <CardContent>
        <ol className="relative ml-3 flex flex-col gap-5 border-l-2 border-brand-100 dark:border-brand-900/50">
          {steps.map((step, idx) => (
            <motion.li
              key={step}
              className="relative pl-5"
              initial={{ opacity: 0, x: -12 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.35, delay: idx * 0.12, ease: "easeOut" }}
            >
              <motion.span
                className="absolute -left-[9px] top-0.5 flex h-4 w-4 items-center justify-center rounded-full bg-brand-500 text-[10px] font-bold text-white"
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ duration: 0.25, delay: idx * 0.12 + 0.1, type: "spring", stiffness: 300 }}
              >
                {idx + 1}
              </motion.span>
              <span className="text-sm text-slate-700 dark:text-slate-200">{step}</span>
            </motion.li>
          ))}
        </ol>
      </CardContent>
    </Card>
  )
}
