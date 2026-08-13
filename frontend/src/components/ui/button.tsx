import { ButtonHTMLAttributes, forwardRef } from "react"

import { cn } from "@/lib/utils"

type Variant = "default" | "outline" | "ghost" | "destructive"
type Size = "default" | "sm" | "lg" | "icon"

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant
  size?: Size
}

const variantClasses: Record<Variant, string> = {
  default: "bg-brand-600 text-white hover:bg-brand-700",
  outline: "border border-gray-300 dark:border-slate-700 bg-transparent hover:bg-gray-100 dark:hover:bg-slate-800",
  ghost: "bg-transparent hover:bg-gray-100 dark:hover:bg-slate-800",
  destructive: "bg-red-600 text-white hover:bg-red-700",
}

const sizeClasses: Record<Size, string> = {
  default: "h-10 px-4 py-2",
  sm: "h-8 px-3 text-sm",
  lg: "h-12 px-6 text-base",
  icon: "h-10 w-10",
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "default", size = "default", ...props }, ref) => (
    <button
      ref={ref}
      className={cn(
        "inline-flex items-center justify-center gap-2 rounded-lg font-medium transition-colors disabled:opacity-50 disabled:pointer-events-none focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500",
        variantClasses[variant],
        sizeClasses[size],
        className,
      )}
      {...props}
    />
  ),
)
Button.displayName = "Button"
