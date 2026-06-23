import type { LucideIcon } from "lucide-react"
import { cn } from "@/lib/utils"

export function PanelShell({
  title,
  count,
  icon: Icon,
  action,
  bodyClassName,
  children,
}: {
  title: string
  count?: number
  icon: LucideIcon
  action?: React.ReactNode
  bodyClassName?: string
  children: React.ReactNode
}) {
  return (
    <section className="flex h-full min-h-0 flex-col rounded-xl border border-border bg-card shadow-sm">
      <div className="flex items-center justify-between gap-2 border-b border-border px-4 py-3">
        <div className="flex items-center gap-2">
          <Icon className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
          <h2 className="text-sm font-semibold tracking-tight">{title}</h2>
          {typeof count === "number" ? (
            <span className="rounded-full bg-secondary px-2 py-0.5 text-xs font-medium text-secondary-foreground tabular-nums">
              {count}
            </span>
          ) : null}
        </div>
        {action}
      </div>
      <div className={cn("min-h-0 flex-1 overflow-y-auto p-4", bodyClassName)}>
        {children}
      </div>
    </section>
  )
}
