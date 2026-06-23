import { ShieldHalf, Radio } from "lucide-react"
import { cn } from "@/lib/utils"
import type { ConnectionStatus } from "@/lib/types"

export function DashboardHeader({
  status,
  timestamp,
}: {
  status: ConnectionStatus
  timestamp?: string
}) {
  const isLive = status === "live"
  const label =
    status === "live" ? "Live" : status === "demo" ? "Demo feed" : "Connecting"

  return (
    <header className="flex flex-col gap-4 border-b border-border pb-6 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex items-center gap-3">
        <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-primary text-primary-foreground">
          <ShieldHalf className="h-6 w-6" aria-hidden="true" />
        </div>
        <div>
          <h1 className="text-balance text-xl font-semibold tracking-tight sm:text-2xl">
            Adaptive Honeypot
          </h1>
          <p className="text-sm text-muted-foreground">
            Live threat intelligence &amp; deception telemetry
          </p>
        </div>
      </div>

      <div className="flex items-center gap-3">
        {timestamp ? (
          <span className="hidden text-xs text-muted-foreground sm:inline">
            Updated{" "}
            {new Date(timestamp).toLocaleTimeString("en-US", { hour12: false })}
          </span>
        ) : null}
        <span
          className={cn(
            "inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-medium",
            isLive
              ? "border-low/40 bg-low/10 text-low-foreground"
              : "border-border bg-secondary text-secondary-foreground",
          )}
        >
          <span
            className={cn(
              "h-2 w-2 rounded-full",
              isLive ? "bg-low live-dot" : "bg-muted-foreground",
            )}
            aria-hidden="true"
          />
          {label}
          <Radio className="h-3.5 w-3.5" aria-hidden="true" />
        </span>
      </div>
    </header>
  )
}
