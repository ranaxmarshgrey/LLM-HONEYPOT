import {
  Activity,
  Network,
  Flame,
  Repeat,
  Fingerprint,
  type LucideIcon,
} from "lucide-react"
import { cn } from "@/lib/utils"
import type { Session, Stats } from "@/lib/types"

interface KpiCardProps {
  label: string
  value: string
  sub: string
  icon: LucideIcon
  accent?: "primary" | "low" | "medium" | "high" | "critical"
}

const accentMap: Record<NonNullable<KpiCardProps["accent"]>, string> = {
  primary: "bg-primary/10 text-primary",
  low: "bg-low/15 text-low-foreground",
  medium: "bg-medium/20 text-medium-foreground",
  high: "bg-high/15 text-high",
  critical: "bg-critical/15 text-critical",
}

function KpiCard({ label, value, sub, icon: Icon, accent = "primary" }: KpiCardProps) {
  return (
    <div className="flex flex-col gap-3 rounded-xl border border-border bg-card p-5 shadow-sm">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium text-muted-foreground">{label}</span>
        <span
          className={cn(
            "flex h-9 w-9 items-center justify-center rounded-lg",
            accentMap[accent],
          )}
        >
          <Icon className="h-5 w-5" aria-hidden="true" />
        </span>
      </div>
      <div>
        <div className="text-3xl font-semibold tracking-tight tabular-nums">
          {value}
        </div>
        <p className="mt-1 text-xs text-muted-foreground">{sub}</p>
      </div>
    </div>
  )
}

export function KpiRow({
  stats,
  sessions,
}: {
  stats: Stats
  sessions: Session[]
}) {
  const criticalCount = sessions.filter(
    (s) => s.threat_level === "critical" || s.threat_level === "high",
  ).length
  const topScore = sessions.reduce((max, s) => Math.max(max, s.threat_score), 0)

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
      <KpiCard
        label="Active sessions"
        value={String(stats.active_sessions)}
        sub={`${stats.total_sessions_today} total today`}
        icon={Activity}
        accent="primary"
      />
      <KpiCard
        label="High / critical"
        value={String(criticalCount)}
        sub={`peak threat score ${topScore}`}
        icon={Flame}
        accent={criticalCount > 0 ? "critical" : "low"}
      />
      <KpiCard
        label="Unique attacker IPs"
        value={String(stats.unique_ips_today)}
        sub="distinct sources today"
        icon={Network}
        accent="medium"
      />
      <KpiCard
        label="Persona switches"
        value={String(stats.persona_switches_today)}
        sub="adaptive deceptions today"
        icon={Repeat}
        accent="high"
      />
      <KpiCard
        label="Fingerprint resistance"
        value={`${stats.fingerprint_score}/${stats.fingerprint_total}`}
        sub={`vs Cowrie ${stats.cowrie_fingerprint}/${stats.fingerprint_total}`}
        icon={Fingerprint}
        accent="low"
      />
    </div>
  )
}
