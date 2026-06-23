"use client"

import { Terminal } from "lucide-react"
import { cn } from "@/lib/utils"
import {
  formatDuration,
  personaLabel,
  threatBarVar,
} from "@/lib/format"
import { ThreatBadge } from "@/components/threat-badge"
import { PanelShell } from "@/components/panel-shell"
import type { Session } from "@/lib/types"

export function ActiveSessions({
  sessions,
  selectedId,
  onSelect,
}: {
  sessions: Session[]
  selectedId: string | null
  onSelect: (id: string) => void
}) {
  return (
    <PanelShell
      title="Active Sessions"
      count={sessions.length}
      icon={Terminal}
    >
      {sessions.length === 0 ? (
        <EmptyState />
      ) : (
        <ul className="flex flex-col gap-2">
          {sessions.map((s) => {
            const selected = s.session_id === selectedId
            return (
              <li key={s.session_id}>
                <button
                  type="button"
                  onClick={() => onSelect(s.session_id)}
                  className={cn(
                    "w-full rounded-lg border p-3 text-left transition-colors",
                    selected
                      ? "border-primary/50 bg-primary/5"
                      : "border-border bg-card hover:bg-accent",
                  )}
                  aria-pressed={selected}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-sm font-medium">
                      {s.attacker_ip}
                    </span>
                    <ThreatBadge level={s.threat_level} />
                  </div>

                  <div className="mt-1 flex items-center gap-2 text-xs text-muted-foreground">
                    <span className="font-mono">{s.session_id.slice(0, 8)}</span>
                    <span aria-hidden="true">•</span>
                    <span>{personaLabel(s.persona)}</span>
                  </div>

                  <div className="mt-2.5 flex items-center gap-3">
                    <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-secondary">
                      <div
                        className="h-full rounded-full transition-all duration-500"
                        style={{
                          width: `${Math.min(100, s.threat_score)}%`,
                          backgroundColor: threatBarVar(s.threat_level),
                        }}
                      />
                    </div>
                    <span className="w-8 text-right font-mono text-sm font-semibold tabular-nums">
                      {s.threat_score}
                    </span>
                  </div>

                  <div className="mt-2 flex items-center justify-between text-xs text-muted-foreground">
                    <span>{s.command_count} commands</span>
                    <span className="tabular-nums">
                      {formatDuration(s.duration_seconds)}
                    </span>
                  </div>
                </button>
              </li>
            )
          })}
        </ul>
      )}
    </PanelShell>
  )
}

function EmptyState() {
  return (
    <div className="flex h-full min-h-40 flex-col items-center justify-center gap-2 text-center text-sm text-muted-foreground">
      <Terminal className="h-6 w-6 opacity-50" aria-hidden="true" />
      <p>No active attacker sessions.</p>
    </div>
  )
}
