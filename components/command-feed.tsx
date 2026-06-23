"use client"

import { ScrollText, Repeat } from "lucide-react"
import { cn } from "@/lib/utils"
import { clockTime, personaLabel, threatTextClass } from "@/lib/format"
import { ThreatBadge } from "@/components/threat-badge"
import { PanelShell } from "@/components/panel-shell"
import type { FeedItem } from "@/lib/types"

export function CommandFeed({ items }: { items: FeedItem[] }) {
  // newest first
  const ordered = [...items].reverse()

  return (
    <PanelShell title="Live Command Feed" icon={ScrollText} bodyClassName="p-0">
      {ordered.length === 0 ? (
        <div className="flex h-full min-h-40 items-center justify-center p-4 text-sm text-muted-foreground">
          Waiting for attacker activity…
        </div>
      ) : (
        <ul className="divide-y divide-border">
          {ordered.map((item, idx) =>
            item.type === "persona_switch" ? (
              <li
                key={`${item.session_id}-${item.timestamp}-${idx}`}
                className="animate-feed-in flex items-center gap-3 bg-primary/5 px-4 py-2.5"
              >
                <Repeat
                  className="h-4 w-4 shrink-0 text-primary"
                  aria-hidden="true"
                />
                <div className="min-w-0 flex-1 text-sm">
                  <span className="font-medium text-primary">
                    Persona switch
                  </span>{" "}
                  <span className="text-muted-foreground">
                    {personaLabel(item.from_persona)} →{" "}
                    {personaLabel(item.to_persona)} @ score {item.trigger_score}
                  </span>
                </div>
                <span className="shrink-0 font-mono text-xs text-muted-foreground">
                  {clockTime(item.timestamp)}
                </span>
              </li>
            ) : (
              <li
                key={`${item.session_id}-${item.timestamp}-${idx}`}
                className="animate-feed-in flex items-center gap-3 px-4 py-2.5"
              >
                <span className="hidden shrink-0 font-mono text-xs text-muted-foreground sm:inline">
                  {item.session_id}
                </span>
                <code className="min-w-0 flex-1 truncate font-mono text-sm">
                  {item.command}
                </code>
                <span
                  className={cn(
                    "shrink-0 font-mono text-xs font-semibold tabular-nums",
                    item.score_delta > 0
                      ? threatTextClass(item.threat_level)
                      : "text-muted-foreground",
                  )}
                >
                  {item.score_delta > 0 ? `+${item.score_delta}` : item.score_delta}
                </span>
                <ThreatBadge level={item.threat_level} className="shrink-0" />
                <span className="hidden shrink-0 font-mono text-xs text-muted-foreground md:inline">
                  {clockTime(item.timestamp)}
                </span>
              </li>
            ),
          )}
        </ul>
      )}
    </PanelShell>
  )
}
