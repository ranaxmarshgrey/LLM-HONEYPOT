"use client"

import { Gauge } from "lucide-react"
import { PanelShell } from "@/components/panel-shell"
import type { Stats } from "@/lib/types"

interface Comparison {
  label: string
  ours: number
  cowrie: number
  oursDisplay: string
  cowrieDisplay: string
  max: number
}

export function SystemStats({ stats }: { stats: Stats }) {
  const comparisons: Comparison[] = [
    {
      label: "Avg. session duration",
      ours: stats.avg_duration_seconds,
      cowrie: 44,
      oursDisplay: stats.avg_duration_display,
      cowrieDisplay: stats.cowrie_avg_duration,
      max: Math.max(stats.avg_duration_seconds, 44, 60),
    },
    {
      label: "Level 3+ engagement",
      ours: stats.level3_plus_pct,
      cowrie: stats.cowrie_level3_pct,
      oursDisplay: `${stats.level3_plus_pct}%`,
      cowrieDisplay: `${stats.cowrie_level3_pct}%`,
      max: 100,
    },
    {
      label: "Fingerprint resistance",
      ours: stats.fingerprint_score,
      cowrie: stats.cowrie_fingerprint,
      oursDisplay: `${stats.fingerprint_score}/${stats.fingerprint_total}`,
      cowrieDisplay: `${stats.cowrie_fingerprint}/${stats.fingerprint_total}`,
      max: stats.fingerprint_total,
    },
  ]

  return (
    <PanelShell title="System Performance vs Cowrie" icon={Gauge}>
      <div className="flex flex-col gap-5">
        {comparisons.map((c) => (
          <div key={c.label}>
            <div className="mb-2 flex items-center justify-between">
              <span className="text-sm font-medium">{c.label}</span>
              <span className="font-mono text-sm font-semibold text-primary tabular-nums">
                {c.oursDisplay}
              </span>
            </div>
            <Bar
              value={c.ours}
              max={c.max}
              colorVar="var(--chart-1)"
              caption="Adaptive honeypot"
              display={c.oursDisplay}
            />
            <div className="mt-2">
              <Bar
                value={c.cowrie}
                max={c.max}
                colorVar="var(--muted-foreground)"
                caption="Cowrie baseline"
                display={c.cowrieDisplay}
                muted
              />
            </div>
          </div>
        ))}
      </div>
    </PanelShell>
  )
}

function Bar({
  value,
  max,
  colorVar,
  caption,
  display,
  muted,
}: {
  value: number
  max: number
  colorVar: string
  caption: string
  display: string
  muted?: boolean
}) {
  const pct = max > 0 ? Math.min(100, (value / max) * 100) : 0
  return (
    <div className="flex items-center gap-3">
      <div className="h-2 flex-1 overflow-hidden rounded-full bg-secondary">
        <div
          className="h-full rounded-full transition-all duration-700"
          style={{ width: `${pct}%`, backgroundColor: colorVar, opacity: muted ? 0.55 : 1 }}
        />
      </div>
      <span className="w-28 shrink-0 text-xs text-muted-foreground">
        {caption}: <span className="font-mono">{display}</span>
      </span>
    </div>
  )
}
