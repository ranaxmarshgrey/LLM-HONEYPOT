"use client"

import { LineChart as LineChartIcon } from "lucide-react"
import {
  Area,
  AreaChart,
  CartesianGrid,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts"
import { PanelShell } from "@/components/panel-shell"
import { personaLabel } from "@/lib/format"
import type { Session } from "@/lib/types"

export function ThreatTimeline({ session }: { session: Session | null }) {
  const data =
    session?.score_history.map((p) => ({
      cmd: p.cmd_index,
      score: p.score,
      command: p.command,
    })) ?? []

  return (
    <PanelShell
      title="Threat Score Timeline"
      icon={LineChartIcon}
      action={
        session ? (
          <span className="font-mono text-xs text-muted-foreground">
            {session.attacker_ip} · {personaLabel(session.persona)}
          </span>
        ) : null
      }
      bodyClassName="flex flex-col"
    >
      {!session || data.length === 0 ? (
        <div className="flex h-full min-h-48 items-center justify-center text-sm text-muted-foreground">
          Select a session to view its threat escalation.
        </div>
      ) : (
        <div className="flex h-full min-h-48 flex-col">
          <div className="flex-1">
            <ResponsiveContainer width="100%" height="100%" minHeight={200}>
              <AreaChart
                data={data}
                margin={{ top: 8, right: 8, bottom: 0, left: -16 }}
              >
                <defs>
                  <linearGradient id="scoreFill" x1="0" y1="0" x2="0" y2="1">
                    <stop
                      offset="0%"
                      stopColor="var(--chart-1)"
                      stopOpacity={0.35}
                    />
                    <stop
                      offset="100%"
                      stopColor="var(--chart-1)"
                      stopOpacity={0.02}
                    />
                  </linearGradient>
                </defs>
                <CartesianGrid
                  strokeDasharray="3 3"
                  stroke="var(--border)"
                  vertical={false}
                />
                <XAxis
                  dataKey="cmd"
                  stroke="var(--muted-foreground)"
                  fontSize={11}
                  tickLine={false}
                  axisLine={false}
                />
                <YAxis
                  domain={[0, 100]}
                  stroke="var(--muted-foreground)"
                  fontSize={11}
                  tickLine={false}
                  axisLine={false}
                  width={36}
                />
                <ReferenceLine y={30} stroke="var(--medium)" strokeDasharray="4 4" />
                <ReferenceLine y={60} stroke="var(--high)" strokeDasharray="4 4" />
                <ReferenceLine y={85} stroke="var(--critical)" strokeDasharray="4 4" />
                <Tooltip content={<ChartTooltip />} />
                <Area
                  type="monotone"
                  dataKey="score"
                  stroke="var(--chart-1)"
                  strokeWidth={2}
                  fill="url(#scoreFill)"
                  isAnimationActive={false}
                  dot={{ r: 2, fill: "var(--chart-1)" }}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <Legend />
        </div>
      )}
    </PanelShell>
  )
}

function Legend() {
  const items = [
    { label: "Medium 30+", color: "var(--medium)" },
    { label: "High 60+", color: "var(--high)" },
    { label: "Critical 85+", color: "var(--critical)" },
  ]
  return (
    <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
      {items.map((i) => (
        <span key={i.label} className="flex items-center gap-1.5">
          <span
            className="h-0.5 w-4 rounded-full"
            style={{ backgroundColor: i.color }}
          />
          {i.label}
        </span>
      ))}
    </div>
  )
}

function ChartTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean
  payload?: Array<{ payload: { command: string; score: number } }>
  label?: number | string
}) {
  if (!active || !payload || payload.length === 0) return null
  const point = payload[0].payload
  return (
    <div className="rounded-lg border border-border bg-popover px-3 py-2 text-xs shadow-md">
      <div className="font-medium text-popover-foreground">
        Command #{label} · score {point.score}
      </div>
      <div className="mt-0.5 font-mono text-muted-foreground">{point.command}</div>
    </div>
  )
}
