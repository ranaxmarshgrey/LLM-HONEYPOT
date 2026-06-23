"use client"

import { useEffect, useMemo, useState } from "react"
import { useHoneypotData } from "@/lib/use-honeypot-data"
import { DashboardHeader } from "@/components/dashboard-header"
import { KpiRow } from "@/components/kpi-row"
import { ActiveSessions } from "@/components/active-sessions"
import { ThreatTimeline } from "@/components/threat-timeline"
import { CommandFeed } from "@/components/command-feed"
import { SystemStats } from "@/components/system-stats"

export default function DashboardPage() {
  const { data, status } = useHoneypotData()
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const sessions = data?.sessions ?? []

  // Auto-select the highest-threat session when nothing is selected
  // or when the selected session ends.
  useEffect(() => {
    if (sessions.length === 0) {
      setSelectedId(null)
      return
    }
    const stillActive = sessions.some((s) => s.session_id === selectedId)
    if (!stillActive) {
      setSelectedId(sessions[0].session_id)
    }
  }, [sessions, selectedId])

  const selectedSession = useMemo(
    () => sessions.find((s) => s.session_id === selectedId) ?? null,
    [sessions, selectedId],
  )

  return (
    <main className="mx-auto flex min-h-screen w-full max-w-[1500px] flex-col gap-6 px-4 py-6 sm:px-6 lg:px-8">
      <DashboardHeader status={status} timestamp={data?.timestamp} />

      {data ? (
        <>
          <KpiRow stats={data.stats} sessions={sessions} />

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <div className="lg:col-span-1 lg:row-span-2 lg:max-h-[640px]">
              <ActiveSessions
                sessions={sessions}
                selectedId={selectedId}
                onSelect={setSelectedId}
              />
            </div>

            <div className="h-[300px] lg:col-span-2">
              <ThreatTimeline session={selectedSession} />
            </div>

            <div className="h-[300px] lg:col-span-2">
              <CommandFeed items={data.commands} />
            </div>
          </div>

          <SystemStats stats={data.stats} />
        </>
      ) : (
        <LoadingState />
      )}
    </main>
  )
}

function LoadingState() {
  return (
    <div className="grid flex-1 place-items-center py-24 text-sm text-muted-foreground">
      Establishing connection to honeypot telemetry…
    </div>
  )
}
