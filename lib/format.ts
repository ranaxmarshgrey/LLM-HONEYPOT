import type { ThreatLevel } from "./types"

export function personaLabel(persona: string): string {
  switch (persona) {
    case "generic_linux":
      return "Generic Linux"
    case "dev_workstation":
      return "Dev Workstation"
    case "finance_server":
      return "Finance Server"
    default:
      return persona
  }
}

export function threatTextClass(level: ThreatLevel): string {
  switch (level) {
    case "critical":
      return "text-critical"
    case "high":
      return "text-high"
    case "medium":
      return "text-medium-foreground"
    default:
      return "text-low-foreground"
  }
}

/** Returns tailwind classes for a threat-level pill. */
export function threatBadgeClass(level: ThreatLevel): string {
  switch (level) {
    case "critical":
      return "bg-critical text-critical-foreground"
    case "high":
      return "bg-high/15 text-high border border-high/30"
    case "medium":
      return "bg-medium/20 text-medium-foreground border border-medium/40"
    default:
      return "bg-low/15 text-low-foreground border border-low/30"
  }
}

/** Bar/track color for a threat level. */
export function threatBarVar(level: ThreatLevel): string {
  switch (level) {
    case "critical":
      return "var(--critical)"
    case "high":
      return "var(--high)"
    case "medium":
      return "var(--medium)"
    default:
      return "var(--low)"
  }
}

export function formatDuration(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds))
  const m = Math.floor(s / 60)
  const rem = s % 60
  if (m === 0) return `${rem}s`
  return `${m}m ${String(rem).padStart(2, "0")}s`
}

export function relativeTime(iso: string): string {
  const then = new Date(iso).getTime()
  const diff = Math.max(0, Date.now() - then)
  const s = Math.floor(diff / 1000)
  if (s < 5) return "just now"
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  return `${h}h ago`
}

export function clockTime(iso: string): string {
  return new Date(iso).toLocaleTimeString("en-US", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  })
}
