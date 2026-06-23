export type ThreatLevel = "low" | "medium" | "high" | "critical"

export type Persona = "generic_linux" | "dev_workstation" | "finance_server"

export interface ScorePoint {
  cmd_index: number
  score: number
  persona: string
  command: string
}

export interface Session {
  session_id: string
  attacker_ip: string
  threat_score: number
  threat_level: ThreatLevel
  persona: string
  command_count: number
  start_time: string
  duration_seconds: number
  score_history: ScorePoint[]
}

export interface CommandFeedItem {
  session_id: string
  session_id_full: string
  command: string
  score_delta: number
  category: string
  threat_level: ThreatLevel
  persona: string
  timestamp: string
  type: "command"
}

export interface PersonaSwitchItem {
  session_id: string
  session_id_full: string
  from_persona: string
  to_persona: string
  trigger_score: number
  timestamp: string
  type: "persona_switch"
}

export type FeedItem = CommandFeedItem | PersonaSwitchItem

export interface Stats {
  avg_duration_seconds: number
  avg_duration_display: string
  cowrie_avg_duration: string
  level3_plus_pct: number
  cowrie_level3_pct: number
  fingerprint_score: number
  fingerprint_total: number
  cowrie_fingerprint: number
  persona_switches_today: number
  unique_ips_today: number
  total_sessions_today: number
  active_sessions: number
}

export interface DashboardPayload {
  type: "update"
  sessions: Session[]
  commands: FeedItem[]
  stats: Stats
  timestamp: string
}

export type ConnectionStatus = "live" | "demo" | "connecting"
