"use client"

import { useEffect, useState } from "react"
import { Play, Square, Terminal, Shield, Cpu, Layers, CheckCircle2, Loader2, Sparkles, RefreshCw, Zap } from "lucide-react"
import { PanelShell } from "@/components/panel-shell"
import type { ScriptItem } from "@/lib/types"

const DASHBOARD_URL = process.env.NEXT_PUBLIC_DASHBOARD_URL || "http://127.0.0.1:8080"

const BUILTIN_SCRIPTS: ScriptItem[] = [
  {
    id: "demo_session",
    title: "1. Panel Presentation Demo 1 (Standard Persona Switch)",
    category: "Panel Presentation",
    script: "scripts/demo_session.py",
    args: [],
    command_count: 10,
    estimated_duration: "15s",
    attack_pattern: "Recon -> Exploration -> Sensitive File Exfiltration -> Persona Switch Trigger",
    design_patterns: ["Facade Pattern", "Observer Pattern", "Driver Test Double"],
    description: "Standard 10-command sequence simulating an adversary escalating threat score from LOW to CRITICAL and triggering a mid-session persona switch.",
    highlights: [
      "whoami, id, uname -a recon",
      "sudo privilege check & shadow read",
      "cat /home/john.dev/.env exfiltration",
      "Live Persona Switch alert"
    ]
  },
  {
    id: "demo_session_2",
    title: "2. Stealth Recon & Data Exfiltration Demo",
    category: "Panel Presentation",
    script: "scripts/demo_session_2.py",
    args: [],
    command_count: 14,
    estimated_duration: "20s",
    attack_pattern: "Stealth Recon -> linpeas.sh Download -> Directory Compression -> HTTP Exfiltration",
    design_patterns: ["Facade Pattern", "In-Memory Overlay Pattern", "Pipeline Pattern"],
    description: "Simulates a stealthy attacker searching config files, downloading enumeration scripts, and exfiltrating archives via curl.",
    highlights: [
      "netstat & find *.conf recon",
      "wget linpeas.sh execution",
      "tar backup creation in /tmp",
      "curl POST exfiltration"
    ]
  },
  {
    id: "demo_session_3",
    title: "3. Loud Ransomware & Lateral Movement Demo",
    category: "Panel Presentation",
    script: "scripts/demo_session_3.py",
    args: [],
    command_count: 10,
    estimated_duration: "15s",
    attack_pattern: "Immediate PrivEsc -> SSH Key Theft -> Lateral Movement -> Ransomware & Log Wipe",
    design_patterns: ["Facade Pattern", "Threat Taxonomy Classifier", "Overlay Isolation"],
    description: "High-noise attacker stealing private SSH keys, attempting lateral SSH movement, and simulating file wiping.",
    highlights: [
      "Direct cat /etc/shadow grab",
      "cat ~/.ssh/id_rsa key theft",
      "Lateral SSH connection attempt",
      "Ransomware simulation & rm -rf /var/log/*"
    ]
  },
  {
    id: "attack_botnet",
    title: "4. Botnet Automated Probe Scenario",
    category: "Attacker Scenarios",
    script: "scripts/attack_scenarios.py",
    args: ["--scenario", "botnet", "--speed", "0.5"],
    command_count: 12,
    estimated_duration: "10s",
    attack_pattern: "High-Speed Automated Botnet Scan & Mass Recon",
    design_patterns: ["Strategy Pattern", "Stochastic Timing Model"],
    description: "Simulates an automated botnet script scanning open ports, system uptime, and user enumeration at high speed.",
    highlights: [
      "Automated command burst",
      "Stochastic typing intervals",
      "Fast threat accumulation"
    ]
  },
  {
    id: "attack_credential",
    title: "5. Credential Harvesting Attack Scenario",
    category: "Attacker Scenarios",
    script: "scripts/attack_scenarios.py",
    args: ["--scenario", "credential", "--speed", "0.8"],
    command_count: 10,
    estimated_duration: "12s",
    attack_pattern: "Targeted Key/Credential Search (.env, AWS keys, shadow)",
    design_patterns: ["Strategy Pattern", "Threat Threshold Switcher"],
    description: "Targeted adversary hunting for hardcoded passwords, AWS credentials, and environment config files.",
    highlights: [
      "Targeted .env search",
      "AWS credential hunting",
      "High threat score escalation"
    ]
  },
  {
    id: "attack_privesc",
    title: "6. Privilege Escalation Attack Scenario",
    category: "Attacker Scenarios",
    script: "scripts/attack_scenarios.py",
    args: ["--scenario", "privesc", "--speed", "0.8"],
    command_count: 11,
    estimated_duration: "15s",
    attack_pattern: "SUID Binary Search -> Sudo Exploit Attempt -> Root Shell Escalation",
    design_patterns: ["Strategy Pattern", "Persona Merging State Engine"],
    description: "Exploration of SUID binaries, sudoers configuration, and kernel vulnerability checking.",
    highlights: [
      "find / -perm -4000 SUID search",
      "cat /etc/sudoers check",
      "Triggers high persona transition"
    ]
  },
  {
    id: "attack_persistence",
    title: "7. Persistence & Backdoor Scenario",
    category: "Attacker Scenarios",
    script: "scripts/attack_scenarios.py",
    args: ["--scenario", "persistence", "--speed", "0.8"],
    command_count: 10,
    estimated_duration: "12s",
    attack_pattern: "Cron Injection -> SSH Authorized Keys -> Bashrc Persistence",
    design_patterns: ["Strategy Pattern", "In-Memory Write Overlay"],
    description: "Attacker attempting to establish persistent rootkits, backdoor users, and crontab entries.",
    highlights: [
      "Crontab backdoor injection",
      "echo to ~/.bashrc",
      "Overlay filesystem modification"
    ]
  },
  {
    id: "run_evaluation",
    title: "8. Academic Evaluation & Fingerprint Resistance Test",
    category: "Evaluation Suite",
    script: "scripts/run_evaluation.py",
    args: [],
    command_count: 22,
    estimated_duration: "10s",
    attack_pattern: "22 Honeypot Fingerprint Probes + Cross-Reference Invariant Checks",
    design_patterns: ["Automated Test Harness", "Cross-Reference Consistency Evaluator"],
    description: "Runs 22 honeypot detection probes against the system and scores overall fingerprint resistance.",
    highlights: [
      "22/22 Fingerprint resistance pass check",
      "Cross-reference state validation",
      "Latency fast-path vs slow-path benchmark"
    ]
  }
]

export function ScriptLauncher() {
  const [scripts, setScripts] = useState<ScriptItem[]>(BUILTIN_SCRIPTS)
  const [activeCategory, setActiveCategory] = useState<string>("All")
  const [runningScriptId, setRunningScriptId] = useState<string | null>(null)
  const [logs, setLogs] = useState<string[]>([])
  const [isLaunching, setIsLaunching] = useState<string | null>(null)
  const [showLogs, setShowLogs] = useState<boolean>(true)

  // Fetch live catalog on mount to sync with backend
  useEffect(() => {
    fetchScripts()
    const interval = setInterval(checkStatus, 2000)
    return () => clearInterval(interval)
  }, [])

  const getApiUrls = () => [
    DASHBOARD_URL,
    "http://127.0.0.1:8080",
    "http://localhost:8080",
  ]

  const fetchScripts = async () => {
    for (const url of getApiUrls()) {
      try {
        const res = await fetch(`${url}/api/scripts`)
        if (res.ok) {
          const data = await res.json()
          if (data.scripts && data.scripts.length > 0) {
            setScripts(data.scripts)
          }
          setRunningScriptId(data.running_script_id || null)
          return
        }
      } catch {
        // try next URL
      }
    }
  }

  const checkStatus = async () => {
    for (const url of getApiUrls()) {
      try {
        const res = await fetch(`${url}/api/scripts/status`)
        if (res.ok) {
          const data = await res.json()
          setRunningScriptId(data.is_running ? data.script_id : null)
          if (data.logs && data.logs.length > 0) {
            setLogs(data.logs)
          }
          return
        }
      } catch {
        // try next URL
      }
    }
  }

  const handleLaunch = async (scriptId: string) => {
    setIsLaunching(scriptId)
    setShowLogs(true)
    let launched = false

    for (const url of getApiUrls()) {
      try {
        const res = await fetch(`${url}/api/scripts/run`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ script_id: scriptId }),
        })
        if (res.ok) {
          const data = await res.json()
          if (data.status === "ok") {
            setRunningScriptId(scriptId)
            launched = true
            break
          } else {
            alert(`Launch error: ${data.message}`)
            launched = true
            break
          }
        }
      } catch {
        // try next URL
      }
    }

    if (!launched) {
      alert(`Failed to connect to backend server on port 8080. Ensure the FastAPI backend is running: python -m uvicorn dashboard.app:app --port 8080`)
    }
    setIsLaunching(null)
  }

  const handleStop = async () => {
    try {
      await fetch(`${DASHBOARD_URL}/api/scripts/stop`, { method: "POST" })
      setRunningScriptId(null)
    } catch {
      // ignore
    }
  }

  const handleClearDashboard = async () => {
    try {
      await fetch(`${DASHBOARD_URL}/api/dashboard/clear`, { method: "POST" })
      setLogs(["[SYSTEM] Dashboard telemetry cleared. Select any pattern below and click RUN."])
    } catch {
      // ignore
    }
  }

  const categories = ["All", "Panel Presentation", "Attacker Scenarios", "Evaluation Suite"]

  const filteredScripts = activeCategory === "All"
    ? scripts
    : scripts.filter(s => s.category === activeCategory)

  return (
    <PanelShell
      title="Demo & Attack Scenario Launcher — Select a Pattern & Run"
      count={scripts.length}
      icon={Sparkles}
      action={
        <div className="flex items-center gap-2">
          <button
            onClick={handleClearDashboard}
            className="flex items-center gap-1 text-xs px-2.5 py-1 rounded-md border border-border bg-secondary/50 text-secondary-foreground hover:bg-secondary transition-colors"
            title="Reset active sessions and telemetry feed"
          >
            <RefreshCw className="h-3 w-3" />
            Reset State
          </button>
          {runningScriptId && (
            <button
              onClick={handleStop}
              className="flex items-center gap-1 text-xs px-2.5 py-1 rounded-md bg-destructive/10 text-destructive border border-destructive/30 hover:bg-destructive/20 font-medium transition-colors"
            >
              <Square className="h-3 w-3 fill-current" />
              Stop Active Script
            </button>
          )}
        </div>
      }
    >
      <div className="flex flex-col gap-5">
        {/* Category Filters */}
        <div className="flex items-center justify-between gap-2 border-b border-border/60 pb-2">
          <div className="flex items-center gap-1.5 overflow-x-auto">
            {categories.map((cat) => (
              <button
                key={cat}
                onClick={() => setActiveCategory(cat)}
                className={`text-xs px-3 py-1.5 rounded-lg font-medium transition-all ${
                  activeCategory === cat
                    ? "bg-primary text-primary-foreground shadow-sm font-semibold"
                    : "bg-muted/50 text-muted-foreground hover:bg-muted hover:text-foreground"
                }`}
              >
                {cat}
              </button>
            ))}
          </div>

          <span className="text-[11px] text-muted-foreground font-mono hidden sm:inline">
            Click <strong className="text-emerald-400">RUN THIS PATTERN</strong> on any card to execute
          </span>
        </div>

        {/* Catalog Grid — Cards with Direct RUN Buttons */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-2 gap-4">
          {filteredScripts.map((s) => {
            const isRunning = s.id === runningScriptId
            const isThisLaunching = isLaunching === s.id

            return (
              <div
                key={s.id}
                className={`flex flex-col justify-between p-4 rounded-xl border transition-all shadow-sm gap-3 ${
                  isRunning
                    ? "border-emerald-500 bg-emerald-500/5 ring-1 ring-emerald-500/30"
                    : "border-border/80 bg-card hover:border-primary/50"
                }`}
              >
                <div className="flex flex-col gap-2">
                  {/* Top Bar: Title + Duration + Run Button */}
                  <div className="flex items-start justify-between gap-3 border-b border-border/40 pb-2.5">
                    <div className="flex flex-col">
                      <div className="flex items-center gap-1.5">
                        <span className="text-[10px] font-bold uppercase tracking-wider text-primary">
                          {s.category}
                        </span>
                        <span className="text-[10px] text-muted-foreground">·</span>
                        <span className="text-[10px] font-mono text-muted-foreground">
                          {s.estimated_duration} ({s.command_count} cmds)
                        </span>
                      </div>
                      <h3 className="text-sm font-bold text-foreground mt-0.5 leading-snug">
                        {s.title}
                      </h3>
                    </div>

                    {/* DIRECT RUN BUTTON ON EVERY CARD */}
                    <button
                      onClick={() => handleLaunch(s.id)}
                      disabled={runningScriptId !== null || isThisLaunching}
                      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-bold text-xs shrink-0 transition-all shadow-md ${
                        isRunning
                          ? "bg-emerald-600 text-white cursor-not-allowed"
                          : runningScriptId !== null
                          ? "bg-muted text-muted-foreground cursor-not-allowed opacity-60"
                          : "bg-emerald-500 hover:bg-emerald-600 text-slate-950 hover:shadow-lg active:scale-95"
                      }`}
                    >
                      {isThisLaunching ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      ) : isRunning ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin text-white" />
                      ) : (
                        <Play className="h-3.5 w-3.5 fill-current" />
                      )}
                      <span>{isRunning ? "Running..." : "RUN THIS PATTERN"}</span>
                    </button>
                  </div>

                  <p className="text-xs text-muted-foreground leading-relaxed">
                    {s.description}
                  </p>

                  {/* Attack Pattern Flow */}
                  <div className="flex flex-col gap-1 p-2 rounded-lg bg-background/70 border border-border/50">
                    <div className="flex items-center gap-1 text-[11px] font-semibold text-amber-400">
                      <Shield className="h-3 w-3" />
                      Attack Threat Flow:
                    </div>
                    <div className="text-[11px] font-mono text-foreground font-medium pl-4">
                      {s.attack_pattern}
                    </div>
                  </div>

                  {/* Software Design Patterns */}
                  <div className="flex flex-col gap-1 mt-0.5">
                    <div className="flex items-center gap-1 text-[11px] font-semibold text-blue-400">
                      <Cpu className="h-3 w-3" />
                      Architectural Patterns Used:
                    </div>
                    <div className="flex flex-wrap gap-1 pl-4">
                      {s.design_patterns.map((dp) => (
                        <span
                          key={dp}
                          className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/20"
                        >
                          {dp}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Key Highlights */}
                  <div className="flex flex-col gap-1 mt-0.5">
                    <div className="flex items-center gap-1 text-[11px] font-semibold text-emerald-400">
                      <Layers className="h-3 w-3" />
                      Key Highlights:
                    </div>
                    <ul className="grid grid-cols-2 gap-1 pl-4">
                      {s.highlights.map((h, idx) => (
                        <li key={idx} className="flex items-center gap-1 text-[10px] text-muted-foreground">
                          <CheckCircle2 className="h-2.5 w-2.5 text-emerald-500 shrink-0" />
                          <span className="truncate">{h}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            )
          })}
        </div>

        {/* Real-Time Live Execution Console Log */}
        {showLogs && (
          <div className="flex flex-col rounded-xl border border-border bg-slate-950 p-3 shadow-inner mt-1">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2 mb-2">
              <div className="flex items-center gap-2">
                <Terminal className="h-4 w-4 text-emerald-400" />
                <span className="text-xs font-mono font-semibold text-slate-200">
                  Live Execution Console Stream
                </span>
                {runningScriptId ? (
                  <span className="flex items-center gap-1 text-[10px] font-mono text-emerald-400 animate-pulse bg-emerald-500/10 px-2 py-0.5 rounded-full border border-emerald-500/20">
                    <Zap className="h-3 w-3" /> Running: {runningScriptId}
                  </span>
                ) : (
                  <span className="text-[10px] font-mono text-slate-400">
                    (Idle — Select a pattern above and click RUN)
                  </span>
                )}
              </div>
              <button
                onClick={() => setLogs([])}
                className="text-[10px] font-mono text-slate-400 hover:text-slate-200"
              >
                Clear Console Log
              </button>
            </div>

            <div className="max-h-[180px] overflow-y-auto font-mono text-[11px] text-slate-300 space-y-0.5">
              {logs.length === 0 ? (
                <div className="text-slate-500 italic py-2 text-center">
                  Console stream empty. Click <strong className="text-emerald-400 font-bold">RUN THIS PATTERN</strong> on any scenario card above to start live execution!
                </div>
              ) : (
                logs.map((line, i) => (
                  <div key={i} className="whitespace-pre-wrap leading-tight">
                    {line}
                  </div>
                ))
              )}
            </div>
          </div>
        )}
      </div>
    </PanelShell>
  )
}
