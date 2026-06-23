"use client"

import { useEffect, useRef, useState } from "react"
import { HoneypotSimulator } from "./simulator"
import type { ConnectionStatus, DashboardPayload } from "./types"

const WS_URL = process.env.NEXT_PUBLIC_HONEYPOT_WS_URL

/**
 * Subscribes to the FastAPI honeypot WebSocket (`/ws`) when
 * NEXT_PUBLIC_HONEYPOT_WS_URL is configured and reachable. Otherwise it falls
 * back to a realistic local simulation so the dashboard is always populated.
 */
export function useHoneypotData() {
  const [data, setData] = useState<DashboardPayload | null>(null)
  const [status, setStatus] = useState<ConnectionStatus>("connecting")
  const simRef = useRef<HoneypotSimulator | null>(null)
  const simTimerRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    let cancelled = false
    let ws: WebSocket | null = null
    let connectTimeout: ReturnType<typeof setTimeout> | null = null

    function startSimulation() {
      if (cancelled || simTimerRef.current) return
      const sim = new HoneypotSimulator()
      simRef.current = sim
      setStatus("demo")
      setData(sim.snapshot())
      simTimerRef.current = setInterval(() => {
        sim.tick()
        setData(sim.snapshot())
      }, 2000)
    }

    if (WS_URL) {
      try {
        ws = new WebSocket(WS_URL)
        // If it doesn't open quickly, drop into simulation mode.
        connectTimeout = setTimeout(() => {
          if (ws && ws.readyState !== WebSocket.OPEN) {
            ws.close()
            startSimulation()
          }
        }, 2500)

        ws.onopen = () => {
          if (connectTimeout) clearTimeout(connectTimeout)
          if (!cancelled) setStatus("live")
        }
        ws.onmessage = (event) => {
          try {
            const payload = JSON.parse(event.data) as DashboardPayload
            if (!cancelled) {
              setStatus("live")
              setData(payload)
            }
          } catch {
            /* ignore malformed frames */
          }
        }
        ws.onerror = () => {
          if (connectTimeout) clearTimeout(connectTimeout)
          startSimulation()
        }
        ws.onclose = () => {
          if (!cancelled && status !== "demo") startSimulation()
        }
      } catch {
        startSimulation()
      }
    } else {
      startSimulation()
    }

    return () => {
      cancelled = true
      if (connectTimeout) clearTimeout(connectTimeout)
      if (simTimerRef.current) clearInterval(simTimerRef.current)
      simTimerRef.current = null
      if (ws) ws.close()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return { data, status }
}
