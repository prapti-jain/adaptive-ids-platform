import { useCallback, useEffect, useRef, useState } from 'react'
import { alertsWebSocketUrl } from '../api/client'

/**
 * Connect to /ws/alerts and keep a live list of EnrichedAlert payloads.
 * Newest alerts are prepended. Dedupes by alert.id (updates replace in place).
 */
export function useAlertStream({ enabled = true, maxItems = 100 } = {}) {
  const [alerts, setAlerts] = useState([])
  const [connected, setConnected] = useState(false)
  const [error, setError] = useState(null)
  const wsRef = useRef(null)
  const retryRef = useRef(null)

  const upsert = useCallback(
    (incoming) => {
      setAlerts((prev) => {
        const id = incoming?.alert?.id
        if (!id) return prev
        const without = prev.filter((item) => item.alert.id !== id)
        return [incoming, ...without].slice(0, maxItems)
      })
    },
    [maxItems],
  )

  useEffect(() => {
    if (!enabled) return undefined

    let closed = false

    const connect = () => {
      if (closed) return
      const ws = new WebSocket(alertsWebSocketUrl())
      wsRef.current = ws

      ws.onopen = () => {
        setConnected(true)
        setError(null)
      }

      ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data)
          upsert(payload)
        } catch (err) {
          console.error('Failed to parse alert WS payload', err)
        }
      }

      ws.onerror = () => {
        setError('WebSocket connection error')
      }

      ws.onclose = () => {
        setConnected(false)
        wsRef.current = null
        if (!closed) {
          retryRef.current = window.setTimeout(connect, 2000)
        }
      }
    }

    connect()

    return () => {
      closed = true
      if (retryRef.current) window.clearTimeout(retryRef.current)
      if (wsRef.current) wsRef.current.close()
    }
  }, [enabled, upsert])

  const clear = useCallback(() => setAlerts([]), [])

  return { alerts, connected, error, clear, upsert }
}
