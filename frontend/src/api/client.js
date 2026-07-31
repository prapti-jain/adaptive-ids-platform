/**
 * AIDTIP API client.
 *
 * Production (Vercel): set VITE_API_BASE_URL / VITE_WS_BASE_URL to the Render backend.
 * Local dev: leave them unset — relative paths go through the Vite proxy to :8000.
 */

const API_BASE = String(import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '')
const WS_BASE = String(import.meta.env.VITE_WS_BASE_URL || '').replace(/\/$/, '')

function apiUrl(path) {
  // path must start with /
  return `${API_BASE}${path}`
}

async function request(path, options = {}) {
  const response = await fetch(apiUrl(path), {
    headers: {
      Accept: 'application/json',
      ...(options.body ? { 'Content-Type': 'application/json' } : {}),
      ...options.headers,
    },
    ...options,
  })
  if (!response.ok) {
    const detail = await response.text()
    throw new Error(`${response.status} ${response.statusText}: ${detail}`)
  }
  if (response.status === 204) return null
  return response.json()
}

export function fetchAlerts({
  severity,
  status,
  attack_type,
  limit = 50,
  offset = 0,
} = {}) {
  const params = new URLSearchParams()
  if (severity) params.set('severity', severity)
  if (status) params.set('status', status)
  if (attack_type) params.set('attack_type', attack_type)
  params.set('limit', String(limit))
  params.set('offset', String(offset))
  return request(`/api/alerts?${params.toString()}`)
}

export function fetchAlert(id) {
  return request(`/api/alerts/${id}`)
}

export function patchAlertStatus(id, status) {
  return request(`/api/alerts/${id}/status`, {
    method: 'PATCH',
    body: JSON.stringify({ status }),
  })
}

export function fetchOverview(windowHours = 24) {
  const params = new URLSearchParams({ window_hours: String(windowHours) })
  return request(`/api/stats/overview?${params.toString()}`)
}

export function fetchTimeline({ interval = 'hour', windowHours = 24 } = {}) {
  const params = new URLSearchParams({
    interval,
    window_hours: String(windowHours),
  })
  return request(`/api/stats/timeline?${params.toString()}`)
}

export function fetchTopAttackers({ limit = 10, windowHours = 24 * 30 } = {}) {
  const params = new URLSearchParams({
    limit: String(limit),
    window_hours: String(windowHours),
  })
  return request(`/api/stats/top-attackers?${params.toString()}`)
}

export function fetchTopPorts({ limit = 10, windowHours = 24 * 30 } = {}) {
  const params = new URLSearchParams({
    limit: String(limit),
    window_hours: String(windowHours),
  })
  return request(`/api/stats/top-ports?${params.toString()}`)
}

export function replaySamplePcap(pcapPath) {
  return request('/api/pipeline/replay', {
    method: 'POST',
    body: JSON.stringify(pcapPath ? { pcap_path: pcapPath } : {}),
  })
}

export function alertsWebSocketUrl() {
  if (WS_BASE) {
    return `${WS_BASE}/ws/alerts`
  }
  // Local Vite proxy: same host as the page (e.g. localhost:5174 → /ws → backend).
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${proto}//${window.location.host}/ws/alerts`
}
