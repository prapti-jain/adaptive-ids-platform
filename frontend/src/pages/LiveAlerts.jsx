import { useState } from 'react'
import { fetchAlert } from '../api/client'
import { EmptyState, LoadingBlock, SeverityBadge, formatTime } from '../components/ui'

export default function LiveAlerts({ stream }) {
  const { alerts, connected, error } = stream
  const [selected, setSelected] = useState(null)
  const [detail, setDetail] = useState(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [detailError, setDetailError] = useState(null)

  const openDetail = async (enriched) => {
    const id = enriched.alert.id
    setSelected(id)
    setDetailLoading(true)
    setDetailError(null)
    try {
      setDetail(await fetchAlert(id))
    } catch (err) {
      setDetailError(err.message)
      setDetail(enriched)
    } finally {
      setDetailLoading(false)
    }
  }

  return (
    <div className="grid gap-6 lg:grid-cols-[1.4fr_1fr]">
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-semibold text-slate-100">Live Alerts</h2>
            <p className="text-sm text-slate-400">
              Stream from <span className="font-mono">/ws/alerts</span>
            </p>
          </div>
          <span
            className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs ${
              connected
                ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300'
                : 'border-slate-600 bg-slate-800 text-slate-400'
            }`}
          >
            <span
              className={`h-2 w-2 rounded-full ${connected ? 'bg-emerald-400' : 'bg-slate-500'}`}
            />
            {connected ? 'Connected' : 'Reconnecting…'}
          </span>
        </div>

        {error ? <p className="text-sm text-amber-300">{error}</p> : null}

        {alerts.length === 0 ? (
          <EmptyState
            title="Waiting for live alerts"
            detail="Open Overview and click Replay Sample PCAP — new detections will appear here without refreshing."
          />
        ) : (
          <ul className="divide-y divide-slate-800 overflow-hidden rounded-lg border border-slate-800 bg-slate-900/70">
            {alerts.map((item) => {
              const alert = item.alert
              const active = selected === alert.id
              return (
                <li key={alert.id}>
                  <button
                    type="button"
                    onClick={() => openDetail(item)}
                    className={`flex w-full items-start gap-4 px-4 py-3 text-left transition hover:bg-slate-800/60 ${
                      active ? 'bg-slate-800/80' : ''
                    }`}
                  >
                    <SeverityBadge severity={alert.severity} />
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                        <span className="font-mono text-sm text-cyan-300">
                          {alert.attack_type}
                        </span>
                        <span className="font-mono text-sm text-slate-200">{alert.source_ip}</span>
                      </div>
                      <p className="mt-1 text-xs text-slate-500">
                        risk {alert.risk_score.toFixed(2)} · {formatTime(alert.detected_at)}
                        {item.is_known_malicious ? ' · known malicious' : ''}
                      </p>
                    </div>
                  </button>
                </li>
              )
            })}
          </ul>
        )}
      </div>

      <aside className="rounded-lg border border-slate-800 bg-slate-900/70 p-4">
        <h3 className="mb-3 text-sm font-medium uppercase tracking-wider text-slate-400">
          Alert Detail
        </h3>
        {!selected ? (
          <p className="text-sm text-slate-500">Select an alert to inspect enrichment and evidence.</p>
        ) : detailLoading ? (
          <LoadingBlock label="Loading detail…" />
        ) : detailError && !detail ? (
          <p className="text-sm text-red-300">{detailError}</p>
        ) : (
          <AlertDetailPanel enriched={detail} />
        )}
      </aside>
    </div>
  )
}

function AlertDetailPanel({ enriched }) {
  const alert = enriched.alert
  return (
    <div className="space-y-4 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={alert.severity} />
        <span className="font-mono text-cyan-300">{alert.attack_type}</span>
      </div>
      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-2">
        <dt className="text-slate-500">ID</dt>
        <dd className="truncate font-mono text-slate-300">{alert.id}</dd>
        <dt className="text-slate-500">Source</dt>
        <dd className="font-mono text-slate-200">{alert.source_ip}</dd>
        <dt className="text-slate-500">Target</dt>
        <dd className="font-mono text-slate-200">{alert.target_ip || '—'}</dd>
        <dt className="text-slate-500">Status</dt>
        <dd className="text-slate-200">{alert.status}</dd>
        <dt className="text-slate-500">Risk</dt>
        <dd className="font-mono text-slate-200">{alert.risk_score.toFixed(4)}</dd>
        <dt className="text-slate-500">Confidence</dt>
        <dd className="font-mono text-slate-200">{alert.confidence.toFixed(4)}</dd>
        <dt className="text-slate-500">Detected</dt>
        <dd className="text-slate-200">{formatTime(alert.detected_at)}</dd>
        <dt className="text-slate-500">Reputation</dt>
        <dd className="text-slate-200">{enriched.ip_reputation}</dd>
        <dt className="text-slate-500">Geo</dt>
        <dd className="font-mono text-slate-200">{enriched.geo_country || '—'}</dd>
        <dt className="text-slate-500">Malicious</dt>
        <dd className="text-slate-200">{enriched.is_known_malicious ? 'yes' : 'no'}</dd>
        <dt className="text-slate-500">History</dt>
        <dd className="text-slate-200">{enriched.historical_alert_count}</dd>
      </dl>
      <div>
        <p className="mb-1 text-xs uppercase tracking-wider text-slate-500">Evidence</p>
        <pre className="overflow-x-auto rounded border border-slate-800 bg-slate-950 p-3 font-mono text-xs text-slate-300">
          {JSON.stringify(alert.evidence, null, 2)}
        </pre>
      </div>
    </div>
  )
}
