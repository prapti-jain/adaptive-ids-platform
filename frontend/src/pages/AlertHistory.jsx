import { useCallback, useEffect, useState } from 'react'
import { fetchAlerts, patchAlertStatus } from '../api/client'
import { EmptyState, LoadingBlock, SeverityBadge, formatTime } from '../components/ui'

const PAGE_SIZE = 20
const SEVERITIES = ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
const STATUSES = ['', 'OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE']
const ATTACK_TYPES = ['', 'PORT_SCAN', 'SYN_FLOOD', 'SSH_BRUTE_FORCE']

export default function AlertHistory() {
  const [filters, setFilters] = useState({
    severity: '',
    status: '',
    attack_type: '',
  })
  const [offset, setOffset] = useState(0)
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [busyId, setBusyId] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const result = await fetchAlerts({
        ...filters,
        severity: filters.severity || undefined,
        status: filters.status || undefined,
        attack_type: filters.attack_type || undefined,
        limit: PAGE_SIZE,
        offset,
      })
      setData(result)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [filters, offset])

  useEffect(() => {
    load()
  }, [load])

  const updateStatus = async (id, status) => {
    setBusyId(id)
    try {
      await patchAlertStatus(id, status)
      await load()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusyId(null)
    }
  }

  const total = data?.total ?? 0
  const items = data?.items ?? []
  const page = Math.floor(offset / PAGE_SIZE) + 1
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE))

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-xl font-semibold text-slate-100">Alert History</h2>
        <p className="text-sm text-slate-400">Paginated archive with status workflow actions</p>
      </div>

      <div className="flex flex-wrap gap-3 rounded-lg border border-slate-800 bg-slate-900/70 p-3">
        <FilterSelect
          label="Severity"
          value={filters.severity}
          options={SEVERITIES}
          onChange={(severity) => {
            setOffset(0)
            setFilters((f) => ({ ...f, severity }))
          }}
        />
        <FilterSelect
          label="Status"
          value={filters.status}
          options={STATUSES}
          onChange={(status) => {
            setOffset(0)
            setFilters((f) => ({ ...f, status }))
          }}
        />
        <FilterSelect
          label="Attack type"
          value={filters.attack_type}
          options={ATTACK_TYPES}
          onChange={(attack_type) => {
            setOffset(0)
            setFilters((f) => ({ ...f, attack_type }))
          }}
        />
      </div>

      {loading ? (
        <LoadingBlock label="Loading alerts…" />
      ) : error ? (
        <EmptyState title="Could not load alerts" detail={error} />
      ) : items.length === 0 ? (
        <EmptyState
          title="No alerts match these filters"
          detail="Try clearing filters or replay the sample PCAP from Overview."
        />
      ) : (
        <>
          <div className="overflow-x-auto rounded-lg border border-slate-800">
            <table className="min-w-full divide-y divide-slate-800 text-left text-sm">
              <thead className="bg-slate-900 text-xs uppercase tracking-wider text-slate-500">
                <tr>
                  <th className="px-3 py-2">Severity</th>
                  <th className="px-3 py-2">Type</th>
                  <th className="px-3 py-2">Source</th>
                  <th className="px-3 py-2">Risk</th>
                  <th className="px-3 py-2">Status</th>
                  <th className="px-3 py-2">Detected</th>
                  <th className="px-3 py-2">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 bg-slate-950/60">
                {items.map((item) => {
                  const alert = item.alert
                  const busy = busyId === alert.id
                  return (
                    <tr key={alert.id} className="hover:bg-slate-900/80">
                      <td className="px-3 py-2">
                        <SeverityBadge severity={alert.severity} />
                      </td>
                      <td className="px-3 py-2 font-mono text-cyan-300">{alert.attack_type}</td>
                      <td className="px-3 py-2 font-mono text-slate-200">{alert.source_ip}</td>
                      <td className="px-3 py-2 font-mono text-slate-300">
                        {alert.risk_score.toFixed(2)}
                      </td>
                      <td className="px-3 py-2 text-slate-300">{alert.status}</td>
                      <td className="px-3 py-2 text-slate-400">{formatTime(alert.detected_at)}</td>
                      <td className="px-3 py-2">
                        <div className="flex flex-wrap gap-1">
                          <ActionButton
                            disabled={busy || alert.status === 'INVESTIGATING'}
                            onClick={() => updateStatus(alert.id, 'INVESTIGATING')}
                          >
                            Investigate
                          </ActionButton>
                          <ActionButton
                            disabled={busy || alert.status === 'RESOLVED'}
                            onClick={() => updateStatus(alert.id, 'RESOLVED')}
                          >
                            Resolve
                          </ActionButton>
                          <ActionButton
                            disabled={busy || alert.status === 'FALSE_POSITIVE'}
                            onClick={() => updateStatus(alert.id, 'FALSE_POSITIVE')}
                          >
                            False Positive
                          </ActionButton>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          <div className="flex items-center justify-between text-sm text-slate-400">
            <span>
              {total} alert{total === 1 ? '' : 's'} · page {page} / {pageCount}
            </span>
            <div className="flex gap-2">
              <button
                type="button"
                className="btn-secondary"
                disabled={offset === 0}
                onClick={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}
              >
                Previous
              </button>
              <button
                type="button"
                className="btn-secondary"
                disabled={offset + PAGE_SIZE >= total}
                onClick={() => setOffset((o) => o + PAGE_SIZE)}
              >
                Next
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}

function FilterSelect({ label, value, options, onChange }) {
  return (
    <label className="flex flex-col gap-1 text-xs text-slate-500">
      {label}
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-200"
      >
        {options.map((opt) => (
          <option key={opt || 'all'} value={opt}>
            {opt || 'All'}
          </option>
        ))}
      </select>
    </label>
  )
}

function ActionButton({ children, ...props }) {
  return (
    <button
      type="button"
      className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-slate-300 hover:border-cyan-500/50 hover:text-cyan-300 disabled:cursor-not-allowed disabled:opacity-40"
      {...props}
    >
      {children}
    </button>
  )
}
