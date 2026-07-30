import { useEffect, useState } from 'react'
import { ArcElement, Chart as ChartJS, Legend, Tooltip } from 'chart.js'
import { Doughnut } from 'react-chartjs-2'
import { fetchOverview, replaySamplePcap } from '../api/client'
import { EmptyState, LoadingBlock, SEVERITY_COLORS } from '../components/ui'

ChartJS.register(ArcElement, Tooltip, Legend)

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export default function Overview({ onReplayDone }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [replaying, setReplaying] = useState(false)
  const [replayMsg, setReplayMsg] = useState(null)

  const load = async () => {
    setLoading(true)
    setError(null)
    try {
      setData(await fetchOverview(24))
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  const handleReplay = async () => {
    setReplaying(true)
    setReplayMsg(null)
    try {
      const result = await replaySamplePcap()
      setReplayMsg(`Replay finished — ${result.processed_events} events processed.`)
      await load()
      onReplayDone?.()
    } catch (err) {
      setReplayMsg(`Replay failed: ${err.message}`)
    } finally {
      setReplaying(false)
    }
  }

  if (loading) return <LoadingBlock label="Loading overview…" />
  if (error) {
    return (
      <EmptyState
        title="Could not load overview"
        detail={error}
        action={
          <button type="button" onClick={load} className="btn-secondary">
            Retry
          </button>
        }
      />
    )
  }

  const total = data?.total ?? 0
  const bySeverity = data?.by_severity ?? {}
  const byAttack = data?.by_attack_type ?? {}

  const severityLabels = SEVERITY_ORDER.filter((s) => bySeverity[s])
  const severityChart = {
    labels: severityLabels,
    datasets: [
      {
        data: severityLabels.map((s) => bySeverity[s] || 0),
        backgroundColor: severityLabels.map((s) => SEVERITY_COLORS[s].chart),
        borderColor: '#0f172a',
        borderWidth: 2,
      },
    ],
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-semibold text-slate-100">Operations Overview</h2>
          <p className="text-sm text-slate-400">Last {data.window_hours}h of alert activity</p>
        </div>
        <button
          type="button"
          onClick={handleReplay}
          disabled={replaying}
          className="btn-primary"
        >
          {replaying ? 'Replaying…' : 'Replay Sample PCAP'}
        </button>
      </div>

      {replayMsg ? (
        <p className="rounded border border-slate-700 bg-slate-900/80 px-3 py-2 text-sm text-slate-300">
          {replayMsg}
        </p>
      ) : null}

      {total === 0 ? (
        <EmptyState
          title="No alerts yet"
          detail="Click Replay Sample PCAP to generate detection events from the bundled capture."
          action={
            <button type="button" onClick={handleReplay} disabled={replaying} className="btn-primary">
              {replaying ? 'Replaying…' : 'Replay Sample PCAP'}
            </button>
          }
        />
      ) : (
        <>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <StatCard label="Total Alerts" value={total} accent="text-cyan-300" />
            <StatCard
              label="Critical"
              value={bySeverity.CRITICAL || 0}
              accent="text-red-400"
            />
            <StatCard label="High" value={bySeverity.HIGH || 0} accent="text-orange-400" />
            <StatCard
              label="Attack Types"
              value={Object.keys(byAttack).length}
              accent="text-violet-300"
            />
          </div>

          <div className="grid gap-6 lg:grid-cols-2">
            <Panel title="Severity Distribution">
              <div className="mx-auto h-64 max-w-xs">
                <Doughnut
                  data={severityChart}
                  options={{
                    plugins: {
                      legend: {
                        position: 'bottom',
                        labels: { color: '#cbd5e1' },
                      },
                    },
                    cutout: '62%',
                  }}
                />
              </div>
            </Panel>

            <Panel title="Attack Type Breakdown">
              <ul className="space-y-3">
                {Object.entries(byAttack)
                  .sort((a, b) => b[1] - a[1])
                  .map(([type, count]) => (
                    <li key={type} className="flex items-center justify-between gap-3">
                      <span className="font-mono text-sm text-slate-300">{type}</span>
                      <div className="flex flex-1 items-center gap-3">
                        <div className="h-2 flex-1 overflow-hidden rounded bg-slate-800">
                          <div
                            className="h-full rounded bg-cyan-500/80"
                            style={{ width: `${Math.max(8, (count / total) * 100)}%` }}
                          />
                        </div>
                        <span className="w-8 text-right font-mono text-sm text-slate-200">
                          {count}
                        </span>
                      </div>
                    </li>
                  ))}
              </ul>
            </Panel>
          </div>
        </>
      )}
    </div>
  )
}

function StatCard({ label, value, accent }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-4">
      <p className="text-xs uppercase tracking-wider text-slate-500">{label}</p>
      <p className={`mt-2 text-3xl font-semibold tabular-nums ${accent}`}>{value}</p>
    </div>
  )
}

function Panel({ title, children }) {
  return (
    <section className="rounded-lg border border-slate-800 bg-slate-900/70 p-4">
      <h3 className="mb-4 text-sm font-medium uppercase tracking-wider text-slate-400">
        {title}
      </h3>
      {children}
    </section>
  )
}
