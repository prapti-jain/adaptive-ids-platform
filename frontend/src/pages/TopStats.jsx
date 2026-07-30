import { useEffect, useState } from 'react'
import {
  BarElement,
  CategoryScale,
  Chart as ChartJS,
  LinearScale,
  Tooltip,
  Legend,
} from 'chart.js'
import { Bar } from 'react-chartjs-2'
import { fetchTopAttackers, fetchTopPorts } from '../api/client'
import { EmptyState, LoadingBlock } from '../components/ui'

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip, Legend)

export default function TopStats() {
  const [attackers, setAttackers] = useState(null)
  const [ports, setPorts] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      setLoading(true)
      setError(null)
      try {
        const [a, p] = await Promise.all([
          fetchTopAttackers({ limit: 10 }),
          fetchTopPorts({ limit: 10 }),
        ])
        if (!cancelled) {
          setAttackers(a)
          setPorts(p)
        }
      } catch (err) {
        if (!cancelled) setError(err.message)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    return () => {
      cancelled = true
    }
  }, [])

  if (loading) return <LoadingBlock label="Loading top stats…" />
  if (error) return <EmptyState title="Could not load top stats" detail={error} />

  const attackerItems = attackers?.items ?? []
  const portItems = ports?.items ?? []

  if (attackerItems.length === 0 && portItems.length === 0) {
    return (
      <EmptyState
        title="No attacker / port data yet"
        detail="Replay Sample PCAP from Overview to populate these charts."
      />
    )
  }

  const chartOptions = {
    indexAxis: 'y',
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      x: {
        beginAtZero: true,
        ticks: { color: '#94a3b8', precision: 0 },
        grid: { color: 'rgba(51, 65, 85, 0.45)' },
      },
      y: {
        ticks: { color: '#cbd5e1', font: { family: 'ui-monospace, monospace' } },
        grid: { display: false },
      },
    },
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold text-slate-100">Top Attackers & Ports</h2>
        <p className="text-sm text-slate-400">Highest-volume sources and targeted ports</p>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <section className="rounded-lg border border-slate-800 bg-slate-900/70 p-4">
          <h3 className="mb-3 text-sm font-medium uppercase tracking-wider text-slate-400">
            Top Attackers
          </h3>
          {attackerItems.length === 0 ? (
            <p className="text-sm text-slate-500">No attacker data</p>
          ) : (
            <div className="h-72">
              <Bar
                data={{
                  labels: attackerItems.map((i) => i.source_ip),
                  datasets: [
                    {
                      data: attackerItems.map((i) => i.alert_count),
                      backgroundColor: 'rgba(248, 113, 113, 0.7)',
                    },
                  ],
                }}
                options={chartOptions}
              />
            </div>
          )}
        </section>

        <section className="rounded-lg border border-slate-800 bg-slate-900/70 p-4">
          <h3 className="mb-3 text-sm font-medium uppercase tracking-wider text-slate-400">
            Top Ports
          </h3>
          {portItems.length === 0 ? (
            <p className="text-sm text-slate-500">No port data</p>
          ) : (
            <div className="h-72">
              <Bar
                data={{
                  labels: portItems.map((i) => String(i.port)),
                  datasets: [
                    {
                      data: portItems.map((i) => i.alert_count),
                      backgroundColor: 'rgba(56, 189, 248, 0.7)',
                    },
                  ],
                }}
                options={chartOptions}
              />
            </div>
          )}
          {ports?.note ? (
            <p className="mt-3 text-xs leading-relaxed text-slate-500">{ports.note}</p>
          ) : null}
        </section>
      </div>
    </div>
  )
}
