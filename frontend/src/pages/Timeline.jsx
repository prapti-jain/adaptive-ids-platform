import { useEffect, useState } from 'react'
import {
  BarElement,
  CategoryScale,
  Chart as ChartJS,
  LinearScale,
  LineElement,
  PointElement,
  Tooltip,
  Legend,
} from 'chart.js'
import { Bar, Line } from 'react-chartjs-2'
import { fetchTimeline } from '../api/client'
import { EmptyState, LoadingBlock } from '../components/ui'

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Tooltip,
  Legend,
)

export default function Timeline() {
  const [interval, setIntervalMode] = useState('hour')
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      setLoading(true)
      setError(null)
      try {
        const result = await fetchTimeline({ interval, windowHours: 24 * 7 })
        if (!cancelled) setData(result)
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
  }, [interval])

  if (loading) return <LoadingBlock label="Loading timeline…" />
  if (error) {
    return <EmptyState title="Could not load timeline" detail={error} />
  }

  const buckets = data?.buckets ?? []
  if (buckets.length === 0) {
    return (
      <EmptyState
        title="No timeline data"
        detail="Replay a sample PCAP to populate alert activity over time."
      />
    )
  }

  const chartData = {
    labels: buckets.map((b) => b.bucket),
    datasets: [
      {
        label: 'Alerts',
        data: buckets.map((b) => b.count),
        borderColor: '#22d3ee',
        backgroundColor: 'rgba(34, 211, 238, 0.35)',
        tension: 0.25,
        fill: true,
      },
    ],
  }

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { labels: { color: '#cbd5e1' } },
    },
    scales: {
      x: {
        ticks: { color: '#94a3b8', maxRotation: 45, minRotation: 0 },
        grid: { color: 'rgba(51, 65, 85, 0.5)' },
      },
      y: {
        beginAtZero: true,
        ticks: { color: '#94a3b8', precision: 0 },
        grid: { color: 'rgba(51, 65, 85, 0.5)' },
      },
    },
  }

  const Chart = interval === 'day' ? Bar : Line

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-semibold text-slate-100">Alert Timeline</h2>
          <p className="text-sm text-slate-400">Bucketed counts for charting</p>
        </div>
        <div className="inline-flex rounded-md border border-slate-700 bg-slate-900 p-1">
          {['hour', 'day'].map((value) => (
            <button
              key={value}
              type="button"
              onClick={() => setIntervalMode(value)}
              className={`rounded px-3 py-1.5 text-sm capitalize ${
                interval === value
                  ? 'bg-cyan-500/20 text-cyan-300'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {value}
            </button>
          ))}
        </div>
      </div>
      <div className="h-80 rounded-lg border border-slate-800 bg-slate-900/70 p-4">
        <Chart data={chartData} options={options} />
      </div>
    </div>
  )
}
