import { useMemo, useState } from 'react'
import { useAlertStream } from './hooks/useAlertStream'
import Overview from './pages/Overview'
import LiveAlerts from './pages/LiveAlerts'
import Timeline from './pages/Timeline'
import TopStats from './pages/TopStats'
import AlertHistory from './pages/AlertHistory'

const NAV = [
  { id: 'overview', label: 'Overview' },
  { id: 'live', label: 'Live Alerts' },
  { id: 'timeline', label: 'Timeline' },
  { id: 'top', label: 'Top Stats' },
  { id: 'history', label: 'Alert History' },
]

export default function App() {
  const [tab, setTab] = useState('overview')
  const [historyKey, setHistoryKey] = useState(0)
  const stream = useAlertStream({ enabled: true })

  const content = useMemo(() => {
    switch (tab) {
      case 'live':
        return <LiveAlerts stream={stream} />
      case 'timeline':
        return <Timeline key={`timeline-${historyKey}`} />
      case 'top':
        return <TopStats key={`top-${historyKey}`} />
      case 'history':
        return <AlertHistory key={`history-${historyKey}`} />
      case 'overview':
      default:
        return (
          <Overview
            key={`overview-${historyKey}`}
            onReplayDone={() => {
              setHistoryKey((k) => k + 1)
              setTab('live')
            }}
          />
        )
    }
  }, [tab, stream, historyKey])

  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-800/80 bg-slate-950/80 backdrop-blur">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 px-4 py-4">
          <div>
            <p className="text-xs uppercase tracking-[0.25em] text-cyan-500/80">AIDTIP</p>
            <h1 className="text-lg font-semibold text-slate-100 sm:text-xl">
              Adaptive Intrusion Detection &amp; Threat Intelligence
            </h1>
          </div>
          <div className="flex items-center gap-3 text-xs text-slate-400">
            <span
              className={`inline-flex items-center gap-2 rounded-full border px-2.5 py-1 ${
                stream.connected
                  ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                  : 'border-slate-700 bg-slate-900 text-slate-500'
              }`}
            >
              <span
                className={`h-1.5 w-1.5 rounded-full ${
                  stream.connected ? 'bg-emerald-400' : 'bg-slate-600'
                }`}
              />
              Live feed {stream.connected ? 'online' : 'offline'}
            </span>
          </div>
        </div>
        <nav className="mx-auto flex max-w-7xl gap-1 overflow-x-auto px-4 pb-3">
          {NAV.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => setTab(item.id)}
              className={`rounded-md px-3 py-1.5 text-sm whitespace-nowrap transition ${
                tab === item.id
                  ? 'bg-slate-800 text-cyan-300'
                  : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
              }`}
            >
              {item.label}
            </button>
          ))}
        </nav>
      </header>

      <main className="mx-auto max-w-7xl px-4 py-6">{content}</main>
    </div>
  )
}
