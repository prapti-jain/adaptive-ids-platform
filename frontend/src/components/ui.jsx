export const SEVERITY_COLORS = {
  CRITICAL: {
    text: 'text-red-400',
    bg: 'bg-red-500/15',
    border: 'border-red-500/40',
    chart: '#f87171',
  },
  HIGH: {
    text: 'text-orange-400',
    bg: 'bg-orange-500/15',
    border: 'border-orange-500/40',
    chart: '#fb923c',
  },
  MEDIUM: {
    text: 'text-amber-300',
    bg: 'bg-amber-500/15',
    border: 'border-amber-500/40',
    chart: '#fbbf24',
  },
  LOW: {
    text: 'text-sky-400',
    bg: 'bg-sky-500/15',
    border: 'border-sky-500/40',
    chart: '#38bdf8',
  },
}

export function SeverityBadge({ severity }) {
  const tone = SEVERITY_COLORS[severity] || SEVERITY_COLORS.LOW
  return (
    <span
      className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-semibold tracking-wide ${tone.bg} ${tone.text} border ${tone.border}`}
    >
      {severity}
    </span>
  )
}

export function formatTime(value) {
  if (!value) return '—'
  const date = new Date(value)
  return date.toLocaleString(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

export function EmptyState({ title, detail, action }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-slate-700 bg-slate-900/40 px-6 py-16 text-center">
      <p className="text-lg font-medium text-slate-200">{title}</p>
      {detail ? <p className="max-w-md text-sm text-slate-400">{detail}</p> : null}
      {action}
    </div>
  )
}

export function LoadingBlock({ label = 'Loading…' }) {
  return (
    <div className="flex items-center justify-center py-16 text-sm text-slate-400">
      <span className="mr-2 inline-block h-2 w-2 animate-pulse rounded-full bg-cyan-400" />
      {label}
    </div>
  )
}
