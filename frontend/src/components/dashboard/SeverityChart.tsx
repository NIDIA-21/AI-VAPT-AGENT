import { clsx } from 'clsx'
import type { SeverityCount } from '@/types'
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell,
  CartesianGrid,
} from 'recharts'
import { ShieldCheck, Info } from 'lucide-react'

interface SeverityChartProps {
  data: SeverityCount
  loading?: boolean
}

const SEVERITY_CONFIG = [
  { key: 'critical',      label: 'Critical',      color: '#ef4444', desc: 'CVSS 9.0–10.0' },
  { key: 'high',          label: 'High',          color: '#f97316', desc: 'CVSS 7.0–8.9' },
  { key: 'medium',        label: 'Medium',        color: '#f59e0b', desc: 'CVSS 4.0–6.9' },
  { key: 'low',           label: 'Low',           color: '#3b82f6', desc: 'CVSS 0.1–3.9' },
  { key: 'informational', label: 'Informational', color: '#06b6d4', desc: 'Contextual info' },
]

const CustomTooltip = ({ active, payload, label }: any) => {
  if (active && payload?.length) {
    const config = SEVERITY_CONFIG.find((c) => c.label === label)
    return (
      <div className="bg-navy-900 border border-slate-700 rounded-xl p-3 shadow-2xl text-xs">
        <div className="flex items-center gap-2 mb-1">
          <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: config?.color }} />
          <span className="text-slate-100 font-semibold">{label}</span>
          <span className="text-[10px] text-slate-400 font-mono">({config?.desc})</span>
        </div>
        <p className="text-slate-300 font-mono text-sm font-bold">
          {payload[0].value} <span className="text-xs text-slate-400 font-normal">finding(s)</span>
        </p>
      </div>
    )
  }
  return null
}

export default function SeverityChart({ data, loading }: SeverityChartProps) {
  const chartData = SEVERITY_CONFIG.map((s) => ({
    name: s.label,
    count: data[s.key as keyof SeverityCount] ?? 0,
    color: s.color,
  }))

  const total = chartData.reduce((sum, d) => sum + d.count, 0)

  if (loading) {
    return (
      <div className="h-64 flex flex-col items-center justify-center gap-3">
        <div className="w-9 h-9 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
        <span className="text-xs text-slate-400 font-mono">Loading vulnerability metrics…</span>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Chart Header Meta */}
      <div className="flex items-center justify-between text-xs pb-1 border-b border-slate-800">
        <span className="text-slate-400">Total Normalised Findings:</span>
        <span className="font-mono font-bold text-slate-200 bg-slate-800 px-2 py-0.5 rounded border border-slate-700">
          {total}
        </span>
      </div>

      {total === 0 ? (
        /* Empty State */
        <div className="h-52 flex flex-col items-center justify-center text-center p-6 rounded-xl bg-slate-900/40 border border-dashed border-slate-800">
          <div className="w-12 h-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400 mb-3 shadow-glow-cyan">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <h4 className="text-sm font-semibold text-slate-200">Zero Findings Recorded</h4>
          <p className="text-xs text-slate-400 mt-1 max-w-sm leading-relaxed">
            Database contains 0 vulnerabilities. Register an authorized target and launch an assessment to generate real scanner findings.
          </p>
        </div>
      ) : (
        /* Recharts Visualization */
        <div className="h-52 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis
                dataKey="name"
                tick={{ fill: '#94a3b8', fontSize: 11 }}
                axisLine={{ stroke: '#334155' }}
                tickLine={false}
              />
              <YAxis
                tick={{ fill: '#94a3b8', fontSize: 11 }}
                axisLine={{ stroke: '#334155' }}
                tickLine={false}
                allowDecimals={false}
              />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.03)' }} />
              <Bar dataKey="count" radius={[6, 6, 0, 0]} maxBarSize={48}>
                {chartData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} fillOpacity={0.9} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Severity Badges Breakdown */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 pt-1">
        {SEVERITY_CONFIG.map((s) => {
          const val = data[s.key as keyof SeverityCount] ?? 0
          return (
            <div
              key={s.key}
              className="flex flex-col p-2 rounded-lg bg-navy-950/60 border border-slate-800"
            >
              <div className="flex items-center gap-1.5">
                <div className="w-2 h-2 rounded-full" style={{ backgroundColor: s.color }} />
                <span className="text-[11px] font-medium text-slate-400 truncate">{s.label}</span>
              </div>
              <span className="text-sm font-bold text-slate-200 font-mono mt-1">{val}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
