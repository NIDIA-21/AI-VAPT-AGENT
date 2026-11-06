import { clsx } from 'clsx'
import type { LucideIcon } from 'lucide-react'

interface StatCardProps {
  title: string
  value: string | number
  icon: LucideIcon
  trend?: { value: string; positive: boolean }
  accent?: 'blue' | 'cyan' | 'emerald' | 'red' | 'orange' | 'yellow'
  loading?: boolean
}

const accentMap = {
  blue:    { bg: 'bg-blue-500/10',    border: 'border-blue-500/20',    icon: 'text-blue-400',    glow: 'shadow-glow-blue' },
  cyan:    { bg: 'bg-cyan-500/10',    border: 'border-cyan-500/20',    icon: 'text-cyan-400',    glow: 'shadow-glow-cyan' },
  emerald: { bg: 'bg-emerald-500/10', border: 'border-emerald-500/20', icon: 'text-emerald-400', glow: '' },
  red:     { bg: 'bg-red-500/10',     border: 'border-red-500/20',     icon: 'text-red-400',     glow: 'shadow-glow-red' },
  orange:  { bg: 'bg-orange-500/10',  border: 'border-orange-500/20',  icon: 'text-orange-400',  glow: '' },
  yellow:  { bg: 'bg-yellow-500/10',  border: 'border-yellow-500/20',  icon: 'text-yellow-400',  glow: '' },
}

export default function StatCard({ title, value, icon: Icon, trend, accent = 'blue', loading }: StatCardProps) {
  const a = accentMap[accent]
  return (
    <div className={clsx('card hover:border-slate-600/60 transition-all duration-200', a.glow && 'hover:' + a.glow)}>
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium text-slate-500 uppercase tracking-widest mb-2">{title}</p>
          {loading ? (
            <div className="h-8 w-16 bg-slate-700/50 rounded animate-pulse" />
          ) : (
            <p className="text-3xl font-bold text-slate-100">{value}</p>
          )}
          {trend && !loading && (
            <p className={clsx('text-xs mt-2 font-medium', trend.positive ? 'text-emerald-400' : 'text-red-400')}>
              {trend.positive ? '↑' : '↓'} {trend.value}
            </p>
          )}
        </div>
        <div className={clsx('w-11 h-11 rounded-xl flex items-center justify-center border', a.bg, a.border)}>
          <Icon className={clsx('w-5 h-5', a.icon)} />
        </div>
      </div>
    </div>
  )
}
