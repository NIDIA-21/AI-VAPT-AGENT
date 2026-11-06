import { Shield, Activity, ShieldAlert, Flame } from 'lucide-react'
import type { DashboardStats } from '@/types'
import { clsx } from 'clsx'

interface MetricCardsProps {
  stats: DashboardStats
  loading: boolean
}

interface CardDef {
  id: string
  title: string
  getValue: (s: DashboardStats) => number
  description: string
  icon: React.ElementType
  accent: 'blue' | 'cyan' | 'amber' | 'red'
  glow: string
  iconColor: string
  borderColor: string
}

const cardDefinitions: CardDef[] = [
  {
    id: 'total_assessments',
    title: 'Total Assessments',
    getValue: (s) => s.total_assessments,
    description: 'Authorized scope assessments',
    icon: Shield,
    accent: 'blue',
    glow: 'hover:shadow-glow-blue',
    iconColor: 'text-blue-400',
    borderColor: 'border-blue-500/20 hover:border-blue-500/40',
  },
  {
    id: 'active_scans',
    title: 'Active Scans',
    getValue: (s) => s.active_scans,
    description: 'Jobs queued or executing',
    icon: Activity,
    accent: 'cyan',
    glow: 'hover:shadow-glow-cyan',
    iconColor: 'text-cyan-400',
    borderColor: 'border-cyan-500/20 hover:border-cyan-500/40',
  },
  {
    id: 'total_vulnerabilities',
    title: 'Total Vulnerabilities',
    getValue: (s) => s.total_vulnerabilities,
    description: 'Deduplicated normalized findings',
    icon: ShieldAlert,
    accent: 'amber',
    glow: '',
    iconColor: 'text-amber-400',
    borderColor: 'border-amber-500/20 hover:border-amber-500/40',
  },
  {
    id: 'critical_vulnerabilities',
    title: 'Critical Vulnerabilities',
    getValue: (s) => s.critical_vulnerabilities,
    description: 'CVSS 9.0–10.0 highest priority',
    icon: Flame,
    accent: 'red',
    glow: 'hover:shadow-glow-red',
    iconColor: 'text-red-400',
    borderColor: 'border-red-500/20 hover:border-red-500/40',
  },
]

export default function MetricCards({ stats, loading }: MetricCardsProps) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {cardDefinitions.map((card) => {
        const Icon = card.icon
        const count = card.getValue(stats)

        return (
          <div
            key={card.id}
            className={clsx(
              'relative rounded-xl border bg-navy-900/90 p-5 transition-all duration-200 select-none shadow-card',
              card.borderColor,
              card.glow
            )}
          >
            <div className="flex items-start justify-between">
              <div>
                <p className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                  {card.title}
                </p>
                {loading ? (
                  <div className="mt-2 h-9 w-20 rounded bg-slate-800/80 animate-pulse" />
                ) : (
                  <div className="mt-1.5 flex items-baseline gap-2">
                    <span className="text-3xl font-extrabold tracking-tight text-slate-100 font-mono">
                      {count}
                    </span>
                    {count === 0 && (
                      <span className="text-[10px] text-slate-400 font-medium">None active</span>
                    )}
                  </div>
                )}
                {loading ? (
                  <div className="mt-2 h-3.5 w-32 rounded bg-slate-800/60 animate-pulse" />
                ) : (
                  <p className="text-xs text-slate-400 mt-1.5 truncate">
                    {card.description}
                  </p>
                )}
              </div>

              <div
                className={clsx(
                  'w-11 h-11 rounded-xl bg-slate-800/80 border border-slate-700/60 flex items-center justify-center flex-shrink-0 transition-transform duration-200 hover:scale-105',
                  card.iconColor
                )}
              >
                <Icon className="w-5 h-5" />
              </div>
            </div>

            {/* Subtle bottom accent line */}
            <div
              className={clsx(
                'absolute bottom-0 left-4 right-4 h-0.5 rounded-full opacity-30',
                card.accent === 'blue' && 'bg-blue-500',
                card.accent === 'cyan' && 'bg-cyan-500',
                card.accent === 'amber' && 'bg-amber-500',
                card.accent === 'red' && 'bg-red-500'
              )}
            />
          </div>
        )
      })}
    </div>
  )
}
