import { Link } from 'react-router-dom'
import { PlusCircle, Bot, ShieldAlert, FileText, ArrowUpRight } from 'lucide-react'
import { clsx } from 'clsx'

const actions = [
  {
    title: 'Create Assessment',
    description: 'Register scope & configure tool orchestration',
    icon: PlusCircle,
    path: '/assessment/new',
    accent: 'blue',
    borderStyle: 'border-blue-500/30 hover:border-blue-400/60 shadow-glow-blue',
    iconColor: 'text-blue-400',
    bgGradient: 'from-blue-600/15 to-transparent',
    badge: 'Scope Protected',
  },
  {
    title: 'Open AI Agent',
    description: 'Ask AI assistant to plan or analyze security posture',
    icon: Bot,
    path: '/agent',
    accent: 'cyan',
    borderStyle: 'border-cyan-500/30 hover:border-cyan-400/60 shadow-glow-cyan',
    iconColor: 'text-cyan-400',
    bgGradient: 'from-cyan-600/15 to-transparent',
    badge: 'Conversational',
  },
  {
    title: 'View Vulnerabilities',
    description: 'Explore deduplicated findings and CVSS risk scores',
    icon: ShieldAlert,
    path: '/vulnerabilities',
    accent: 'amber',
    borderStyle: 'border-amber-500/30 hover:border-amber-400/60',
    iconColor: 'text-amber-400',
    bgGradient: 'from-amber-600/15 to-transparent',
    badge: 'Normalized',
  },
  {
    title: 'Generate Report',
    description: 'Compile technical summaries and remediation PDFs',
    icon: FileText,
    path: '/reports',
    accent: 'emerald',
    borderStyle: 'border-emerald-500/30 hover:border-emerald-400/60',
    iconColor: 'text-emerald-400',
    bgGradient: 'from-emerald-600/15 to-transparent',
    badge: 'Executive & Tech',
  },
]

export default function QuickActions() {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {actions.map((act) => {
        const Icon = act.icon
        return (
          <Link
            key={act.title}
            to={act.path}
            className={clsx(
              'group relative overflow-hidden rounded-xl border bg-navy-900/90 p-4 transition-all duration-200 hover:-translate-y-0.5',
              act.borderStyle
            )}
          >
            {/* Top background glow gradient */}
            <div
              className={clsx(
                'absolute inset-0 bg-gradient-to-br opacity-50 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none',
                act.bgGradient
              )}
            />

            <div className="relative z-10 flex flex-col justify-between h-full">
              <div className="flex items-start justify-between">
                <div
                  className={clsx(
                    'w-10 h-10 rounded-xl bg-slate-800/80 border border-slate-700/60 flex items-center justify-center transition-transform duration-200 group-hover:scale-105',
                    act.iconColor
                  )}
                >
                  <Icon className="w-5 h-5" />
                </div>
                <div className="flex items-center gap-1">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
                    {act.badge}
                  </span>
                  <ArrowUpRight className="w-4 h-4 text-slate-400 group-hover:text-slate-100 transition-colors" />
                </div>
              </div>

              <div className="mt-3">
                <h3 className="text-sm font-semibold text-slate-100 group-hover:text-cyan-300 transition-colors">
                  {act.title}
                </h3>
                <p className="text-xs text-slate-400 mt-1 line-clamp-2 leading-relaxed">
                  {act.description}
                </p>
              </div>
            </div>
          </Link>
        )
      })}
    </div>
  )
}
