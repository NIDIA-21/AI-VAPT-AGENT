import { Link } from 'react-router-dom'
import {
  Bot,
  Compass,
  Wrench,
  Activity,
  ShieldCheck,
  AlertTriangle,
  Radio,
  ArrowRight,
  Clock,
  Sparkles,
} from 'lucide-react'
import type { AgentActivityItem } from '@/types'
import { clsx } from 'clsx'

interface AgentActivityPanelProps {
  activities: AgentActivityItem[]
  loading: boolean
}

const categoryMeta: Record<
  string,
  { label: string; icon: React.ElementType; color: string; badge: string }
> = {
  planning: {
    label: 'Assessment Planning',
    icon: Compass,
    color: 'text-blue-400',
    badge: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  },
  tool_selection: {
    label: 'Tool Selection',
    icon: Wrench,
    color: 'text-cyan-400',
    badge: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
  },
  scan_status: {
    label: 'Scan Status',
    icon: Activity,
    color: 'text-indigo-400',
    badge: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/20',
  },
  analysis: {
    label: 'Analysis Event',
    icon: ShieldCheck,
    color: 'text-emerald-400',
    badge: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  },
  warning: {
    label: 'Warning / Failure',
    icon: AlertTriangle,
    color: 'text-amber-400',
    badge: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  },
  system: {
    label: 'System Audit',
    icon: Radio,
    color: 'text-slate-400',
    badge: 'bg-slate-800 text-slate-300 border-slate-700',
  },
}

export default function AgentActivityPanel({ activities, loading }: AgentActivityPanelProps) {
  const formatTime = (ts: string) => {
    try {
      const d = new Date(ts)
      return d.toLocaleTimeString(undefined, {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      })
    } catch {
      return ts
    }
  }

  return (
    <div className="card space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between pb-2 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400 shadow-glow-cyan">
            <Bot className="w-4 h-4" />
          </div>
          <div>
            <h3 className="section-title text-sm">AI Agent Activity Stream</h3>
            <p className="section-subtitle text-[11px]">
              Autonomous reasoning decisions, tool orchestration, and validation events
            </p>
          </div>
        </div>

        <Link
          to="/agent"
          className="flex items-center gap-1.5 text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
        >
          <span>Open Agent</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </Link>
      </div>

      {/* Content */}
      {loading ? (
        <div className="space-y-3 py-3">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-14 rounded-lg bg-slate-800/40 animate-pulse" />
          ))}
        </div>
      ) : activities.length === 0 ? (
        /* Informational Empty State */
        <div className="py-8 px-4 flex flex-col items-center justify-center text-center rounded-xl bg-slate-900/30 border border-dashed border-slate-800">
          <div className="w-11 h-11 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400 mb-2.5 shadow-glow-cyan">
            <Sparkles className="w-5 h-5" />
          </div>
          <h4 className="text-xs font-semibold text-slate-200">AI Agent Standby</h4>
          <p className="text-[11px] text-slate-400 mt-1 max-w-xs leading-relaxed">
            No agent decisions or audit activities logged yet. As the AI security assistant plans assessments, selects tools, and parses evidence, events stream here live.
          </p>
          <Link
            to="/agent"
            className="mt-3.5 inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 text-xs font-medium transition-all duration-150"
          >
            <Bot className="w-3.5 h-3.5" />
            Engage AI Assistant
          </Link>
        </div>
      ) : (
        /* Event Stream List */
        <div className="space-y-2.5 max-h-80 overflow-y-auto pr-1">
          {activities.map((item) => {
            const cat = categoryMeta[item.category] || categoryMeta.system
            const CatIcon = cat.icon

            return (
              <div
                key={item.id}
                className="flex items-start gap-3 p-3 rounded-xl bg-navy-950/70 border border-slate-800/80 hover:border-slate-700 transition-colors"
              >
                <div
                  className={clsx(
                    'w-7 h-7 rounded-lg bg-slate-800/80 border border-slate-700/60 flex items-center justify-center flex-shrink-0 mt-0.5',
                    cat.color
                  )}
                >
                  <CatIcon className="w-3.5 h-3.5" />
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-2">
                    <span
                      className={clsx(
                        'text-[10px] font-mono px-2 py-0.2 rounded-full border',
                        cat.badge
                      )}
                    >
                      {cat.label}
                    </span>
                    <span className="text-[10px] font-mono text-slate-400 flex items-center gap-1">
                      <Clock className="w-2.5 h-2.5" />
                      {formatTime(item.timestamp)}
                    </span>
                  </div>

                  <p className="text-xs text-slate-200 mt-1.5 leading-relaxed break-words">
                    {item.description}
                  </p>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
