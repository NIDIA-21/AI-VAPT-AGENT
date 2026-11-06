import { Link } from 'react-router-dom'
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  ArrowRight,
  Shield,
  FileCode,
  Flame,
  Globe,
  Server,
  Layers,
  FileText,
} from 'lucide-react'
import type { ToolStatusItem, ToolIntegrationState } from '@/types'
import { clsx } from 'clsx'

interface ToolIntegrationsGridProps {
  tools: ToolStatusItem[]
  loading: boolean
}

const statusBadgeStyles: Record<
  ToolIntegrationState,
  { label: string; badgeClass: string; icon: React.ElementType }
> = {
  Available: {
    label: 'Available',
    badgeClass: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 shadow-glow-cyan',
    icon: CheckCircle2,
  },
  'Not Installed': {
    label: 'Not Installed',
    badgeClass: 'bg-slate-800 text-slate-400 border-slate-700',
    icon: XCircle,
  },
  'Not Configured': {
    label: 'Not Configured',
    badgeClass: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    icon: AlertTriangle,
  },
  'Import Only': {
    label: 'Import Only',
    badgeClass: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
    icon: FileText,
  },
  Planned: {
    label: 'Planned',
    badgeClass: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30',
    icon: Clock,
  },
  Unsupported: {
    label: 'Unsupported',
    badgeClass: 'bg-red-500/10 text-red-400 border-red-500/30',
    icon: XCircle,
  },
}

const toolIcons: Record<string, React.ElementType> = {
  nmap: Layers,
  zap: Globe,
  nikto: Server,
  nessus: Shield,
  openvas: FileCode,
  burpsuite: Globe,
  metasploit: Flame,
}

export default function ToolIntegrationsGrid({ tools, loading }: ToolIntegrationsGridProps) {
  const availableCount = tools.filter((t) => t.status === 'Available').length

  return (
    <div className="card space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2">
        <div>
          <h3 className="section-title flex items-center gap-2">
            <span>Scanner Integration Status</span>
            <span className="text-xs font-mono font-normal text-slate-400">
              ({availableCount} of {tools.length} available)
            </span>
          </h3>
          <p className="section-subtitle">
            Safe executable path verification — active scanning disabled without authorization
          </p>
        </div>

        <Link
          to="/integrations"
          className="flex items-center gap-1.5 text-xs text-cyan-400 hover:text-cyan-300 transition-colors self-start sm:self-auto"
        >
          <span>All Integrations</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </Link>
      </div>

      {/* Grid of Tools */}
      {loading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5">
          {[1, 2, 3, 4, 5, 6, 7].map((i) => (
            <div key={i} className="h-32 rounded-xl bg-slate-800/40 animate-pulse" />
          ))}
        </div>
      ) : tools.length === 0 ? (
        <div className="p-8 text-center text-xs text-slate-400">
          No tool integration status returned by backend.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5">
          {tools.map((tool) => {
            const Icon = toolIcons[tool.name] || Shield
            const style = statusBadgeStyles[tool.status] || statusBadgeStyles['Not Installed']
            const StatusIcon = style.icon

            return (
              <div
                key={tool.name}
                className={clsx(
                  'relative rounded-xl border bg-navy-950/70 p-4 transition-all duration-200 flex flex-col justify-between hover:border-slate-700/80',
                  tool.status === 'Available' ? 'border-emerald-500/20' : 'border-slate-800'
                )}
              >
                <div>
                  {/* Top: Icon + Name + Badge */}
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2.5">
                      <div className="w-8 h-8 rounded-lg bg-slate-800/80 border border-slate-700/60 flex items-center justify-center text-cyan-400 flex-shrink-0">
                        <Icon className="w-4 h-4" />
                      </div>
                      <div>
                        <h4 className="text-xs font-bold text-slate-100">{tool.display_name}</h4>
                        <p className="text-[10px] text-slate-400 font-mono leading-none mt-0.5">
                          {tool.category}
                        </p>
                      </div>
                    </div>

                    <span
                      className={clsx(
                        'inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold border flex-shrink-0',
                        style.badgeClass
                      )}
                    >
                      <StatusIcon className="w-3 h-3" />
                      {style.label}
                    </span>
                  </div>

                  {/* Description */}
                  <p className="text-[11px] text-slate-400 mt-2.5 line-clamp-2 leading-relaxed">
                    {tool.description}
                  </p>
                </div>

                {/* Capabilities Chips */}
                <div className="mt-3 pt-2.5 border-t border-slate-800/70">
                  <div className="flex flex-wrap gap-1">
                    {tool.capabilities.slice(0, 3).map((cap) => (
                      <span
                        key={cap}
                        className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-slate-800/70 text-slate-300 border border-slate-700/40 truncate"
                      >
                        {cap}
                      </span>
                    ))}
                    {tool.capabilities.length > 3 && (
                      <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-slate-800/40 text-slate-400">
                        +{tool.capabilities.length - 3}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
