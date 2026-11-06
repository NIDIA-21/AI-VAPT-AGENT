import { useState, useEffect } from 'react'
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  RefreshCw,
  FileText,
  Shield,
  Layers,
  Globe,
  Server,
  FileCode,
  Flame,
} from 'lucide-react'
import type { ToolStatusItem, ToolIntegrationState } from '@/types'
import { dashboardApi } from '@/services/api'
import { clsx } from 'clsx'

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

export default function Integrations() {
  const [tools, setTools] = useState<ToolStatusItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [lastChecked, setLastChecked] = useState<Date | null>(null)

  const fetchTools = async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await dashboardApi.tools()
      setTools(data.tools)
      setLastChecked(new Date())
    } catch (err: any) {
      setError(err?.userMessage ?? 'Failed to probe tool integrations')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchTools()
  }, [])

  const availableCount = tools.filter((t) => t.status === 'Available').length

  return (
    <div className="space-y-6 animate-fade-in pb-10">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-bold text-slate-100 tracking-tight">Tool Integrations</h2>
          <p className="text-xs text-slate-400 mt-1">
            Status of the 7 supported cybersecurity scanners — verified safely using executable PATH probes
          </p>
        </div>

        <button
          onClick={fetchTools}
          disabled={loading}
          className="btn-secondary text-xs py-2 px-3 self-start sm:self-auto flex items-center gap-1.5"
        >
          <RefreshCw className={clsx('w-3.5 h-3.5', loading && 'animate-spin text-cyan-400')} />
          <span>Re-probe Tools</span>
        </button>
      </div>

      {/* Summary banner */}
      {!loading && !error && (
        <div
          className={clsx(
            'flex items-center gap-3 p-4 rounded-xl border text-xs',
            availableCount > 0
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              : 'bg-amber-500/10 border-amber-500/30 text-amber-300'
          )}
        >
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          <span>
            {availableCount} of {tools.length} security tools verified on system PATH.
            {availableCount === 0 &&
              ' External scanners are optional for dashboard development. Install Nmap or ZAP locally to enable real scan execution in future phases.'}
          </span>
        </div>
      )}

      {error && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-xs">
          {error}
        </div>
      )}

      {/* Scanner grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {loading
          ? [1, 2, 3, 4, 5, 6, 7].map((i) => (
              <div key={i} className="card h-44 animate-pulse bg-navy-800/60" />
            ))
          : tools.map((tool) => {
              const Icon = toolIcons[tool.name] || Shield
              const style = statusBadgeStyles[tool.status] || statusBadgeStyles['Not Installed']
              const StatusIcon = style.icon

              return (
                <div
                  key={tool.name}
                  className={clsx(
                    'card flex flex-col justify-between transition-all duration-200 hover:border-slate-600/80',
                    tool.status === 'Available' ? 'border-emerald-500/30' : 'border-slate-800'
                  )}
                >
                  <div>
                    <div className="flex items-start justify-between gap-2 mb-3">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-xl bg-slate-800/80 border border-slate-700/60 flex items-center justify-center text-cyan-400 flex-shrink-0">
                          <Icon className="w-5 h-5" />
                        </div>
                        <div>
                          <h3 className="text-sm font-semibold text-slate-100">{tool.display_name}</h3>
                          <span className="text-[11px] text-slate-400 font-mono">{tool.category}</span>
                        </div>
                      </div>

                      <span
                        className={clsx(
                          'inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full border flex-shrink-0',
                          style.badgeClass
                        )}
                      >
                        <StatusIcon className="w-3 h-3" />
                        {style.label}
                      </span>
                    </div>

                    <p className="text-xs text-slate-400 mb-3 leading-relaxed">{tool.description}</p>

                    {tool.path && (
                      <p className="text-[10px] font-mono text-slate-400 truncate bg-slate-900/60 p-1.5 rounded border border-slate-800">
                        {tool.path}
                      </p>
                    )}
                  </div>

                  <div className="mt-4 pt-3 border-t border-slate-800/80">
                    <span className="text-[10px] text-slate-400 uppercase font-mono block mb-1.5">
                      Capabilities
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {tool.capabilities.map((cap) => (
                        <span
                          key={cap}
                          className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800/80 text-slate-300 border border-slate-700/50"
                        >
                          {cap}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              )
            })}
      </div>
    </div>
  )
}
