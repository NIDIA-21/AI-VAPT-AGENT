import { clsx } from 'clsx'
import type { ScannerStatus } from '@/types'
import { CheckCircle, XCircle, Loader2, ExternalLink } from 'lucide-react'

interface ToolStatusCardProps {
  scanner: ScannerStatus
}

const categoryColors: Record<string, string> = {
  Network:       'text-blue-400 bg-blue-500/10 border-blue-500/20',
  Web:           'text-cyan-400 bg-cyan-500/10 border-cyan-500/20',
  Vulnerability: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
}

export default function ToolStatusCard({ scanner }: ToolStatusCardProps) {
  const catStyle = categoryColors[scanner.category] ?? 'text-slate-400 bg-slate-500/10 border-slate-500/20'
  return (
    <div
      className={clsx(
        'flex items-center justify-between p-4 rounded-lg border transition-all duration-200',
        scanner.available
          ? 'bg-emerald-500/5 border-emerald-500/20 hover:border-emerald-500/40'
          : 'bg-navy-800/60 border-slate-700/50 hover:border-slate-600/60'
      )}
    >
      <div className="flex items-center gap-3 min-w-0">
        {scanner.available ? (
          <CheckCircle className="w-5 h-5 text-emerald-400 flex-shrink-0" />
        ) : (
          <XCircle className="w-5 h-5 text-slate-600 flex-shrink-0" />
        )}
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-slate-200">{scanner.name}</span>
            <span className={clsx('badge text-[10px] border', catStyle)}>{scanner.category}</span>
          </div>
          <p className="text-xs text-slate-500 truncate mt-0.5">{scanner.description}</p>
          {scanner.available && scanner.version && (
            <p className="text-[10px] text-slate-600 font-mono mt-1 truncate">{scanner.version}</p>
          )}
        </div>
      </div>
      <span
        className={clsx(
          'text-xs font-semibold flex-shrink-0 ml-3',
          scanner.available ? 'text-emerald-400' : 'text-slate-600'
        )}
      >
        {scanner.available ? 'AVAILABLE' : 'NOT FOUND'}
      </span>
    </div>
  )
}
