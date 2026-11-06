import { useState, useMemo } from 'react'
import { Link } from 'react-router-dom'
import {
  Search,
  Filter,
  Eye,
  X,
  Target,
  Clock,
  Shield,
  Layers,
  CheckCircle,
  AlertCircle,
  HelpCircle,
  PlusCircle,
} from 'lucide-react'
import type { AssessmentActivityItem } from '@/types'
import { clsx } from 'clsx'

interface AssessmentActivityTableProps {
  assessments: AssessmentActivityItem[]
  loading: boolean
}

export default function AssessmentActivityTable({ assessments, loading }: AssessmentActivityTableProps) {
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState('ALL')
  const [selectedAssessment, setSelectedAssessment] = useState<AssessmentActivityItem | null>(null)

  const filteredAssessments = useMemo(() => {
    return assessments.filter((asm) => {
      const matchesSearch =
        asm.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        asm.target_host.toLowerCase().includes(searchTerm.toLowerCase()) ||
        asm.name.toLowerCase().includes(searchTerm.toLowerCase())

      const matchesStatus =
        statusFilter === 'ALL' || asm.status.toLowerCase() === statusFilter.toLowerCase()

      return matchesSearch && matchesStatus
    })
  }, [assessments, searchTerm, statusFilter])

  const getStatusBadge = (status: string) => {
    const s = status.toLowerCase()
    switch (s) {
      case 'completed':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            Completed
          </span>
        )
      case 'running':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
            Running
          </span>
        )
      case 'pending_approval':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <Clock className="w-3 h-3" />
            Pending Approval
          </span>
        )
      case 'planning':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-medium bg-blue-500/10 text-blue-400 border border-blue-500/20">
            <Layers className="w-3 h-3" />
            Planning
          </span>
        )
      case 'failed':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-medium bg-red-500/10 text-red-400 border border-red-500/20">
            <AlertCircle className="w-3 h-3" />
            Failed
          </span>
        )
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-medium bg-slate-800 text-slate-300 border border-slate-700">
            <span className="w-1.5 h-1.5 rounded-full bg-slate-400" />
            {status}
          </span>
        )
    }
  }

  const formatTimestamp = (dateStr: string | null) => {
    if (!dateStr) return 'Not started'
    try {
      const d = new Date(dateStr)
      return d.toLocaleDateString(undefined, {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      })
    } catch {
      return dateStr
    }
  }

  return (
    <div className="card space-y-4">
      {/* Header and Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2">
        <div>
          <h3 className="section-title flex items-center gap-2">
            <span>Assessment Activity</span>
            <span className="text-xs font-mono font-normal text-slate-400">
              ({assessments.length} total)
            </span>
          </h3>
          <p className="section-subtitle">
            Historical and executing VAPT engagements against authorized targets
          </p>
        </div>

        {/* Search & Filter */}
        <div className="flex items-center gap-2.5">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search target or ID…"
              className="bg-navy-950/80 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-400 focus:outline-none focus:border-cyan-500/50 w-44 sm:w-56"
            />
          </div>

          <div className="relative">
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-navy-950/80 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500/50 appearance-none pr-7 cursor-pointer"
            >
              <option value="ALL">All Status</option>
              <option value="completed">Completed</option>
              <option value="running">Running</option>
              <option value="pending_approval">Pending Approval</option>
              <option value="planning">Planning</option>
              <option value="draft">Draft</option>
              <option value="failed">Failed</option>
            </select>
            <Filter className="w-3 h-3 text-slate-400 absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
          </div>
        </div>
      </div>

      {/* Table Content */}
      {loading ? (
        <div className="space-y-2 py-4">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-12 bg-slate-800/40 rounded-lg animate-pulse" />
          ))}
        </div>
      ) : assessments.length === 0 ? (
        /* Empty State — No assessments yet */
        <div className="py-12 flex flex-col items-center justify-center text-center p-6 rounded-xl bg-slate-900/30 border border-dashed border-slate-800">
          <div className="w-12 h-12 rounded-2xl bg-blue-600/10 border border-blue-500/20 flex items-center justify-center text-blue-400 mb-3 shadow-glow-blue">
            <Target className="w-6 h-6" />
          </div>
          <h4 className="text-sm font-semibold text-slate-200">No Assessments Created Yet</h4>
          <p className="text-xs text-slate-400 mt-1 max-w-sm leading-relaxed">
            All assessment engagements require target authorization before orchestration can begin.
          </p>
          <Link to="/assessment/new" className="mt-4 btn-primary text-xs py-2">
            <PlusCircle className="w-3.5 h-3.5" />
            Create First Assessment
          </Link>
        </div>
      ) : filteredAssessments.length === 0 ? (
        <div className="py-10 text-center text-xs text-slate-400">
          No assessments match &ldquo;{searchTerm}&rdquo; or selected filter.
        </div>
      ) : (
        /* Data Table */
        <div className="overflow-x-auto rounded-lg border border-slate-800">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-navy-950/80 text-slate-400 font-semibold uppercase tracking-wider text-[10px]">
                <th className="py-3 px-4">Assessment ID</th>
                <th className="py-3 px-4">Target</th>
                <th className="py-3 px-4">Assessment Type</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Start Time</th>
                <th className="py-3 px-4 text-center">Findings</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70 text-slate-300">
              {filteredAssessments.map((asm) => (
                <tr
                  key={asm.id}
                  className="hover:bg-slate-800/40 transition-colors duration-150 group"
                >
                  <td className="py-3 px-4 font-mono text-[11px] text-cyan-400">
                    <span title={asm.id}>
                      asm-{asm.id.slice(0, 8)}…
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-2">
                      <Target className="w-3.5 h-3.5 text-slate-400 flex-shrink-0" />
                      <div>
                        <span className="font-semibold text-slate-200 block truncate max-w-[180px]">
                          {asm.target_host}
                        </span>
                        <span className="text-[10px] text-slate-400 truncate block">
                          {asm.name}
                        </span>
                      </div>
                    </div>
                  </td>
                  <td className="py-3 px-4">
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700/60 text-[11px]">
                      {asm.assessment_type}
                    </span>
                  </td>
                  <td className="py-3 px-4">{getStatusBadge(asm.status)}</td>
                  <td className="py-3 px-4 text-slate-400 font-mono text-[11px]">
                    {formatTimestamp(asm.start_time)}
                  </td>
                  <td className="py-3 px-4 text-center">
                    <span
                      className={clsx(
                        'px-2 py-0.5 rounded-full font-mono text-[11px] font-bold border',
                        asm.findings_count > 0
                          ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                          : 'bg-slate-800 text-slate-400 border-slate-700'
                      )}
                    >
                      {asm.findings_count}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right">
                    <button
                      onClick={() => setSelectedAssessment(asm)}
                      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-cyan-300 border border-slate-700/70 transition-colors text-[11px]"
                    >
                      <Eye className="w-3 h-3" />
                      View
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* ── View Assessment Details Modal ─────────────────────────────────── */}
      {selectedAssessment && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-navy-950/80 backdrop-blur-sm animate-fade-in">
          <div className="bg-navy-900 border border-slate-700 rounded-2xl w-full max-w-lg p-6 shadow-2xl relative">
            <button
              onClick={() => setSelectedAssessment(null)}
              className="absolute top-4 right-4 p-1.5 rounded-lg text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>

            <div className="flex items-center gap-3 pb-4 border-b border-slate-800">
              <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                <Shield className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-semibold text-slate-100">{selectedAssessment.name}</h3>
                <p className="text-xs font-mono text-cyan-400 mt-0.5">ID: {selectedAssessment.id}</p>
              </div>
            </div>

            <div className="mt-5 space-y-3.5 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 rounded-lg bg-navy-950/80 border border-slate-800">
                  <span className="text-slate-400 text-[10px] uppercase font-mono block">Target Host</span>
                  <span className="font-semibold text-slate-200 mt-1 block font-mono">
                    {selectedAssessment.target_host}
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-navy-950/80 border border-slate-800">
                  <span className="text-slate-400 text-[10px] uppercase font-mono block">Status</span>
                  <div className="mt-1">{getStatusBadge(selectedAssessment.status)}</div>
                </div>

                <div className="p-3 rounded-lg bg-navy-950/80 border border-slate-800">
                  <span className="text-slate-400 text-[10px] uppercase font-mono block">Assessment Type</span>
                  <span className="font-medium text-slate-200 mt-1 block">
                    {selectedAssessment.assessment_type}
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-navy-950/80 border border-slate-800">
                  <span className="text-slate-400 text-[10px] uppercase font-mono block">Discovered Findings</span>
                  <span className="font-mono font-bold text-amber-400 mt-1 block text-sm">
                    {selectedAssessment.findings_count}
                  </span>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-navy-950/80 border border-slate-800">
                <span className="text-slate-400 text-[10px] uppercase font-mono block">Execution Timestamp</span>
                <span className="font-mono text-slate-300 mt-1 block">
                  {selectedAssessment.start_time
                    ? new Date(selectedAssessment.start_time).toUTCString()
                    : 'Created: ' + new Date(selectedAssessment.created_at).toUTCString()}
                </span>
              </div>
            </div>

            <div className="mt-6 flex justify-end gap-2.5">
              <button
                onClick={() => setSelectedAssessment(null)}
                className="btn-secondary text-xs py-2 px-4"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
