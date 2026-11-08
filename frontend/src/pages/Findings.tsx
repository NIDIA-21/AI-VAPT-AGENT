import { useState, useEffect } from 'react'
import {
  ShieldAlert,
  Search,
  Filter,
  CheckCircle2,
  XCircle,
  Eye,
  AlertTriangle,
  RefreshCw,
  Layers,
  ArrowUpDown,
  Tag,
  ExternalLink,
  SlidersHorizontal,
} from 'lucide-react'
import type { Finding } from '@/types'
import { findingsApi } from '@/services/api'
import { clsx } from 'clsx'

export default function Findings() {
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Filters
  const [searchTerm, setSearchTerm] = useState('')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')
  const [toolFilter, setToolFilter] = useState('all')

  // Detail Modal
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)
  const [updatingStatus, setUpdatingStatus] = useState(false)
  const [fpNote, setFpNote] = useState('')
  const [showStatusModal, setShowStatusModal] = useState(false)

  const fetchFindings = async () => {
    try {
      setLoading(true)
      setError(null)
      const data = await findingsApi.list()
      setFindings(data)
    } catch (err: any) {
      setError(err?.userMessage || 'Failed to fetch vulnerability findings.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchFindings()
  }, [])

  const handleUpdateStatus = async (newStatus: 'CONFIRMED' | 'FALSE_POSITIVE' | 'INVESTIGATING') => {
    if (!selectedFinding) return
    setUpdatingStatus(true)
    try {
      const updated = await findingsApi.updateStatus(selectedFinding.id, {
        validation_status: newStatus,
        notes: newStatus === 'FALSE_POSITIVE' ? fpNote : undefined,
      })
      setSelectedFinding(updated)
      setShowStatusModal(false)
      setFpNote('')
      await fetchFindings()
    } catch (err: any) {
      alert(err?.userMessage || 'Failed to update validation status.')
    } finally {
      setUpdatingStatus(false)
    }
  }

  const getSeverityBadge = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical':
        return <span className="px-2 py-0.5 rounded text-xs font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">CRITICAL</span>
      case 'high':
        return <span className="px-2 py-0.5 rounded text-xs font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">HIGH</span>
      case 'medium':
        return <span className="px-2 py-0.5 rounded text-xs font-bold bg-yellow-500/20 text-yellow-300 border border-yellow-500/30">MEDIUM</span>
      case 'low':
        return <span className="px-2 py-0.5 rounded text-xs font-bold bg-blue-500/20 text-blue-400 border border-blue-500/30">LOW</span>
      default:
        return <span className="px-2 py-0.5 rounded text-xs font-bold bg-slate-500/20 text-slate-300 border border-slate-500/30">INFO</span>
    }
  }

  const getRiskScorePill = (score: number | null | undefined, isFp?: boolean) => {
    if (isFp) {
      return (
        <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-slate-800 text-slate-500 line-through">
          0.0 / 100
        </span>
      )
    }
    const val = score ?? 0
    let colorClass = 'bg-slate-500/20 text-slate-300 border-slate-500/30'
    if (val >= 80) colorClass = 'bg-rose-500/20 text-rose-400 border-rose-500/40 shadow-glow-red'
    else if (val >= 60) colorClass = 'bg-amber-500/20 text-amber-400 border-amber-500/40'
    else if (val >= 40) colorClass = 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40'
    else if (val >= 20) colorClass = 'bg-blue-500/20 text-blue-400 border-blue-500/40'

    return (
      <span className={clsx('px-2.5 py-0.5 rounded-full text-xs font-mono font-bold border', colorClass)}>
        {val.toFixed(1)} / 100
      </span>
    )
  }

  const filteredFindings = findings.filter((f) => {
    if (severityFilter !== 'all' && f.severity.toLowerCase() !== severityFilter.toLowerCase()) return false
    if (statusFilter !== 'all') {
      if (statusFilter === 'FALSE_POSITIVE' && !f.is_false_positive) return false
      if (statusFilter === 'CONFIRMED' && f.validation_status !== 'CONFIRMED') return false
      if (statusFilter === 'UNVALIDATED' && (f.validation_status !== 'UNVALIDATED' || f.is_false_positive)) return false
    }
    if (toolFilter !== 'all' && !(f.source_tool || '').toLowerCase().includes(toolFilter.toLowerCase())) return false
    if (searchTerm.trim()) {
      const term = searchTerm.toLowerCase()
      const match =
        f.title.toLowerCase().includes(term) ||
        (f.cve_id || '').toLowerCase().includes(term) ||
        (f.cwe_id || '').toLowerCase().includes(term) ||
        (f.host || '').toLowerCase().includes(term) ||
        (f.description || '').toLowerCase().includes(term)
      if (!match) return false
    }
    return true
  })

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
            <ShieldAlert className="w-6 h-6 text-rose-400" />
            Unified Vulnerability Findings
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Normalized, deduplicated, and risk-prioritized findings across Nmap, OWASP ZAP, and Nikto with raw evidence preservation.
          </p>
        </div>
        <button
          onClick={fetchFindings}
          disabled={loading}
          className="btn-secondary flex items-center gap-2 text-sm px-3 py-2 self-start sm:self-auto"
        >
          <RefreshCw className={clsx('w-4 h-4', loading && 'animate-spin')} />
          Refresh
        </button>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <div className="card p-3 border-l-4 border-l-rose-500">
          <p className="text-xs text-slate-400">Critical</p>
          <p className="text-xl font-bold text-rose-400 mt-0.5">
            {findings.filter((f) => f.severity.toLowerCase() === 'critical' && !f.is_false_positive).length}
          </p>
        </div>
        <div className="card p-3 border-l-4 border-l-amber-500">
          <p className="text-xs text-slate-400">High</p>
          <p className="text-xl font-bold text-amber-400 mt-0.5">
            {findings.filter((f) => f.severity.toLowerCase() === 'high' && !f.is_false_positive).length}
          </p>
        </div>
        <div className="card p-3 border-l-4 border-l-yellow-500">
          <p className="text-xs text-slate-400">Medium</p>
          <p className="text-xl font-bold text-yellow-300 mt-0.5">
            {findings.filter((f) => f.severity.toLowerCase() === 'medium' && !f.is_false_positive).length}
          </p>
        </div>
        <div className="card p-3 border-l-4 border-l-blue-500">
          <p className="text-xs text-slate-400">Low / Info</p>
          <p className="text-xl font-bold text-blue-400 mt-0.5">
            {findings.filter((f) => ['low', 'informational', 'info'].includes(f.severity.toLowerCase()) && !f.is_false_positive).length}
          </p>
        </div>
        <div className="card p-3 border-l-4 border-l-slate-600">
          <p className="text-xs text-slate-400">False Positives</p>
          <p className="text-xl font-bold text-slate-400 mt-0.5">
            {findings.filter((f) => f.is_false_positive).length}
          </p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="card p-4 space-y-3">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search findings by CVE, CWE, title, host, or keyword..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 py-2 text-sm bg-slate-950 text-slate-100 border border-slate-700/80 rounded-lg placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
            />
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="text-xs py-2 px-3 bg-slate-950 text-slate-100 border border-slate-700/80 rounded-lg focus:border-cyan-500 focus:outline-none font-mono"
            >
              <option value="all" className="bg-slate-950 text-slate-100">All Severities</option>
              <option value="critical" className="bg-slate-950 text-rose-400">Critical</option>
              <option value="high" className="bg-slate-950 text-amber-400">High</option>
              <option value="medium" className="bg-slate-950 text-yellow-300">Medium</option>
              <option value="low" className="bg-slate-950 text-cyan-400">Low</option>
              <option value="informational" className="bg-slate-950 text-slate-400">Info</option>
            </select>

            <select
              value={toolFilter}
              onChange={(e) => setToolFilter(e.target.value)}
              className="text-xs py-2 px-3 bg-slate-950 text-slate-100 border border-slate-700/80 rounded-lg focus:border-cyan-500 focus:outline-none font-mono"
            >
              <option value="all" className="bg-slate-950 text-slate-100">All Tools</option>
              <option value="nmap" className="bg-slate-950 text-slate-100">Nmap</option>
              <option value="zap" className="bg-slate-950 text-slate-100">OWASP ZAP</option>
              <option value="nikto" className="bg-slate-950 text-slate-100">Nikto</option>
            </select>

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="text-xs py-2 px-3 bg-slate-950 text-slate-100 border border-slate-700/80 rounded-lg focus:border-cyan-500 focus:outline-none font-mono"
            >
              <option value="all" className="bg-slate-950 text-slate-100">All Statuses</option>
              <option value="UNVALIDATED" className="bg-slate-950 text-slate-100">Unvalidated</option>
              <option value="CONFIRMED" className="bg-slate-950 text-emerald-400">Confirmed</option>
              <option value="FALSE_POSITIVE" className="bg-slate-950 text-slate-400">False Positive</option>
            </select>
          </div>
        </div>
      </div>

      {/* Findings Table */}
      <div className="card overflow-hidden">
        {filteredFindings.length === 0 ? (
          <div className="p-12 text-center text-slate-400">
            <ShieldAlert className="w-12 h-12 mx-auto text-slate-600 mb-3" />
            <p className="text-base font-medium text-slate-300">No findings match the current criteria.</p>
            <p className="text-sm text-slate-500 mt-1">
              Run an assessment scan or adjust filters to view observations.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-900/60 text-slate-400 text-xs font-mono uppercase tracking-wider border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Risk Score</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Vulnerability Title & ID</th>
                  <th className="py-3 px-4">Source Tool</th>
                  <th className="py-3 px-4">Asset / Endpoint</th>
                  <th className="py-3 px-4">Validation</th>
                  <th className="py-3 px-4 text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-xs">
                {filteredFindings.map((f) => (
                  <tr
                    key={f.id}
                    className={clsx(
                      'hover:bg-slate-800/40 transition-colors cursor-pointer',
                      f.is_false_positive && 'opacity-60 bg-slate-950/40'
                    )}
                    onClick={() => setSelectedFinding(f)}
                  >
                    <td className="py-3 px-4 whitespace-nowrap">
                      {getRiskScorePill(f.risk_score, f.is_false_positive)}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      {getSeverityBadge(f.severity)}
                    </td>
                    <td className="py-3 px-4 max-w-md">
                      <div className="font-semibold text-slate-200 line-clamp-1">{f.title}</div>
                      <div className="flex items-center gap-2 mt-1">
                        {f.cve_id && (
                          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-rose-500/20 text-rose-300 border border-rose-500/30">
                            {f.cve_id}
                          </span>
                        )}
                        {f.cwe_id && (
                          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                            {f.cwe_id}
                          </span>
                        )}
                        <span className="text-[11px] text-slate-500 font-mono">
                          Confidence: {f.confidence || 'Medium'}
                        </span>
                      </div>
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded bg-slate-800 font-medium text-cyan-300 border border-slate-700">
                        {f.source_tool || 'Scanner'}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-300">
                      <div>{f.host}:{f.port || '—'}</div>
                      {f.url_path && <div className="text-slate-500 text-[11px] truncate max-w-xs">{f.url_path}</div>}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      {f.is_false_positive ? (
                        <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-slate-800 text-slate-400 border border-slate-700">
                          FALSE POSITIVE
                        </span>
                      ) : f.validation_status === 'CONFIRMED' ? (
                        <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                          CONFIRMED
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-amber-500/10 text-amber-300/80 border border-amber-500/20">
                          UNVALIDATED
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation()
                          setSelectedFinding(f)
                        }}
                        className="btn-secondary text-xs px-2.5 py-1 inline-flex items-center gap-1"
                      >
                        <Eye className="w-3.5 h-3.5 text-cyan-400" />
                        Details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Finding Detail Modal */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="card max-w-3xl w-full p-6 shadow-2xl flex flex-col max-h-[90vh]">
            <div className="flex items-start justify-between pb-3 border-b border-slate-800">
              <div>
                <div className="flex items-center gap-2">
                  {getSeverityBadge(selectedFinding.severity)}
                  {getRiskScorePill(selectedFinding.risk_score, selectedFinding.is_false_positive)}
                  <span className="px-2 py-0.5 rounded bg-slate-800 text-xs font-mono text-cyan-400">
                    {selectedFinding.source_tool}
                  </span>
                </div>
                <h2 className="text-lg font-bold text-slate-100 mt-2">
                  {selectedFinding.title}
                </h2>
              </div>
              <button
                onClick={() => setSelectedFinding(null)}
                className="text-slate-400 hover:text-slate-200 text-sm font-semibold p-1"
              >
                ✕
              </button>
            </div>

            <div className="mt-4 flex-1 overflow-auto space-y-4 text-sm">
              {/* Target & Port Details */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 p-3 bg-slate-900/60 rounded border border-slate-800 font-mono text-xs">
                <div>
                  <span className="text-slate-500">Asset Host:</span>
                  <div className="text-slate-200 font-semibold">{selectedFinding.host}</div>
                </div>
                <div>
                  <span className="text-slate-500">Port / Protocol:</span>
                  <div className="text-slate-200 font-semibold">{selectedFinding.port || 'N/A'}</div>
                </div>
                <div>
                  <span className="text-slate-500">CVE ID:</span>
                  <div className="text-rose-400 font-semibold">{selectedFinding.cve_id || 'None Reported'}</div>
                </div>
                <div>
                  <span className="text-slate-500">CWE ID:</span>
                  <div className="text-indigo-400 font-semibold">{selectedFinding.cwe_id || 'None Reported'}</div>
                </div>
              </div>

              {/* Mathematical Risk Score Explanation */}
              {selectedFinding.risk_explanation && (
                <div className="p-3 bg-slate-900/40 rounded border border-cyan-500/20 text-xs">
                  <div className="font-semibold text-cyan-400 mb-1 flex items-center gap-1.5">
                    <SlidersHorizontal className="w-3.5 h-3.5" />
                    Transparent Risk Score Calculation
                  </div>
                  <div className="font-mono text-slate-300 leading-relaxed">
                    {selectedFinding.risk_explanation}
                  </div>
                </div>
              )}

              {/* Description & Solution */}
              <div>
                <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">
                  Vulnerability Description & Remediation
                </h4>
                <div className="p-3 bg-slate-950 rounded border border-slate-800 text-slate-300 text-xs whitespace-pre-line leading-relaxed">
                  {selectedFinding.description || 'No description provided.'}
                </div>
              </div>

              {/* Raw Evidence Extract */}
              <div>
                <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">
                  Scanner Observed Evidence & Fingerprint
                </h4>
                <div className="p-3 bg-slate-950 rounded border border-slate-800 font-mono text-xs text-emerald-400 whitespace-pre-wrap break-all">
                  {selectedFinding.evidence || 'No direct evidence payload captured.'}
                </div>
                <div className="mt-1 text-[11px] font-mono text-slate-500 truncate">
                  Fingerprint SHA-256: {selectedFinding.fingerprint || 'N/A'}
                </div>
              </div>
            </div>

            {/* Modal Actions */}
            <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleUpdateStatus('CONFIRMED')}
                  disabled={updatingStatus}
                  className="btn-secondary text-xs px-3 py-1.5 flex items-center gap-1.5 text-emerald-400 hover:text-emerald-300"
                >
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  Mark Confirmed
                </button>
                <button
                  onClick={() => setShowStatusModal(true)}
                  disabled={updatingStatus}
                  className="btn-secondary text-xs px-3 py-1.5 flex items-center gap-1.5 text-rose-400 hover:text-rose-300"
                >
                  <XCircle className="w-3.5 h-3.5" />
                  Flag False Positive
                </button>
              </div>
              <button
                onClick={() => setSelectedFinding(null)}
                className="btn-primary text-xs px-4 py-2"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}

      {/* False Positive Note Modal */}
      {showStatusModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="card max-w-md w-full p-5 shadow-2xl border-rose-500/30">
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <XCircle className="w-4 h-4 text-rose-400" />
              Confirm False Positive Classification
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Marking as False Positive will adjust its risk score to 0.0 and update the AI attack chain model.
            </p>
            <div className="mt-3">
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Analyst Rationale / Note (Optional)
              </label>
              <textarea
                rows={3}
                placeholder="e.g. Server banner confirms Nginx, signature for Apache was incorrectly triggered."
                value={fpNote}
                onChange={(e) => setFpNote(e.target.value)}
                className="w-full text-xs bg-slate-950 text-slate-100 placeholder-slate-500 border border-slate-700/80 rounded-lg p-2.5 focus:border-cyan-500 focus:outline-none"
              />
            </div>
            <div className="mt-4 flex justify-end gap-2">
              <button
                onClick={() => setShowStatusModal(false)}
                className="btn-secondary text-xs px-3 py-1.5"
              >
                Cancel
              </button>
              <button
                onClick={() => handleUpdateStatus('FALSE_POSITIVE')}
                disabled={updatingStatus}
                className="btn-primary bg-rose-600 hover:bg-rose-500 text-xs px-3 py-1.5"
              >
                Confirm False Positive
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
