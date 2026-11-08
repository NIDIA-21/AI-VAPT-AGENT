import { useState, useEffect } from 'react'
import {
  Activity,
  Play,
  RefreshCw,
  Terminal,
  AlertCircle,
  CheckCircle2,
  Clock,
  XCircle,
  Eye,
  Shield,
  Layers,
  ChevronRight,
  Filter,
} from 'lucide-react'
import type { ScanJob, AuthorizedTarget } from '@/types'
import { scannersApi, targetsApi } from '@/services/api'
import { clsx } from 'clsx'

export default function ScanActivity() {
  const [jobs, setJobs] = useState<ScanJob[]>([])
  const [targets, setTargets] = useState<AuthorizedTarget[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Launch Scan Modal State
  const [showLaunchModal, setShowLaunchModal] = useState(false)
  const [selectedTargetId, setSelectedTargetId] = useState('')
  const [portsOverride, setPortsOverride] = useState('')
  const [launching, setLaunching] = useState(false)
  const [launchError, setLaunchError] = useState<string | null>(null)

  // Raw Output Modal State
  const [selectedJob, setSelectedJob] = useState<ScanJob | null>(null)
  const [showOutputModal, setShowOutputModal] = useState(false)

  // Filter state
  const [statusFilter, setStatusFilter] = useState<string>('all')

  const fetchData = async () => {
    try {
      setLoading(true)
      setError(null)
      const [jobsData, targetsData] = await Promise.all([
        scannersApi.listJobs(),
        targetsApi.list({ status: 'ACTIVE' }),
      ])
      setJobs(jobsData)
      setTargets(targetsData)
      if (targetsData.length > 0 && !selectedTargetId) {
        setSelectedTargetId(targetsData[0].id)
      }
    } catch (err: any) {
      setError(err?.userMessage || 'Failed to load scan activity data.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
    // Poll every 10 seconds for real-time scan job updates
    const interval = setInterval(fetchData, 10000)
    return () => clearInterval(interval)
  }, [])

  const handleLaunchScan = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedTargetId) return

    setLaunching(true)
    setLaunchError(null)

    try {
      let ports: number[] | undefined = undefined
      if (portsOverride.trim()) {
        ports = portsOverride
          .split(',')
          .map((p) => parseInt(p.trim(), 10))
          .filter((p) => !isNaN(p) && p > 0 && p <= 65535)
      }

      await scannersApi.executeNmap({
        target_id: selectedTargetId,
        ports_override: ports,
      })

      setShowLaunchModal(false)
      setPortsOverride('')
      await fetchData()
    } catch (err: any) {
      setLaunchError(err?.userMessage || 'Failed to execute scoped scan.')
    } finally {
      setLaunching(false)
    }
  }

  const getStatusBadge = (status: string) => {
    switch (status.toUpperCase()) {
      case 'COMPLETED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <CheckCircle2 className="w-3.5 h-3.5" />
            COMPLETED
          </span>
        )
      case 'RUNNING':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 animate-pulse">
            <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            RUNNING
          </span>
        )
      case 'QUEUED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <Clock className="w-3.5 h-3.5" />
            QUEUED
          </span>
        )
      case 'FAILED':
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <XCircle className="w-3.5 h-3.5" />
            FAILED
          </span>
        )
    }
  }

  const filteredJobs = jobs.filter((j) => {
    if (statusFilter === 'all') return true
    return j.status.toUpperCase() === statusFilter.toUpperCase()
  })

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
            <Activity className="w-6 h-6 text-cyan-400" />
            Scan Activity & Live Execution Monitor
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Real-time tracking of Nmap, OWASP ZAP, and Nikto security jobs with strict scope enforcement.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={fetchData}
            disabled={loading}
            className="btn-secondary flex items-center gap-2 text-sm px-3 py-2"
          >
            <RefreshCw className={clsx('w-4 h-4', loading && 'animate-spin')} />
            Refresh
          </button>
          <button
            onClick={() => setShowLaunchModal(true)}
            className="btn-primary flex items-center gap-2 text-sm px-4 py-2 bg-cyan-600 hover:bg-cyan-500"
          >
            <Play className="w-4 h-4" />
            Launch Scoped Scan
          </button>
        </div>
      </div>

      {/* Error alert */}
      {error && (
        <div className="bg-rose-500/10 border border-rose-500/30 rounded-lg p-4 flex items-center gap-3 text-rose-300 text-sm">
          <AlertCircle className="w-5 h-5 flex-shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Metrics Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="card p-4 flex items-center justify-between">
          <div>
            <p className="text-xs font-medium text-slate-400">Total Scan Jobs</p>
            <p className="text-2xl font-bold text-slate-100 mt-1">{jobs.length}</p>
          </div>
          <Layers className="w-8 h-8 text-cyan-500/40" />
        </div>
        <div className="card p-4 flex items-center justify-between">
          <div>
            <p className="text-xs font-medium text-slate-400">Running / Active</p>
            <p className="text-2xl font-bold text-cyan-400 mt-1">
              {jobs.filter((j) => j.status === 'RUNNING').length}
            </p>
          </div>
          <Activity className="w-8 h-8 text-cyan-500/40" />
        </div>
        <div className="card p-4 flex items-center justify-between">
          <div>
            <p className="text-xs font-medium text-slate-400">Completed Successfully</p>
            <p className="text-2xl font-bold text-emerald-400 mt-1">
              {jobs.filter((j) => j.status === 'COMPLETED').length}
            </p>
          </div>
          <CheckCircle2 className="w-8 h-8 text-emerald-500/40" />
        </div>
        <div className="card p-4 flex items-center justify-between">
          <div>
            <p className="text-xs font-medium text-slate-400">Failed / Scope Denied</p>
            <p className="text-2xl font-bold text-rose-400 mt-1">
              {jobs.filter((j) => j.status === 'FAILED').length}
            </p>
          </div>
          <XCircle className="w-8 h-8 text-rose-500/40" />
        </div>
      </div>

      {/* Jobs Table Card */}
      <div className="card overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-slate-400" />
            <span className="text-sm font-semibold text-slate-200">Execution History</span>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <button
              onClick={() => setStatusFilter('all')}
              className={clsx(
                'px-2.5 py-1 rounded transition-colors',
                statusFilter === 'all'
                  ? 'bg-slate-700 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              )}
            >
              All ({jobs.length})
            </button>
            <button
              onClick={() => setStatusFilter('RUNNING')}
              className={clsx(
                'px-2.5 py-1 rounded transition-colors',
                statusFilter === 'RUNNING'
                  ? 'bg-cyan-500/20 text-cyan-300'
                  : 'text-slate-400 hover:text-slate-200'
              )}
            >
              Running
            </button>
            <button
              onClick={() => setStatusFilter('COMPLETED')}
              className={clsx(
                'px-2.5 py-1 rounded transition-colors',
                statusFilter === 'COMPLETED'
                  ? 'bg-emerald-500/20 text-emerald-300'
                  : 'text-slate-400 hover:text-slate-200'
              )}
            >
              Completed
            </button>
            <button
              onClick={() => setStatusFilter('FAILED')}
              className={clsx(
                'px-2.5 py-1 rounded transition-colors',
                statusFilter === 'FAILED'
                  ? 'bg-rose-500/20 text-rose-300'
                  : 'text-slate-400 hover:text-slate-200'
              )}
            >
              Failed
            </button>
          </div>
        </div>

        {filteredJobs.length === 0 ? (
          <div className="p-12 text-center text-slate-400">
            <Terminal className="w-12 h-12 mx-auto text-slate-600 mb-3" />
            <p className="text-base font-medium text-slate-300">No scan jobs match filter.</p>
            <p className="text-sm text-slate-500 mt-1">
              Launch a live Nmap scan or import a scan report from the Integrations tab.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-900/60 text-slate-400 text-xs font-mono uppercase tracking-wider border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Scanner Tool</th>
                  <th className="py-3 px-4">Target Host</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Findings</th>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 font-mono text-xs">
                {filteredJobs.map((job) => (
                  <tr key={job.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-4 font-sans font-medium text-slate-200 flex items-center gap-2">
                      <Shield className="w-4 h-4 text-cyan-400" />
                      {job.scanner}
                    </td>
                    <td className="py-3 px-4 text-cyan-300">{job.target_host || '—'}</td>
                    <td className="py-3 px-4">{getStatusBadge(job.status)}</td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-semibold">
                        {job.findings_count || 0} findings
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-400">
                      {new Date(job.created_at).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => {
                          setSelectedJob(job)
                          setShowOutputModal(true)
                        }}
                        className="btn-secondary text-xs px-2.5 py-1 inline-flex items-center gap-1.5"
                      >
                        <Eye className="w-3.5 h-3.5 text-cyan-400" />
                        Inspect Output
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Launch Scoped Scan Modal */}
      {showLaunchModal && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="card max-w-lg w-full p-6 shadow-2xl border-cyan-500/30">
            <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <Play className="w-5 h-5 text-cyan-400" />
              Launch Scoped Nmap Scan
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Subprocess execution strictly validates target authorization before launching.
            </p>

            {launchError && (
              <div className="mt-4 p-3 rounded bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
                <AlertCircle className="w-4 h-4 flex-shrink-0" />
                <span>{launchError}</span>
              </div>
            )}

            <form onSubmit={handleLaunchScan} className="mt-4 space-y-4 text-sm">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Target Host (Must be in ACTIVE Scope)
                </label>
                <select
                  value={selectedTargetId}
                  onChange={(e) => setSelectedTargetId(e.target.value)}
                  className="input-field w-full text-sm"
                  required
                >
                  {targets.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name} ({t.host}) — Ref: {t.auth_reference || 'N/A'}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Permitted Port Restriction Override (Optional, e.g. 80, 443, 8080)
                </label>
                <input
                  type="text"
                  placeholder="Leave blank to use target registered ports"
                  value={portsOverride}
                  onChange={(e) => setPortsOverride(e.target.value)}
                  className="input-field w-full text-sm"
                />
                <p className="text-[11px] text-slate-500 mt-1">
                  Excluded ports on the registered target will always be blocked regardless of overrides.
                </p>
              </div>

              <div className="pt-2 flex items-center justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setShowLaunchModal(false)}
                  className="btn-secondary text-xs px-4 py-2"
                  disabled={launching}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={launching || targets.length === 0}
                  className="btn-primary text-xs px-4 py-2 flex items-center gap-2 bg-cyan-600 hover:bg-cyan-500"
                >
                  {launching ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      Validating & Executing...
                    </>
                  ) : (
                    <>
                      <Shield className="w-3.5 h-3.5" />
                      Execute Safe Scan
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Inspect Raw Output Modal */}
      {showOutputModal && selectedJob && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="card max-w-4xl w-full p-6 shadow-2xl flex flex-col max-h-[85vh]">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div>
                <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                  <Terminal className="w-5 h-5 text-cyan-400" />
                  Scan Output Trace — {selectedJob.scanner} ({selectedJob.target_host})
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Job ID: {selectedJob.id} | Status: {selectedJob.status}
                </p>
              </div>
              <button
                onClick={() => setShowOutputModal(false)}
                className="text-slate-400 hover:text-slate-200 text-sm font-semibold p-1"
              >
                ✕
              </button>
            </div>

            {selectedJob.error_message && (
              <div className="mt-4 p-3 bg-rose-500/10 border border-rose-500/30 rounded text-rose-300 text-xs">
                <strong>Execution Error:</strong> {selectedJob.error_message}
              </div>
            )}

            <div className="mt-4 flex-1 overflow-auto bg-slate-950 border border-slate-800 rounded p-4 font-mono text-xs text-slate-300 whitespace-pre">
              {selectedJob.raw_output || 'No raw output generated.'}
            </div>

            <div className="mt-4 pt-2 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setShowOutputModal(false)}
                className="btn-secondary text-xs px-4 py-2"
              >
                Close Output
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
