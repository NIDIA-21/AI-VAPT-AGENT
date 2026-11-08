import { useState, useEffect } from 'react'
import {
  FileText,
  Download,
  Eye,
  RefreshCw,
  Shield,
  Layers,
  AlertTriangle,
  CheckCircle2,
  Calendar,
  Lock,
  Clock,
  ExternalLink,
  ChevronRight,
  Printer,
  Sparkles,
} from 'lucide-react'
import type { ReportSummary, ReportableAssessment } from '@/types'
import { reportsApi } from '@/services/api'
import { clsx } from 'clsx'

export default function Reports() {
  const [assessments, setAssessments] = useState<ReportableAssessment[]>([])
  const [selectedId, setSelectedId] = useState<string>('')
  const [summary, setSummary] = useState<ReportSummary | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadingSummary, setLoadingSummary] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [showPreviewModal, setShowPreviewModal] = useState(false)

  const loadAssessments = async () => {
    try {
      setLoading(true)
      setError(null)
      const data = await reportsApi.listAssessments()
      setAssessments(data)
      if (data.length > 0) {
        setSelectedId(data[0].id)
        loadSummary(data[0].id)
      }
    } catch (err: any) {
      setError(err?.userMessage || 'Failed to load reportable assessments.')
    } finally {
      setLoading(false)
    }
  }

  const loadSummary = async (assessmentId: string) => {
    try {
      setLoadingSummary(true)
      const data = await reportsApi.getSummary(assessmentId)
      setSummary(data)
    } catch (err: any) {
      setError(err?.userMessage || 'Failed to load assessment report summary.')
    } finally {
      setLoadingSummary(false)
    }
  }

  useEffect(() => {
    loadAssessments()
  }, [])

  const handleSelectAssessment = (id: string) => {
    setSelectedId(id)
    loadSummary(id)
  }

  const downloadPdf = () => {
    if (!selectedId) return
    const url = reportsApi.getPdfUrl(selectedId)
    window.open(url, '_blank')
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
            <FileText className="w-6 h-6 text-cyan-400" />
            Audit-Grade VAPT Reports &amp; Export Center
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Generate and export professional PDF vulnerability reports using actual database findings, scanner evidence, and human approvals.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <select
            value={selectedId}
            onChange={(e) => handleSelectAssessment(e.target.value)}
            className="input-field text-xs py-2 max-w-xs"
            disabled={loading || loadingSummary}
          >
            {assessments.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name} ({a.target_host})
              </option>
            ))}
          </select>

          <button
            onClick={() => loadSummary(selectedId)}
            disabled={loadingSummary}
            className="btn-secondary text-xs px-3 py-2 flex items-center gap-1.5"
          >
            <RefreshCw className={clsx('w-3.5 h-3.5', loadingSummary && 'animate-spin')} />
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 bg-rose-500/10 border border-rose-500/30 rounded text-rose-300 text-xs">
          {error}
        </div>
      )}

      {loadingSummary ? (
        <div className="p-16 text-center text-slate-400 flex flex-col items-center justify-center gap-2">
          <RefreshCw className="w-8 h-8 animate-spin text-cyan-400" />
          <p className="text-sm">Synthesizing audit report records from database...</p>
        </div>
      ) : summary ? (
        <div className="space-y-6">
          {/* Main Action Bar */}
          <div className="card p-6 border-cyan-500/30 bg-gradient-to-r from-slate-900 via-slate-900 to-navy-900 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 shadow-xl">
            <div className="space-y-1">
              <span className="text-xs uppercase font-mono tracking-wider text-cyan-400 font-semibold">
                Report Ready for Export
              </span>
              <h2 className="text-lg font-bold text-slate-100">{summary.assessment_name}</h2>
              <div className="flex items-center gap-4 text-xs text-slate-400 font-mono pt-1">
                <span>Target: <strong className="text-slate-200">{summary.target_host}</strong></span>
                <span>Auth Ref: <strong className="text-slate-200">{summary.auth_reference || 'N/A'}</strong></span>
                <span>Generated: <strong className="text-slate-200">{new Date(summary.generated_at).toLocaleString()}</strong></span>
              </div>
            </div>

            <div className="flex items-center gap-2 self-stretch sm:self-auto">
              <button
                onClick={() => setShowPreviewModal(true)}
                className="btn-secondary flex-1 sm:flex-initial text-xs px-4 py-2 flex items-center justify-center gap-2"
              >
                <Eye className="w-4 h-4 text-cyan-400" />
                View Report Summary
              </button>
              <button
                onClick={downloadPdf}
                className="btn-primary flex-1 sm:flex-initial text-xs px-5 py-2 flex items-center justify-center gap-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 shadow-glow-cyan"
              >
                <Download className="w-4 h-4" />
                Download Official PDF
              </button>
            </div>
          </div>

          {/* Severity Breakdown Cards */}
          <div>
            <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider font-mono mb-2">
              Vulnerability Severity Distribution (Actual Findings)
            </h3>
            <div className="grid grid-cols-2 sm:grid-cols-6 gap-3">
              <div className="card p-3 border-l-4 border-l-slate-400">
                <span className="text-[11px] text-slate-400">Total Findings</span>
                <p className="text-2xl font-bold text-slate-100 mt-0.5">{summary.total_findings}</p>
              </div>
              <div className="card p-3 border-l-4 border-l-rose-500">
                <span className="text-[11px] text-slate-400">Critical</span>
                <p className="text-2xl font-bold text-rose-400 mt-0.5">{summary.critical_findings}</p>
              </div>
              <div className="card p-3 border-l-4 border-l-amber-500">
                <span className="text-[11px] text-slate-400">High</span>
                <p className="text-2xl font-bold text-amber-400 mt-0.5">{summary.high_findings}</p>
              </div>
              <div className="card p-3 border-l-4 border-l-yellow-500">
                <span className="text-[11px] text-slate-400">Medium</span>
                <p className="text-2xl font-bold text-yellow-300 mt-0.5">{summary.medium_findings}</p>
              </div>
              <div className="card p-3 border-l-4 border-l-blue-500">
                <span className="text-[11px] text-slate-400">Low / Info</span>
                <p className="text-2xl font-bold text-blue-400 mt-0.5">
                  {summary.low_findings + summary.informational_findings}
                </p>
              </div>
              <div className="card p-3 border-l-4 border-l-slate-600">
                <span className="text-[11px] text-slate-400">False Positives</span>
                <p className="text-2xl font-bold text-slate-400 mt-0.5">{summary.false_positives_count}</p>
              </div>
            </div>
          </div>

          {/* Scanner Execution & Approvals Row */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Tool Execution Matrix */}
            <div className="card p-5 space-y-3">
              <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                Cybersecurity Scanners Execution Audit
              </h3>
              {summary.scanner_jobs.length === 0 ? (
                <p className="text-xs text-slate-500 italic">No scanner jobs recorded for this assessment.</p>
              ) : (
                <div className="divide-y divide-slate-800 text-xs">
                  {summary.scanner_jobs.map((job) => (
                    <div key={job.id} className="py-2.5 flex items-center justify-between">
                      <div>
                        <span className="font-semibold text-slate-200">{job.scanner}</span>
                        <div className="text-[11px] text-slate-500 font-mono">
                          Target: {job.target_host} | Started: {job.started_at ? new Date(job.started_at).toLocaleTimeString() : 'N/A'}
                        </div>
                      </div>
                      <span
                        className={clsx(
                          'px-2 py-0.5 rounded text-[10px] font-bold font-mono',
                          job.status === 'COMPLETED'
                            ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                            : job.status === 'FAILED'
                            ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                            : 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
                        )}
                      >
                        {job.status}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Approvals & Constraints */}
            <div className="card p-5 space-y-3">
              <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono flex items-center gap-2">
                <Lock className="w-4 h-4 text-emerald-400" />
                Human Approvals &amp; Scope Constraints
              </h3>

              <div className="grid grid-cols-3 gap-2 text-center text-xs">
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block text-[10px]">Pending Gate</span>
                  <span className="font-bold text-amber-400 text-base">{summary.approvals_summary['PENDING'] || 0}</span>
                </div>
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block text-[10px]">Approved Actions</span>
                  <span className="font-bold text-emerald-400 text-base">{summary.approvals_summary['APPROVED'] || 0}</span>
                </div>
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block text-[10px]">Rejected Actions</span>
                  <span className="font-bold text-rose-400 text-base">{summary.approvals_summary['REJECTED'] || 0}</span>
                </div>
              </div>

              <div className="p-3 rounded bg-slate-950 border border-slate-800 text-[11px] text-slate-400 font-mono space-y-1">
                <span className="font-semibold text-slate-300 block">Assessment Limitations:</span>
                <p className="leading-relaxed">{summary.assessment_limitations}</p>
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="card p-12 text-center text-slate-500 text-sm">
          No assessment selected.
        </div>
      )}

      {/* Inline Preview Modal */}
      {showPreviewModal && summary && (
        <div className="fixed inset-0 z-50 bg-black/85 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="card max-w-3xl w-full p-6 shadow-2xl flex flex-col max-h-[85vh]">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <FileText className="w-5 h-5 text-cyan-400" />
                <h3 className="text-base font-bold text-slate-100">
                  Report Executive Summary Preview — {summary.assessment_name}
                </h3>
              </div>
              <button
                onClick={() => setShowPreviewModal(false)}
                className="text-slate-400 hover:text-slate-200 text-sm p-1 font-semibold"
              >
                ✕
              </button>
            </div>

            <div className="mt-4 flex-1 overflow-auto space-y-4 text-xs text-slate-300 font-sans leading-relaxed">
              <div className="p-4 rounded bg-slate-950 border border-slate-800 space-y-2">
                <span className="text-cyan-400 font-bold block uppercase tracking-wider text-[11px]">
                  Executive Overview
                </span>
                <p>
                  Security assessment performed for target <strong>{summary.target_host}</strong> under authorization reference <strong>{summary.auth_reference || 'N/A'}</strong>.
                  A total of <strong>{summary.total_findings} findings</strong> were recorded across authorized ports and paths.
                  {summary.total_findings === 0 && ' No vulnerability findings were recorded during this assessment.'}
                </p>
              </div>

              <div className="p-4 rounded bg-slate-950 border border-slate-800 space-y-2">
                <span className="text-cyan-400 font-bold block uppercase tracking-wider text-[11px]">
                  Methodology &amp; Standards
                </span>
                <p>
                  Testing conducted in compliance with NIST SP 800-115 and OWASP Web Security Testing Guide (WSTG).
                  Zero autonomous exploitation policy enforced with human approval gates.
                </p>
              </div>

              <div className="p-4 rounded bg-slate-950 border border-slate-800 space-y-2">
                <span className="text-cyan-400 font-bold block uppercase tracking-wider text-[11px]">
                  Zero Fabricated Findings Guarantee
                </span>
                <p>
                  All CVE, CWE, and CVSS indicators in the official report reflect verified scanner evidence.
                  Absence of recorded findings does not guarantee the target is vulnerability-free.
                </p>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between">
              <button
                onClick={() => setShowPreviewModal(false)}
                className="btn-secondary text-xs px-4 py-2"
              >
                Close Preview
              </button>
              <button
                onClick={downloadPdf}
                className="btn-primary text-xs px-5 py-2 flex items-center gap-2 bg-cyan-600 hover:bg-cyan-500"
              >
                <Download className="w-4 h-4" />
                Download Complete PDF
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
