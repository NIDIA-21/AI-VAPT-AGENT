import { useState, useEffect } from 'react'
import {
  ShieldCheck,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  RefreshCw,
  Eye,
  FileCheck,
  Plus,
  ShieldAlert,
  UserCheck,
  Filter,
  Lock,
} from 'lucide-react'
import type { ApprovalRequest, AuthorizedTarget, Assessment } from '@/types'
import { approvalsApi, targetsApi, assessmentsApi } from '@/services/api'
import { clsx } from 'clsx'

export default function Approvals() {
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([])
  const [targets, setTargets] = useState<AuthorizedTarget[]>([])
  const [assessments, setAssessments] = useState<Assessment[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Status Filter
  const [statusFilter, setStatusFilter] = useState<string>('all')

  // Decision Modals
  const [activeReq, setActiveReq] = useState<ApprovalRequest | null>(null)
  const [showApproveModal, setShowApproveModal] = useState(false)
  const [showRejectModal, setShowRejectModal] = useState(false)
  const [analystId, setAnalystId] = useState('senior_security_analyst')
  const [decisionNotes, setDecisionNotes] = useState('')
  const [rejectionReason, setRejectionReason] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)

  // Create Request Modal
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [newTargetId, setNewTargetId] = useState('')
  const [newAssessmentId, setNewAssessmentId] = useState('')
  const [newAction, setNewAction] = useState('Active Vulnerability Payload Probe')
  const [newPurpose, setNewPurpose] = useState('Verify DAST finding with non-destructive authenticated test payload')
  const [newRisk, setNewRisk] = useState('Potential brief latency increase on web daemon; non-destructive')
  const [newEvidence, setNewEvidence] = useState('Nmap port 80 open, Nikto flagged outdated tokens')
  const [creating, setCreating] = useState(false)

  const fetchData = async () => {
    try {
      setLoading(true)
      setError(null)
      const [appData, targetData, assessData] = await Promise.all([
        approvalsApi.list(),
        targetsApi.list({ status: 'ACTIVE' }),
        assessmentsApi.list(),
      ])
      setApprovals(appData)
      setTargets(targetData)
      setAssessments(assessData)
      if (targetData.length > 0 && !newTargetId) setNewTargetId(targetData[0].id)
      if (assessData.length > 0 && !newAssessmentId) setNewAssessmentId(assessData[0].id)
    } catch (err: any) {
      setError(err?.userMessage || 'Failed to fetch approval requests.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
  }, [])

  const handleApprove = async () => {
    if (!activeReq) return
    setSubmitting(true)
    setActionError(null)
    try {
      await approvalsApi.approve(activeReq.id, {
        analyst_id: analystId,
        notes: decisionNotes,
      })
      setShowApproveModal(false)
      setActiveReq(null)
      setDecisionNotes('')
      await fetchData()
    } catch (err: any) {
      setActionError(err?.userMessage || 'Failed to approve request.')
    } finally {
      setSubmitting(false)
    }
  }

  const handleReject = async () => {
    if (!activeReq) return
    if (!rejectionReason.trim()) {
      setActionError('Rejection reason is mandatory.')
      return
    }
    setSubmitting(true)
    setActionError(null)
    try {
      await approvalsApi.reject(activeReq.id, {
        analyst_id: analystId,
        rejection_reason: rejectionReason,
        notes: decisionNotes,
      })
      setShowRejectModal(false)
      setActiveReq(null)
      setRejectionReason('')
      setDecisionNotes('')
      await fetchData()
    } catch (err: any) {
      setActionError(err?.userMessage || 'Failed to reject request.')
    } finally {
      setSubmitting(false)
    }
  }

  const handleCreateRequest = async (e: React.FormEvent) => {
    e.preventDefault()
    const selectedTarget = targets.find((t) => t.id === newTargetId)
    if (!selectedTarget) return

    setCreating(true)
    try {
      await approvalsApi.create({
        assessment_id: newAssessmentId,
        target_id: newTargetId,
        target_host: selectedTarget.host,
        requested_action: newAction,
        validation_purpose: newPurpose,
        risk_information: newRisk,
        supporting_evidence: newEvidence,
        requested_by: 'ai_agent_planner',
      })
      setShowCreateModal(false)
      await fetchData()
    } catch (err: any) {
      alert(err?.userMessage || 'Failed to create approval request.')
    } finally {
      setCreating(false)
    }
  }

  const getStatusBadge = (status: string) => {
    switch (status.toUpperCase()) {
      case 'APPROVED':
        return (
          <span className="inline-flex items-center gap-1 text-xs font-semibold px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <CheckCircle2 className="w-3.5 h-3.5" />
            APPROVED
          </span>
        )
      case 'REJECTED':
        return (
          <span className="inline-flex items-center gap-1 text-xs font-semibold px-2.5 py-0.5 rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/30">
            <XCircle className="w-3.5 h-3.5" />
            REJECTED
          </span>
        )
      case 'PENDING':
      default:
        return (
          <span className="inline-flex items-center gap-1 text-xs font-semibold px-2.5 py-0.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/30 animate-pulse">
            <Clock className="w-3.5 h-3.5" />
            PENDING REVIEW
          </span>
        )
    }
  }

  const filteredApprovals = approvals.filter((a) => {
    if (statusFilter === 'all') return true
    return a.status.toUpperCase() === statusFilter.toUpperCase()
  })

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
            <ShieldCheck className="w-6 h-6 text-cyan-400" />
            Human-in-the-Loop Approval Center
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Mandatory human authorization gate for active validation actions, deep probes, and offensive tools.
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
            onClick={() => setShowCreateModal(true)}
            className="btn-primary flex items-center gap-2 text-sm px-3.5 py-2 bg-cyan-600 hover:bg-cyan-500"
          >
            <Plus className="w-4 h-4" />
            Request Action Review
          </button>
        </div>
      </div>

      {/* Security Policy Alert Banner */}
      <div className="p-4 rounded-xl bg-slate-900 border border-cyan-500/30 text-xs text-slate-300 space-y-1">
        <div className="flex items-center gap-2 text-cyan-400 font-bold uppercase tracking-wider">
          <Lock className="w-4 h-4" />
          Strict Governance Policy & Defensive Boundary Rules
        </div>
        <p className="text-slate-400 leading-relaxed">
          • Approvals are <strong>explicit, non-transferable</strong>, and locked to the registered target host and permitted ports.<br/>
          • An analyst approval <strong>CANNOT override</strong> target revocation, expiration, or excluded port boundaries.<br/>
          • <strong>Zero Autonomous Exploitation:</strong> Exploitation frameworks (Metasploit) and intrusive payloads will never execute automatically without logged analyst authorization.
        </p>
      </div>

      {error && (
        <div className="p-4 bg-rose-500/10 border border-rose-500/30 rounded text-rose-300 text-sm">
          {error}
        </div>
      )}

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="card p-4">
          <p className="text-xs text-slate-400">Total Action Requests</p>
          <p className="text-2xl font-bold text-slate-100 mt-1">{approvals.length}</p>
        </div>
        <div className="card p-4 border-l-4 border-l-amber-500">
          <p className="text-xs text-slate-400">Pending Review</p>
          <p className="text-2xl font-bold text-amber-400 mt-1">
            {approvals.filter((a) => a.status === 'PENDING').length}
          </p>
        </div>
        <div className="card p-4 border-l-4 border-l-emerald-500">
          <p className="text-xs text-slate-400">Approved by Analyst</p>
          <p className="text-2xl font-bold text-emerald-400 mt-1">
            {approvals.filter((a) => a.status === 'APPROVED').length}
          </p>
        </div>
        <div className="card p-4 border-l-4 border-l-rose-500">
          <p className="text-xs text-slate-400">Rejected / Blocked</p>
          <p className="text-2xl font-bold text-rose-400 mt-1">
            {approvals.filter((a) => a.status === 'REJECTED').length}
          </p>
        </div>
      </div>

      {/* Table & Filter Card */}
      <div className="card overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-slate-400" />
            <span className="text-sm font-semibold text-slate-200">Validation Action Requests</span>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <button
              onClick={() => setStatusFilter('all')}
              className={clsx(
                'px-2.5 py-1 rounded transition-colors',
                statusFilter === 'all' ? 'bg-slate-700 text-white' : 'text-slate-400 hover:text-slate-200'
              )}
            >
              All ({approvals.length})
            </button>
            <button
              onClick={() => setStatusFilter('PENDING')}
              className={clsx(
                'px-2.5 py-1 rounded transition-colors',
                statusFilter === 'PENDING' ? 'bg-amber-500/20 text-amber-300' : 'text-slate-400 hover:text-slate-200'
              )}
            >
              Pending
            </button>
            <button
              onClick={() => setStatusFilter('APPROVED')}
              className={clsx(
                'px-2.5 py-1 rounded transition-colors',
                statusFilter === 'APPROVED' ? 'bg-emerald-500/20 text-emerald-300' : 'text-slate-400 hover:text-slate-200'
              )}
            >
              Approved
            </button>
            <button
              onClick={() => setStatusFilter('REJECTED')}
              className={clsx(
                'px-2.5 py-1 rounded transition-colors',
                statusFilter === 'REJECTED' ? 'bg-rose-500/20 text-rose-300' : 'text-slate-400 hover:text-slate-200'
              )}
            >
              Rejected
            </button>
          </div>
        </div>

        {filteredApprovals.length === 0 ? (
          <div className="p-12 text-center text-slate-500 text-sm">
            <UserCheck className="w-12 h-12 mx-auto text-slate-600 mb-2" />
            <p>No action approval requests match filter.</p>
          </div>
        ) : (
          <div className="divide-y divide-slate-800 text-xs">
            {filteredApprovals.map((req) => (
              <div key={req.id} className="p-4 hover:bg-slate-800/30 transition-colors space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-3">
                    {getStatusBadge(req.status)}
                    <span className="font-bold text-slate-200 text-sm">{req.requested_action}</span>
                  </div>
                  <span className="text-slate-500 font-mono text-[11px]">
                    ID: {req.id.slice(0, 8)}... | Requested: {new Date(req.created_at).toLocaleString()}
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 p-3 rounded bg-slate-950 border border-slate-800/80">
                  <div>
                    <span className="text-slate-500 block text-[11px] font-mono">Target Asset:</span>
                    <span className="font-semibold text-cyan-300">{req.target_host}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[11px] font-mono">Validation Purpose:</span>
                    <span className="text-slate-300">{req.validation_purpose}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[11px] font-mono">Risk Information:</span>
                    <span className="text-rose-300/90">{req.risk_information}</span>
                  </div>
                </div>

                {req.supporting_evidence && (
                  <div className="text-[11px] text-slate-400 font-mono bg-slate-900/50 p-2 rounded border border-slate-800">
                    <span className="text-slate-500 font-semibold">Supporting Evidence: </span>
                    {req.supporting_evidence}
                  </div>
                )}

                {/* Decision Audit Trail if already decided */}
                {req.status !== 'PENDING' && (
                  <div className="p-2.5 rounded bg-slate-900 border border-slate-800 text-[11px] flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <span className="text-slate-400 font-semibold">Reviewed By: </span>
                      <span className="text-slate-200">{req.reviewed_by || 'Security Analyst'}</span>
                      <span className="text-slate-500 ml-2">
                        at {req.decision_timestamp ? new Date(req.decision_timestamp).toLocaleString() : 'N/A'}
                      </span>
                    </div>
                    {req.rejection_reason && (
                      <div className="text-rose-300">
                        <strong>Rejection Reason:</strong> {req.rejection_reason}
                      </div>
                    )}
                    {req.decision_notes && (
                      <div className="text-slate-400">
                        <strong>Notes:</strong> {req.decision_notes}
                      </div>
                    )}
                  </div>
                )}

                {/* Action Buttons for Pending Requests */}
                {req.status === 'PENDING' && (
                  <div className="flex items-center justify-end gap-2 pt-1">
                    <button
                      onClick={() => {
                        setActiveReq(req)
                        setShowRejectModal(true)
                      }}
                      className="btn-secondary text-xs px-3 py-1.5 flex items-center gap-1.5 text-rose-400 hover:text-rose-300 hover:border-rose-500/40"
                    >
                      <XCircle className="w-3.5 h-3.5" />
                      Reject Action
                    </button>
                    <button
                      onClick={() => {
                        setActiveReq(req)
                        setShowApproveModal(true)
                      }}
                      className="btn-primary text-xs px-3.5 py-1.5 flex items-center gap-1.5 bg-emerald-600 hover:bg-emerald-500 shadow-glow-cyan"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      Approve & Authorize
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Approve Confirmation Modal */}
      {showApproveModal && activeReq && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="card max-w-md w-full p-6 shadow-2xl border-emerald-500/30">
            <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              Authorize Action Execution
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Approving will authorize <strong>{activeReq.requested_action}</strong> on <strong>{activeReq.target_host}</strong>.
              Scope boundaries will be verified prior to execution.
            </p>

            {actionError && (
              <div className="mt-3 p-2.5 rounded bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs">
                {actionError}
              </div>
            )}

            <div className="mt-4 space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">Analyst Identity</label>
                <input
                  type="text"
                  value={analystId}
                  onChange={(e) => setAnalystId(e.target.value)}
                  className="input-field w-full text-xs"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Approval Notes (Optional)</label>
                <textarea
                  rows={2}
                  placeholder="e.g. Verified target test window with DevOps team."
                  value={decisionNotes}
                  onChange={(e) => setDecisionNotes(e.target.value)}
                  className="input-field w-full text-xs"
                />
              </div>
            </div>

            <div className="mt-5 flex justify-end gap-2">
              <button
                onClick={() => {
                  setShowApproveModal(false)
                  setActionError(null)
                }}
                className="btn-secondary text-xs px-3 py-1.5"
                disabled={submitting}
              >
                Cancel
              </button>
              <button
                onClick={handleApprove}
                disabled={submitting}
                className="btn-primary text-xs px-4 py-1.5 bg-emerald-600 hover:bg-emerald-500"
              >
                {submitting ? 'Verifying Scope & Authorizing...' : 'Confirm Approval'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Reject Confirmation Modal */}
      {showRejectModal && activeReq && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="card max-w-md w-full p-6 shadow-2xl border-rose-500/30">
            <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <XCircle className="w-5 h-5 text-rose-400" />
              Reject Action Execution
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Rejecting will prevent the execution of <strong>{activeReq.requested_action}</strong> on <strong>{activeReq.target_host}</strong>.
            </p>

            {actionError && (
              <div className="mt-3 p-2.5 rounded bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs">
                {actionError}
              </div>
            )}

            <div className="mt-4 space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  Mandatory Rejection Reason *
                </label>
                <textarea
                  rows={3}
                  placeholder="e.g. Risk of daemon termination too high during peak production hours; reschedule."
                  value={rejectionReason}
                  onChange={(e) => setRejectionReason(e.target.value)}
                  className="input-field w-full text-xs"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Analyst Identity</label>
                <input
                  type="text"
                  value={analystId}
                  onChange={(e) => setAnalystId(e.target.value)}
                  className="input-field w-full text-xs"
                  required
                />
              </div>
            </div>

            <div className="mt-5 flex justify-end gap-2">
              <button
                onClick={() => {
                  setShowRejectModal(false)
                  setActionError(null)
                }}
                className="btn-secondary text-xs px-3 py-1.5"
                disabled={submitting}
              >
                Cancel
              </button>
              <button
                onClick={handleReject}
                disabled={submitting || !rejectionReason.trim()}
                className="btn-primary text-xs px-4 py-1.5 bg-rose-600 hover:bg-rose-500"
              >
                {submitting ? 'Recording Rejection...' : 'Confirm Rejection'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Create Request Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="card max-w-lg w-full p-6 shadow-2xl border-cyan-500/30">
            <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <Plus className="w-5 h-5 text-cyan-400" />
              Submit Validation Action for Review
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Submit an intrusive validation or elevated scanner test to the human authorization queue.
            </p>

            <form onSubmit={handleCreateRequest} className="mt-4 space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">Target Host</label>
                <select
                  value={newTargetId}
                  onChange={(e) => setNewTargetId(e.target.value)}
                  className="input-field w-full text-xs"
                  required
                >
                  {targets.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name} ({t.host})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Assessment Engagement</label>
                <select
                  value={newAssessmentId}
                  onChange={(e) => setNewAssessmentId(e.target.value)}
                  className="input-field w-full text-xs"
                  required
                >
                  {assessments.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.name} ({a.status})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Requested Action</label>
                <input
                  type="text"
                  value={newAction}
                  onChange={(e) => setNewAction(e.target.value)}
                  className="input-field w-full text-xs"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Validation Purpose</label>
                <textarea
                  rows={2}
                  value={newPurpose}
                  onChange={(e) => setNewPurpose(e.target.value)}
                  className="input-field w-full text-xs"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Risk Assessment</label>
                <input
                  type="text"
                  value={newRisk}
                  onChange={(e) => setNewRisk(e.target.value)}
                  className="input-field w-full text-xs"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Supporting Evidence</label>
                <input
                  type="text"
                  value={newEvidence}
                  onChange={(e) => setNewEvidence(e.target.value)}
                  className="input-field w-full text-xs"
                />
              </div>

              <div className="pt-2 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="btn-secondary text-xs px-3 py-1.5"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="btn-primary text-xs px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500"
                >
                  {creating ? 'Submitting...' : 'Submit for Review'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
