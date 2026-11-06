import { useState, useEffect } from 'react'
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Clock,
  Plus,
  Search,
  CheckCircle2,
  XCircle,
  Ban,
  ExternalLink,
  RefreshCw,
  Terminal,
  Info,
  ChevronDown,
  Trash2,
  Sliders,
} from 'lucide-react'
import { clsx } from 'clsx'
import { targetsApi, scopeApi } from '@/services/api'
import type {
  AuthorizedTarget,
  TargetOverviewStats,
  AuthorizedTargetCreate,
  ScopeValidationResponse,
  ScopeAuditItem,
} from '@/types'

export default function TargetManagement() {
  // State
  const [stats, setStats] = useState<TargetOverviewStats>({
    total_targets: 0,
    active_targets: 0,
    expired_targets: 0,
    revoked_targets: 0,
    pending_targets: 0,
  })
  const [targets, setTargets] = useState<AuthorizedTarget[]>([])
  const [loading, setLoading] = useState(true)
  const [filterStatus, setFilterStatus] = useState<string>('ALL')
  const [searchQuery, setSearchQuery] = useState('')

  // Modals & Panels
  const [showRegisterForm, setShowRegisterForm] = useState(false)
  const [selectedTarget, setSelectedTarget] = useState<AuthorizedTarget | null>(null)
  const [revokeModalTarget, setRevokeModalTarget] = useState<AuthorizedTarget | null>(null)
  const [revocationReason, setRevocationReason] = useState('')

  // Registration Form State
  const [formData, setFormData] = useState<AuthorizedTargetCreate>({
    name: '',
    host: '',
    target_url: '',
    purpose: 'Vulnerability Assessment',
    description: '',
    auth_contact: '',
    auth_reference: '',
    valid_from: new Date().toISOString().slice(0, 10),
    valid_to: new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 10),
    permitted_ports: '80, 443, 8080, 8443',
    excluded_ports: '22, 3389, 5432',
    excluded_paths: '/admin, /logout, /billing',
    restrictions: 'Safe vulnerability assessment only; no destructive exploits; no DoS.',
  })
  const [formError, setFormError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  // Scope Validation Simulator State
  const [simTarget, setSimTarget] = useState('')
  const [simPort, setSimPort] = useState('443')
  const [simPath, setSimPath] = useState('/api/v1/health')
  const [simProtocol, setSimProtocol] = useState('https')
  const [simResult, setSimResult] = useState<ScopeValidationResponse | null>(null)
  const [simLoading, setSimLoading] = useState(false)

  // Audit Log State
  const [auditEvents, setAuditEvents] = useState<ScopeAuditItem[]>([])

  // Load Data
  const loadData = async () => {
    try {
      setLoading(true)
      const [statsRes, listRes, auditRes] = await Promise.all([
        targetsApi.overviewStats().catch(() => ({
          total_targets: 0,
          active_targets: 0,
          expired_targets: 0,
          revoked_targets: 0,
          pending_targets: 0,
        })),
        targetsApi.list().catch(() => []),
        scopeApi.audit({ limit: 10 }).catch(() => ({ total_events: 0, events: [] })),
      ])
      setStats(statsRes)
      setTargets(listRes)
      setAuditEvents(auditRes.events || [])
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
  }, [])

  // Handle Target Registration
  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault()
    setFormError(null)

    if (!formData.name.trim() || !formData.host.trim()) {
      setFormError('Target Name and Target Host (Domain or IP) are mandatory.')
      return
    }

    // Format dates to ISO
    const payload: AuthorizedTargetCreate = {
      ...formData,
      valid_from: formData.valid_from ? new Date(formData.valid_from).toISOString() : undefined,
      valid_to: formData.valid_to ? new Date(formData.valid_to).toISOString() : undefined,
    }

    try {
      setSubmitting(true)
      await targetsApi.create(payload)
      setShowRegisterForm(false)
      // Reset form
      setFormData({
        name: '',
        host: '',
        target_url: '',
        purpose: 'Vulnerability Assessment',
        description: '',
        auth_contact: '',
        auth_reference: '',
        valid_from: new Date().toISOString().slice(0, 10),
        valid_to: new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 10),
        permitted_ports: '80, 443, 8080, 8443',
        excluded_ports: '22, 3389, 5432',
        excluded_paths: '/admin, /logout, /billing',
        restrictions: 'Safe vulnerability assessment only; no destructive exploits; no DoS.',
      })
      await loadData()
    } catch (err: any) {
      setFormError(err?.userMessage || err?.response?.data?.detail || 'Failed to register target.')
    } finally {
      setSubmitting(false)
    }
  }

  // Handle Revocation
  const handleRevoke = async () => {
    if (!revokeModalTarget) return
    if (!revocationReason.trim()) {
      alert('Revocation reason is required.')
      return
    }

    try {
      await targetsApi.revoke(revokeModalTarget.id, {
        revocation_reason: revocationReason,
        revoked_by: 'lead_security_analyst',
      })
      setRevokeModalTarget(null)
      setRevocationReason('')
      await loadData()
    } catch (err: any) {
      alert(err?.userMessage || 'Failed to revoke target authorization.')
    }
  }

  // Handle Scope Simulator Test
  const handleSimulateScope = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!simTarget.trim()) return

    try {
      setSimLoading(true)
      setSimResult(null)
      const res = await scopeApi.validate({
        requested_target: simTarget.trim(),
        requested_port: simPort ? parseInt(simPort, 10) : undefined,
        requested_path: simPath.trim() || undefined,
        requested_protocol: simProtocol.trim() || undefined,
        action_type: 'scope_simulation',
      })
      setSimResult(res)
    } catch (err: any) {
      alert(err?.userMessage || 'Scope validation request failed.')
    } finally {
      setSimLoading(false)
    }
  }

  // Filtered Targets
  const filteredTargets = targets.filter((t) => {
    const matchesStatus =
      filterStatus === 'ALL' || t.status.toUpperCase() === filterStatus.toUpperCase()
    const matchesQuery =
      t.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      t.host.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (t.auth_reference && t.auth_reference.toLowerCase().includes(searchQuery.toLowerCase()))
    return matchesStatus && matchesQuery
  })

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* ── Top Header / Alert ────────────────────────────────────────── */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-2xl bg-gradient-to-r from-navy-900 via-navy-800 to-navy-900 border border-cyan-500/30 shadow-glow-cyan">
        <div>
          <div className="flex items-center gap-2.5">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse" />
            <h1 className="text-xl font-bold text-slate-100 font-mono tracking-tight">
              TARGET REGISTRATION & SCOPE ENFORCEMENT
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            The AI agent executes assessments exclusively against actively authorized targets.
            Default behavior is <span className="text-rose-400 font-semibold font-mono">STRICT DEFAULT-DENY</span>.
            Excluded resources override permitted configurations.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowRegisterForm(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-navy-950 font-semibold text-xs transition-all duration-200 shadow-glow-cyan"
          >
            <Plus className="w-4 h-4" />
            <span>Register Authorized Target</span>
          </button>
          <button
            onClick={loadData}
            title="Refresh"
            className="p-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors"
          >
            <RefreshCw className={clsx('w-4 h-4', loading && 'animate-spin text-cyan-400')} />
          </button>
        </div>
      </div>

      {/* ── Metrics Cards ────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Targets */}
        <div className="p-4 rounded-xl bg-navy-900/80 border border-slate-800 flex items-center justify-between">
          <div>
            <p className="text-xs font-mono text-slate-400 uppercase tracking-wider">Total Targets</p>
            <p className="text-2xl font-bold font-mono text-slate-100 mt-1">{stats.total_targets}</p>
            <p className="text-[11px] text-slate-500 mt-0.5">Allowlist registry entries</p>
          </div>
          <div className="w-10 h-10 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
            <ShieldCheck className="w-5 h-5" />
          </div>
        </div>

        {/* Active Authorized */}
        <div className="p-4 rounded-xl bg-navy-900/80 border border-emerald-500/30 flex items-center justify-between shadow-glow-emerald">
          <div>
            <p className="text-xs font-mono text-emerald-400 uppercase tracking-wider">Active Scope</p>
            <p className="text-2xl font-bold font-mono text-emerald-300 mt-1">{stats.active_targets}</p>
            <p className="text-[11px] text-emerald-500/80 mt-0.5">Permitted for assessment planning</p>
          </div>
          <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
            <CheckCircle2 className="w-5 h-5" />
          </div>
        </div>

        {/* Expired Targets */}
        <div className="p-4 rounded-xl bg-navy-900/80 border border-amber-500/30 flex items-center justify-between">
          <div>
            <p className="text-xs font-mono text-amber-400 uppercase tracking-wider">Expired</p>
            <p className="text-2xl font-bold font-mono text-amber-300 mt-1">{stats.expired_targets}</p>
            <p className="text-[11px] text-amber-500/80 mt-0.5">Window passed; scanning blocked</p>
          </div>
          <div className="w-10 h-10 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
            <Clock className="w-5 h-5" />
          </div>
        </div>

        {/* Revoked Targets */}
        <div className="p-4 rounded-xl bg-navy-900/80 border border-rose-500/30 flex items-center justify-between">
          <div>
            <p className="text-xs font-mono text-rose-400 uppercase tracking-wider">Revoked</p>
            <p className="text-2xl font-bold font-mono text-rose-300 mt-1">{stats.revoked_targets}</p>
            <p className="text-[11px] text-rose-500/80 mt-0.5">Authorization withdrawn</p>
          </div>
          <div className="w-10 h-10 rounded-lg bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400">
            <Ban className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* ── Interactive Scope Validation Simulator ────────────────────── */}
      <div className="p-5 rounded-2xl bg-navy-900/90 border border-slate-800 shadow-xl space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Terminal className="w-5 h-5 text-cyan-400" />
            <h2 className="text-sm font-semibold text-slate-100 font-mono">
              STRICT SCOPE VALIDATION ENGINE (PRE-ASSESSMENT SIMULATOR)
            </h2>
          </div>
          <span className="text-[11px] font-mono px-2 py-0.5 bg-slate-800 text-slate-400 rounded border border-slate-700">
            Default: DENY
          </span>
        </div>
        <p className="text-xs text-slate-400">
          Verify whether an assessment request meets strict allowlist criteria before submitting to the AI planner or scanners.
        </p>

        <form onSubmit={handleSimulateScope} className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-3 pt-1">
          <div className="md:col-span-2">
            <label className="block text-[11px] font-mono text-slate-400 mb-1">Target Host / IP</label>
            <input
              type="text"
              value={simTarget}
              onChange={(e) => setSimTarget(e.target.value)}
              placeholder="e.g. 192.168.1.50 or api.company.com"
              required
              className="w-full px-3 py-2 text-xs rounded-lg bg-navy-950 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-400 font-mono"
            />
          </div>

          <div>
            <label className="block text-[11px] font-mono text-slate-400 mb-1">Port</label>
            <input
              type="number"
              value={simPort}
              onChange={(e) => setSimPort(e.target.value)}
              placeholder="e.g. 443"
              className="w-full px-3 py-2 text-xs rounded-lg bg-navy-950 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-400 font-mono"
            />
          </div>

          <div>
            <label className="block text-[11px] font-mono text-slate-400 mb-1">URL Path</label>
            <input
              type="text"
              value={simPath}
              onChange={(e) => setSimPath(e.target.value)}
              placeholder="/api/v1/health"
              className="w-full px-3 py-2 text-xs rounded-lg bg-navy-950 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-400 font-mono"
            />
          </div>

          <div className="flex items-end">
            <button
              type="submit"
              disabled={simLoading || !simTarget.trim()}
              className="w-full py-2 px-3 text-xs font-semibold rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white transition-all shadow-glow-cyan flex items-center justify-center gap-1.5"
            >
              {simLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Sliders className="w-3.5 h-3.5" />}
              <span>Test Scope</span>
            </button>
          </div>
        </form>

        {/* Validation Result Box */}
        {simResult && (
          <div
            className={clsx(
              'mt-3 p-4 rounded-xl border text-xs font-mono transition-all',
              simResult.allowed
                ? 'bg-emerald-950/20 border-emerald-500/40 text-emerald-200 shadow-glow-emerald'
                : 'bg-rose-950/20 border-rose-500/40 text-rose-200'
            )}
          >
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-center gap-2 font-bold text-sm">
                {simResult.allowed ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                ) : (
                  <XCircle className="w-4 h-4 text-rose-400 flex-shrink-0" />
                )}
                <span>
                  {simResult.allowed ? 'AUTHORIZED: ACTION PERMITTED WITHIN SCOPE' : 'REJECTED: OUTSIDE AUTHORIZED SCOPE'}
                </span>
              </div>
              <span className="text-[10px] text-slate-400 font-mono">
                {new Date(simResult.validated_at).toLocaleTimeString()}
              </span>
            </div>

            <p className="mt-2 text-slate-300 font-sans leading-relaxed">{simResult.reason}</p>

            {simResult.allowed && (
              <div className="mt-3 pt-3 border-t border-emerald-500/20 grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px]">
                <div>
                  <span className="text-slate-400">Target: </span>
                  <span className="text-slate-200 font-semibold">{simResult.target_name}</span>
                </div>
                <div>
                  <span className="text-slate-400">Auth Ref: </span>
                  <span className="text-slate-200">{simResult.auth_reference || 'N/A'}</span>
                </div>
                <div>
                  <span className="text-slate-400">Permitted Ports: </span>
                  <span className="text-slate-200">
                    {Array.isArray(simResult.permitted_ports)
                      ? simResult.permitted_ports.join(', ')
                      : 'All non-excluded'}
                  </span>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* ── Registered Targets Table & Controls ───────────────────────── */}
      <div className="p-5 rounded-2xl bg-navy-900/90 border border-slate-800 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-slate-100 font-mono flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-cyan-400" />
              <span>AUTHORIZED TARGET REGISTRY</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Only ACTIVE targets within valid authorization windows can be assessed.
            </p>
          </div>

          <div className="flex items-center gap-2">
            {/* Filter */}
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="px-3 py-1.5 text-xs rounded-lg bg-navy-950 border border-slate-700 text-slate-300 focus:outline-none"
            >
              <option value="ALL">All Statuses</option>
              <option value="ACTIVE">Active</option>
              <option value="PENDING">Pending</option>
              <option value="EXPIRED">Expired</option>
              <option value="REVOKED">Revoked</option>
            </select>

            {/* Search */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
              <input
                type="text"
                placeholder="Search targets..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-8 pr-3 py-1.5 text-xs rounded-lg bg-navy-950 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-400 w-48 font-mono"
              />
            </div>
          </div>
        </div>

        {/* Table */}
        <div className="overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full text-left text-xs">
            <thead className="bg-navy-950/80 text-slate-400 font-mono text-[11px] uppercase border-b border-slate-800">
              <tr>
                <th className="px-4 py-3">Target Name</th>
                <th className="px-4 py-3">Host / Address</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Permitted Ports</th>
                <th className="px-4 py-3">Authorization Ref</th>
                <th className="px-4 py-3">Valid Until</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {filteredTargets.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-slate-500">
                    {loading ? 'Loading registry records...' : 'No authorized targets found.'}
                  </td>
                </tr>
              ) : (
                filteredTargets.map((target) => {
                  const status = (target.status || 'PENDING').toUpperCase()
                  const isActive = status === 'ACTIVE'
                  const isRevoked = status === 'REVOKED'
                  const isExpired = status === 'EXPIRED'

                  return (
                    <tr key={target.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="px-4 py-3 font-semibold text-slate-200">
                        {target.name}
                        {target.target_url && (
                          <div className="text-[10px] text-slate-500 truncate max-w-xs">{target.target_url}</div>
                        )}
                      </td>
                      <td className="px-4 py-3 font-mono text-cyan-300">{target.host}</td>
                      <td className="px-4 py-3">
                        <span
                          className={clsx(
                            'px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase border',
                            isActive && 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
                            isExpired && 'bg-amber-500/10 text-amber-400 border-amber-500/30',
                            isRevoked && 'bg-rose-500/10 text-rose-400 border-rose-500/30',
                            status === 'PENDING' && 'bg-slate-700/30 text-slate-300 border-slate-600'
                          )}
                        >
                          {status}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono text-slate-400">
                        {target.permitted_ports
                          ? Array.isArray(target.permitted_ports)
                            ? target.permitted_ports.slice(0, 4).join(', ') +
                              (target.permitted_ports.length > 4 ? '...' : '')
                            : String(target.permitted_ports)
                          : 'Any (Non-excluded)'}
                      </td>
                      <td className="px-4 py-3 font-mono text-slate-400 text-[11px]">
                        {target.auth_reference || 'N/A'}
                      </td>
                      <td className="px-4 py-3 text-slate-400 font-mono text-[11px]">
                        {target.valid_to ? new Date(target.valid_to).toLocaleDateString() : 'Indefinite'}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => setSelectedTarget(target)}
                            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-medium border border-slate-700"
                          >
                            Details
                          </button>
                          {isActive && (
                            <button
                              onClick={() => {
                                setRevokeModalTarget(target)
                                setRevocationReason('')
                              }}
                              className="px-2 py-1 rounded bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 text-[11px] font-medium border border-rose-500/30"
                            >
                              Revoke
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Scope Audit Log Feed ──────────────────────────────────────── */}
      {auditEvents.length > 0 && (
        <div className="p-5 rounded-2xl bg-navy-900/90 border border-slate-800 shadow-xl space-y-3">
          <div className="flex items-center gap-2">
            <Info className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-slate-200 font-mono">
              IMMUTABLE SCOPE AUDIT TRAIL (RECENT ACTIONS)
            </h3>
          </div>
          <div className="divide-y divide-slate-800/80 rounded-xl border border-slate-800/80 overflow-hidden font-mono text-[11px]">
            {auditEvents.slice(0, 5).map((ev) => (
              <div key={ev.id} className="p-3 bg-navy-950/40 flex items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <span className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700 text-[10px]">
                    {ev.action}
                  </span>
                  <span className="text-slate-300 font-sans truncate max-w-xl">{ev.detail}</span>
                </div>
                <div className="text-slate-500 text-[10px] flex-shrink-0">
                  {new Date(ev.timestamp).toLocaleTimeString()}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Registration Modal ────────────────────────────────────────── */}
      {showRegisterForm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-navy-950/80 backdrop-blur-sm overflow-y-auto">
          <div className="relative w-full max-w-2xl my-8 p-6 rounded-2xl bg-navy-900 border border-cyan-500/30 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-base font-bold text-slate-100 font-mono">REGISTER AUTHORIZED TARGET</h3>
                <p className="text-xs text-slate-400">Strict scope validation parameters and lifecycle window</p>
              </div>
              <button
                onClick={() => setShowRegisterForm(false)}
                className="text-slate-400 hover:text-slate-100 p-1"
              >
                ✕
              </button>
            </div>

            {/* Note banner */}
            <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5 text-amber-400" />
              <div>
                <span className="font-semibold">Authorization Assertion Notice:</span> Target registration records an
                analyst-provided authorization reference. It does not constitute independently verified legal
                authorization. Wildcard domains and CIDR notations are rejected by policy.
              </div>
            </div>

            {formError && (
              <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs">
                {formError}
              </div>
            )}

            <form onSubmit={handleRegister} className="space-y-4 text-xs">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Target Name *</label>
                  <input
                    type="text"
                    required
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    placeholder="e.g. Production Billing API"
                    className="w-full px-3 py-2 rounded-lg bg-navy-950 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-400 font-sans"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">Target Host / IP * (No wildcards)</label>
                  <input
                    type="text"
                    required
                    value={formData.host}
                    onChange={(e) => setFormData({ ...formData, host: e.target.value })}
                    placeholder="e.g. 192.168.1.50 or api.company.com"
                    className="w-full px-3 py-2 rounded-lg bg-navy-950 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-400 font-mono"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Target URL (Optional)</label>
                  <input
                    type="text"
                    value={formData.target_url || ''}
                    onChange={(e) => setFormData({ ...formData, target_url: e.target.value })}
                    placeholder="https://192.168.1.50:8443"
                    className="w-full px-3 py-2 rounded-lg bg-navy-950 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-400 font-mono"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">Assessment Purpose</label>
                  <select
                    value={formData.purpose || 'Vulnerability Assessment'}
                    onChange={(e) => setFormData({ ...formData, purpose: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg bg-navy-950 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-400"
                  >
                    <option value="Vulnerability Assessment">Routine Vulnerability Assessment</option>
                    <option value="Penetration Testing">Authorized Penetration Testing</option>
                    <option value="Compliance Audit">Compliance Audit (SOC2 / ISO 27001)</option>
                    <option value="Pre-production Verification">Pre-production Verification</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Responsible Authorization Contact</label>
                  <input
                    type="text"
                    value={formData.auth_contact || ''}
                    onChange={(e) => setFormData({ ...formData, auth_contact: e.target.value })}
                    placeholder="ciso-ops@company.internal"
                    className="w-full px-3 py-2 rounded-lg bg-navy-950 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-400"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">Authorization Reference ID</label>
                  <input
                    type="text"
                    value={formData.auth_reference || ''}
                    onChange={(e) => setFormData({ ...formData, auth_reference: e.target.value })}
                    placeholder="AUTH-2026-SEC-0042"
                    className="w-full px-3 py-2 rounded-lg bg-navy-950 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-400 font-mono"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Authorization Start Date</label>
                  <input
                    type="date"
                    value={formData.valid_from?.slice(0, 10) || ''}
                    onChange={(e) => setFormData({ ...formData, valid_from: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg bg-navy-950 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-400 font-mono"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">Authorization Expiration Date</label>
                  <input
                    type="date"
                    value={formData.valid_to?.slice(0, 10) || ''}
                    onChange={(e) => setFormData({ ...formData, valid_to: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg bg-navy-950 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-400 font-mono"
                  />
                </div>
              </div>

              {/* Port & Path Scope Rules */}
              <div className="p-3 rounded-xl bg-navy-950/60 border border-slate-800 space-y-3">
                <div className="text-slate-300 font-semibold font-mono text-[11px] flex items-center gap-1.5">
                  <Sliders className="w-3.5 h-3.5 text-cyan-400" />
                  <span>BOUNDARY ENFORCEMENT RULES</span>
                </div>

                <div>
                  <label className="block text-slate-400 font-mono text-[11px] mb-1">
                    Permitted Ports (Comma-separated or ranges, e.g. 80, 443, 8080-8443)
                  </label>
                  <input
                    type="text"
                    value={typeof formData.permitted_ports === 'string' ? formData.permitted_ports : ''}
                    onChange={(e) => setFormData({ ...formData, permitted_ports: e.target.value })}
                    placeholder="80, 443, 8080, 8443"
                    className="w-full px-3 py-1.5 rounded-lg bg-navy-900 border border-slate-700 text-slate-200 font-mono"
                  />
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-rose-400 font-mono text-[11px] mb-1">
                      Excluded Ports (Precedence override)
                    </label>
                    <input
                      type="text"
                      value={typeof formData.excluded_ports === 'string' ? formData.excluded_ports : ''}
                      onChange={(e) => setFormData({ ...formData, excluded_ports: e.target.value })}
                      placeholder="22, 3389, 5432"
                      className="w-full px-3 py-1.5 rounded-lg bg-navy-900 border border-rose-500/30 text-slate-200 font-mono"
                    />
                  </div>

                  <div>
                    <label className="block text-rose-400 font-mono text-[11px] mb-1">
                      Excluded URL Paths (Precedence override)
                    </label>
                    <input
                      type="text"
                      value={typeof formData.excluded_paths === 'string' ? formData.excluded_paths : ''}
                      onChange={(e) => setFormData({ ...formData, excluded_paths: e.target.value })}
                      placeholder="/admin, /logout, /billing"
                      className="w-full px-3 py-1.5 rounded-lg bg-navy-900 border border-rose-500/30 text-slate-200 font-mono"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-slate-400 font-mono text-[11px] mb-1">
                    Additional Scope Restrictions & Rules
                  </label>
                  <input
                    type="text"
                    value={formData.restrictions || ''}
                    onChange={(e) => setFormData({ ...formData, restrictions: e.target.value })}
                    placeholder="Safe vulnerability assessment only; no destructive exploits; no DoS."
                    className="w-full px-3 py-1.5 rounded-lg bg-navy-900 border border-slate-700 text-slate-200"
                  />
                </div>
              </div>

              <div className="flex justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowRegisterForm(false)}
                  className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-5 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-navy-950 font-bold shadow-glow-cyan flex items-center gap-2"
                >
                  {submitting ? <RefreshCw className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
                  <span>Authorize & Register</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── Details Modal ─────────────────────────────────────────────── */}
      {selectedTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-navy-950/80 backdrop-blur-sm">
          <div className="relative w-full max-w-lg p-6 rounded-2xl bg-navy-900 border border-slate-700 shadow-2xl space-y-4 text-xs">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-base font-bold text-slate-100 font-mono">{selectedTarget.name}</h3>
                <span className="font-mono text-cyan-400">{selectedTarget.host}</span>
              </div>
              <button onClick={() => setSelectedTarget(null)} className="text-slate-400 hover:text-slate-100">
                ✕
              </button>
            </div>

            <div className="space-y-2.5 font-sans">
              <div className="flex justify-between py-1 border-b border-slate-800">
                <span className="text-slate-400">Authorization Status:</span>
                <span className="font-mono font-bold text-cyan-300 uppercase">{selectedTarget.status}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800">
                <span className="text-slate-400">Auth Reference:</span>
                <span className="font-mono text-slate-200">{selectedTarget.auth_reference || 'N/A'}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800">
                <span className="text-slate-400">Responsible Contact:</span>
                <span className="text-slate-200">{selectedTarget.auth_contact || 'N/A'}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800">
                <span className="text-slate-400">Validity Window:</span>
                <span className="font-mono text-slate-200">
                  {selectedTarget.valid_from ? new Date(selectedTarget.valid_from).toLocaleDateString() : '—'} to{' '}
                  {selectedTarget.valid_to ? new Date(selectedTarget.valid_to).toLocaleDateString() : 'Indefinite'}
                </span>
              </div>
              <div className="py-1 border-b border-slate-800">
                <span className="text-slate-400 block mb-1">Permitted Ports:</span>
                <div className="font-mono text-slate-200 bg-navy-950 p-2 rounded border border-slate-800 break-all">
                  {selectedTarget.permitted_ports ? String(selectedTarget.permitted_ports) : 'All non-excluded ports'}
                </div>
              </div>
              <div className="py-1 border-b border-slate-800">
                <span className="text-rose-400 block mb-1">Excluded Ports (Forbidden):</span>
                <div className="font-mono text-rose-300 bg-navy-950 p-2 rounded border border-rose-950/40 break-all">
                  {selectedTarget.excluded_ports ? String(selectedTarget.excluded_ports) : 'None'}
                </div>
              </div>
              <div className="py-1 border-b border-slate-800">
                <span className="text-rose-400 block mb-1">Excluded Paths (Forbidden):</span>
                <div className="font-mono text-rose-300 bg-navy-950 p-2 rounded border border-rose-950/40 break-all">
                  {selectedTarget.excluded_paths ? String(selectedTarget.excluded_paths) : 'None'}
                </div>
              </div>
              <div className="py-1">
                <span className="text-slate-400 block mb-1">Restrictions:</span>
                <p className="text-slate-300 italic">{selectedTarget.restrictions || 'No special restrictions noted.'}</p>
              </div>
            </div>

            <div className="flex justify-end pt-3 border-t border-slate-800">
              <button
                onClick={() => setSelectedTarget(null)}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Revoke Modal ──────────────────────────────────────────────── */}
      {revokeModalTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-navy-950/80 backdrop-blur-sm">
          <div className="relative w-full max-w-md p-6 rounded-2xl bg-navy-900 border border-rose-500/40 shadow-2xl space-y-4 text-xs">
            <div className="flex items-center gap-2 text-rose-400">
              <Ban className="w-5 h-5 flex-shrink-0" />
              <h3 className="text-base font-bold text-slate-100 font-mono">REVOKE TARGET AUTHORIZATION</h3>
            </div>

            <p className="text-slate-300">
              You are withdrawing authorization for <span className="font-mono text-cyan-300">{revokeModalTarget.host}</span>.
              Any existing or subsequent assessment planning against this target will be immediately rejected with HTTP 403.
            </p>

            <div>
              <label className="block text-slate-300 font-medium mb-1">Revocation Reason (Mandatory) *</label>
              <textarea
                rows={3}
                required
                value={revocationReason}
                onChange={(e) => setRevocationReason(e.target.value)}
                placeholder="e.g. Scope window cancelled by client; security incident raised."
                className="w-full px-3 py-2 rounded-lg bg-navy-950 border border-rose-500/30 text-slate-200 focus:outline-none focus:border-rose-400 font-sans"
              />
            </div>

            <div className="flex justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                onClick={() => setRevokeModalTarget(null)}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300"
              >
                Cancel
              </button>
              <button
                onClick={handleRevoke}
                className="px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white font-bold"
              >
                Confirm Revocation
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
