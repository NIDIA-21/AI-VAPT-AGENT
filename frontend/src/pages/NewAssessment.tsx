import { useState, useEffect } from 'react'
import { useNavigate, useLocation, Link } from 'react-router-dom'
import {
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Play,
  ArrowRight,
  Sliders,
  Calendar,
  Lock,
  Layers,
  FileCode,
  Info,
  Bot,
  Sparkles,
  Terminal,
  RefreshCw,
} from 'lucide-react'
import { clsx } from 'clsx'
import { targetsApi, assessmentsApi, scopeApi, agentApi } from '@/services/api'
import type {
  AuthorizedTarget,
  ScopeValidationResponse,
  AssessmentPlan,
  PlanDecision,
} from '@/types'

export default function NewAssessment() {
  const navigate = useNavigate()
  const location = useLocation()

  // Targets state
  const [targets, setTargets] = useState<AuthorizedTarget[]>([])
  const [selectedTargetId, setSelectedTargetId] = useState<string>('')
  const [loadingTargets, setLoadingTargets] = useState(true)

  // Form State
  const [assessmentName, setAssessmentName] = useState('')
  const [assessmentType, setAssessmentType] = useState('full_vapt')
  const [description, setDescription] = useState('')
  const [createdBy, setCreatedBy] = useState('lead_analyst')
  const [testPort, setTestPort] = useState<string>('443')
  const [testPath, setTestPath] = useState<string>('/')

  // Sprint 4: Natural Language Requirements & AI Planner
  const [requirements, setRequirements] = useState(
    'Perform comprehensive vulnerability assessment across open network services and web endpoints. Identify OWASP Top 10 vulnerabilities, weak headers, and TLS configurations.'
  )
  const [selectedCategories, setSelectedCategories] = useState<string[]>([
    'network_discovery',
    'web_vapt',
    'server_config',
    'tls_audit',
  ])
  const [generatedPlan, setGeneratedPlan] = useState<AssessmentPlan | null>(null)
  const [planning, setPlanning] = useState(false)
  const [decisionIds, setDecisionIds] = useState<string[]>([])
  const [viewingDecisions, setViewingDecisions] = useState<PlanDecision[] | null>(null)

  // Scope Pre-validation state
  const [validationResult, setValidationResult] = useState<ScopeValidationResponse | null>(null)
  const [validating, setValidating] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)

  // Fetch targets on mount & handle incoming state from AI Agent chat
  useEffect(() => {
    async function fetchTargets() {
      try {
        setLoadingTargets(true)
        const list = await targetsApi.list()
        setTargets(list)

        const stateTargetId = (location.state as any)?.targetId
        const statePlanSummary = (location.state as any)?.planSummary
        const stateDecisionIds = (location.state as any)?.decisionIds

        if (stateTargetId && list.some((t) => t.id === stateTargetId)) {
          setSelectedTargetId(stateTargetId)
        } else {
          const firstActive = list.find((t) => (t.status || '').toUpperCase() === 'ACTIVE')
          if (firstActive) {
            setSelectedTargetId(firstActive.id)
          } else if (list.length > 0) {
            setSelectedTargetId(list[0].id)
          }
        }

        if (statePlanSummary) {
          setDescription(`Planned via AI Agent: ${statePlanSummary}`)
        }
        if (stateDecisionIds && Array.isArray(stateDecisionIds)) {
          setDecisionIds(stateDecisionIds)
        }
      } catch (err: any) {
        setErrorMessage(err?.userMessage || 'Failed to load authorized targets.')
      } finally {
        setLoadingTargets(false)
      }
    }
    fetchTargets()
  }, [location.state])

  // Currently selected target object
  const currentTarget = targets.find((t) => t.id === selectedTargetId) || null
  const isTargetActive = (currentTarget?.status || '').toUpperCase() === 'ACTIVE'

  // Pre-validate whenever selected target changes or user adjusts parameters
  useEffect(() => {
    if (!currentTarget) {
      setValidationResult(null)
      return
    }

    async function runPreValidation() {
      try {
        setValidating(true)
        const portNum = testPort ? parseInt(testPort, 10) : undefined
        const res = await scopeApi.validate({
          requested_target: currentTarget!.host,
          requested_port: isNaN(portNum as number) ? undefined : portNum,
          requested_path: testPath.trim() || undefined,
          action_type: 'pre_assessment_validation',
        })
        setValidationResult(res)
      } catch (err: any) {
        setValidationResult({
          allowed: false,
          reason: err?.userMessage || 'Scope validation query failed.',
          validated_at: new Date().toISOString(),
        })
      } finally {
        setValidating(false)
      }
    }

    const timer = setTimeout(runPreValidation, 300)
    return () => clearTimeout(timer)
  }, [currentTarget, testPort, testPath])

  // Toggle Category
  const toggleCategory = (cat: string) => {
    setSelectedCategories((prev) =>
      prev.includes(cat) ? prev.filter((c) => c !== cat) : [...prev, cat]
    )
  }

  // Generate Plan with AI
  const handleGeneratePlan = async () => {
    if (!currentTarget) return
    if (!isTargetActive) {
      alert(`Target ${currentTarget.host} is not active.`)
      return
    }

    try {
      setPlanning(true)
      setErrorMessage(null)
      const plan = await agentApi.generatePlan({
        target_id: currentTarget.id,
        requirements,
        assessment_type: assessmentType,
        selected_categories: selectedCategories,
        operator: createdBy,
      })
      setGeneratedPlan(plan)
      setDecisionIds(plan.decisions.map((d) => d.id))
      if (!assessmentName) {
        setAssessmentName(plan.assessment_name)
      }
    } catch (err: any) {
      setErrorMessage(err?.userMessage || err?.response?.data?.detail || 'AI Plan generation failed.')
    } finally {
      setPlanning(false)
    }
  }

  // Handle Assessment Creation
  const handleCreateAssessment = async (e: React.FormEvent) => {
    e.preventDefault()
    setErrorMessage(null)

    if (!currentTarget) {
      setErrorMessage('Please select an authorized target.')
      return
    }

    if (!isTargetActive) {
      setErrorMessage(`Target '${currentTarget.host}' is in ${currentTarget.status} status. Assessments can only be launched on ACTIVE targets.`)
      return
    }

    if (!validationResult || !validationResult.allowed) {
      setErrorMessage(
        validationResult?.reason || 'Strict scope validation rejected this target. Assessment cannot be initiated.'
      )
      return
    }

    if (!assessmentName.trim()) {
      setErrorMessage('Assessment Name is required.')
      return
    }

    try {
      setSubmitting(true)
      const res = await assessmentsApi.create({
        name: assessmentName.trim(),
        description: description.trim() || undefined,
        target_id: currentTarget.id,
        assessment_type: assessmentType,
        ai_plan: generatedPlan ? generatedPlan.summary : undefined,
        decision_ids: decisionIds.length > 0 ? decisionIds : undefined,
        created_by: createdBy.trim() || 'lead_analyst',
      })

      // Route to Dashboard upon success
      navigate('/', {
        state: { notification: `Assessment '${res.name}' created and bound to validated scope snapshot.` },
      })
    } catch (err: any) {
      setErrorMessage(err?.userMessage || err?.response?.data?.detail || 'Failed to initialize assessment.')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="max-w-5xl mx-auto space-y-6 pb-12">
      {/* ── Page Header ────────────────────────────────────────── */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-2xl bg-gradient-to-r from-navy-900 via-navy-800 to-navy-900 border border-cyan-500/30 shadow-glow-cyan">
        <div>
          <div className="flex items-center gap-2.5">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse" />
            <h1 className="text-xl font-bold text-slate-100 font-mono tracking-tight">
              INITIALIZE NEW ASSESSMENT & AI PLANNER
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Strict scope enforcement is mandatory. Configure assessment parameters, let the AI security agent
            generate a tailored multi-stage plan, and review decision traces.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Link
            to="/agent"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 text-xs font-mono transition-colors"
          >
            <Bot className="w-3.5 h-3.5" />
            <span>AI Chat Assistant</span>
          </Link>
          <Link
            to="/targets"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-mono transition-colors"
          >
            <Sliders className="w-3.5 h-3.5" />
            <span>Targets</span>
          </Link>
        </div>
      </div>

      {/* ── Error Banner ──────────────────────────────────────── */}
      {errorMessage && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-500/40 text-rose-200 text-xs flex items-start gap-3 shadow-lg">
          <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0 mt-0.5" />
          <div className="flex-1">
            <span className="font-bold font-mono">Scope Enforcer Blocked Action:</span> {errorMessage}
          </div>
        </div>
      )}

      <form onSubmit={handleCreateAssessment} className="space-y-6">
        {/* ── Section 1: Authorized Target Selector ─────────────── */}
        <div className="p-5 rounded-2xl bg-navy-900/90 border border-slate-800 shadow-xl space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-cyan-400" />
              <h2 className="text-sm font-semibold text-slate-100 font-mono">
                1. SELECT AUTHORIZED TARGET
              </h2>
            </div>
            <span className="text-[11px] font-mono text-slate-400">
              {targets.length} targets in registry
            </span>
          </div>

          {loadingTargets ? (
            <div className="py-6 text-center text-xs text-slate-400 font-mono">
              Loading authorized targets from allowlist...
            </div>
          ) : targets.length === 0 ? (
            <div className="p-6 text-center rounded-xl bg-navy-950 border border-slate-800 text-xs text-slate-400 space-y-3">
              <p>No authorized targets found in database allowlist.</p>
              <Link
                to="/targets"
                className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-cyan-500 text-navy-950 font-bold text-xs"
              >
                Register First Authorized Target
              </Link>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">
                  Authorized Target Host *
                </label>
                <select
                  value={selectedTargetId}
                  onChange={(e) => setSelectedTargetId(e.target.value)}
                  className="w-full px-3 py-2 text-xs rounded-xl bg-navy-950 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-400 font-mono"
                >
                  {targets.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name} — {t.host} [{t.status}]
                    </option>
                  ))}
                </select>
              </div>

              {/* Status & Validity Card */}
              {currentTarget && (
                <div
                  className={clsx(
                    'p-3 rounded-xl border text-xs space-y-1.5',
                    isTargetActive
                      ? 'bg-emerald-950/20 border-emerald-500/30 text-emerald-200'
                      : 'bg-rose-950/20 border-rose-500/30 text-rose-300'
                  )}
                >
                  <div className="flex items-center justify-between font-mono text-[11px]">
                    <span className="text-slate-400">Target Authorization Status:</span>
                    <span
                      className={clsx(
                        'px-2 py-0.5 rounded font-bold uppercase border text-[10px]',
                        isTargetActive
                          ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                          : 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                      )}
                    >
                      {currentTarget.status}
                    </span>
                  </div>

                  <div className="flex justify-between text-[11px] font-mono">
                    <span className="text-slate-400">Auth Reference:</span>
                    <span className="text-slate-200">{currentTarget.auth_reference || 'N/A'}</span>
                  </div>

                  <div className="flex justify-between text-[11px] font-mono">
                    <span className="text-slate-400">Valid Until:</span>
                    <span className="text-slate-200">
                      {currentTarget.valid_to ? new Date(currentTarget.valid_to).toLocaleDateString() : 'Indefinite'}
                    </span>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Bound Scope Boundaries Overview */}
          {currentTarget && (
            <div className="pt-2">
              <p className="text-[11px] font-mono text-slate-400 uppercase tracking-wider mb-2">
                Active Scope Boundary Snapshot:
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px] font-mono">
                <div className="p-2.5 rounded-lg bg-navy-950 border border-slate-800">
                  <span className="text-slate-400 block text-[10px]">Permitted Ports:</span>
                  <span className="text-slate-200 break-all">
                    {currentTarget.permitted_ports ? String(currentTarget.permitted_ports) : 'All non-excluded'}
                  </span>
                </div>
                <div className="p-2.5 rounded-lg bg-navy-950 border border-slate-800">
                  <span className="text-rose-400 block text-[10px]">Excluded Ports:</span>
                  <span className="text-rose-300 break-all">
                    {currentTarget.excluded_ports ? String(currentTarget.excluded_ports) : 'None'}
                  </span>
                </div>
                <div className="p-2.5 rounded-lg bg-navy-950 border border-slate-800">
                  <span className="text-rose-400 block text-[10px]">Excluded URL Paths:</span>
                  <span className="text-rose-300 break-all">
                    {currentTarget.excluded_paths ? String(currentTarget.excluded_paths) : 'None'}
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* ── Section 2: AI Assessment Planner & Requirements ── */}
        <div className="p-5 rounded-2xl bg-navy-900/90 border border-slate-800 shadow-xl space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Bot className="w-4 h-4 text-cyan-400" />
              <h2 className="text-sm font-semibold text-slate-100 font-mono">
                2. AI ASSESSMENT PLANNER & REQUIREMENTS
              </h2>
            </div>
            <span className="text-[11px] font-mono text-cyan-400">
              Deterministic & LLM Supported
            </span>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              Natural Language Assessment Objectives & Scope Requirements
            </label>
            <textarea
              rows={3}
              value={requirements}
              onChange={(e) => setRequirements(e.target.value)}
              placeholder="e.g. Focus on web APIs, check for outdated TLS protocols, perform non-destructive spidering, and flag dangerous headers."
              className="w-full px-3 py-2 text-xs rounded-xl bg-navy-950 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-400 font-sans leading-relaxed"
            />
          </div>

          {/* Permitted Categories */}
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-2">
              Permitted Assessment Categories
            </label>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
              {[
                { id: 'network_discovery', label: 'Network Discovery (Nmap)' },
                { id: 'server_config', label: 'Server Config (Nikto)' },
                { id: 'web_vapt', label: 'Web DAST (OWASP ZAP)' },
                { id: 'tls_audit', label: 'TLS / Crypto Audit' },
              ].map((cat) => {
                const checked = selectedCategories.includes(cat.id)
                return (
                  <button
                    key={cat.id}
                    type="button"
                    onClick={() => toggleCategory(cat.id)}
                    className={clsx(
                      'p-2.5 rounded-xl border text-left transition-all font-mono text-[11px] flex items-center justify-between',
                      checked
                        ? 'bg-cyan-500/10 border-cyan-500/40 text-cyan-300 shadow-glow-cyan'
                        : 'bg-navy-950 border-slate-800 text-slate-400 hover:text-slate-200'
                    )}
                  >
                    <span>{cat.label}</span>
                    {checked && <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />}
                  </button>
                )
              })}
            </div>
          </div>

          <div className="flex justify-end pt-1">
            <button
              type="button"
              onClick={handleGeneratePlan}
              disabled={planning || !isTargetActive}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 text-white font-bold text-xs shadow-glow-cyan transition-all"
            >
              {planning ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Sparkles className="w-3.5 h-3.5" />}
              <span>Generate AI Assessment Plan</span>
            </button>
          </div>

          {/* Render Generated Plan Preview */}
          {generatedPlan && (
            <div className="mt-4 p-4 rounded-xl bg-navy-950 border border-cyan-500/30 text-xs space-y-3 font-sans">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-cyan-300 font-bold font-mono">
                  <ShieldCheck className="w-4 h-4 text-cyan-400" />
                  <span>AI Plan Generated ({generatedPlan.stages.length} Ordered Stages)</span>
                </div>
                <button
                  type="button"
                  onClick={() => setViewingDecisions(generatedPlan.decisions)}
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 font-mono text-[11px] border border-slate-700"
                >
                  Review Decision Trace ({generatedPlan.decisions.length})
                </button>
              </div>

              <p className="text-slate-300">{generatedPlan.summary}</p>

              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2 text-[11px] pt-1">
                {generatedPlan.stages.map((stage) => (
                  <div key={stage.stage_number} className="p-2.5 rounded-lg bg-navy-900 border border-slate-800">
                    <div className="flex items-center justify-between font-mono mb-1">
                      <span className="text-cyan-400 font-bold">Stage {stage.stage_number}</span>
                      {stage.requires_human_approval && (
                        <span className="text-[10px] text-amber-400 font-bold">APPROVAL REQ</span>
                      )}
                    </div>
                    <p className="font-semibold text-slate-200 truncate">{stage.name}</p>
                    <p className="text-slate-400 text-[10px] truncate">{stage.recommended_tools.join(', ')}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* ── Section 3: Assessment Engagement Settings ────────── */}
        <div className="p-5 rounded-2xl bg-navy-900/90 border border-slate-800 shadow-xl space-y-4">
          <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
            <Layers className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-semibold text-slate-100 font-mono">
              3. ASSESSMENT CONFIGURATION
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Assessment Name *
              </label>
              <input
                type="text"
                required
                value={assessmentName}
                onChange={(e) => setAssessmentName(e.target.value)}
                placeholder="e.g. Q4 Staging Infrastructure Security Audit"
                className="w-full px-3 py-2 text-xs rounded-xl bg-navy-950 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-400"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Assessment Type
              </label>
              <select
                value={assessmentType}
                onChange={(e) => setAssessmentType(e.target.value)}
                className="w-full px-3 py-2 text-xs rounded-xl bg-navy-950 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-400"
              >
                <option value="full_vapt">Full VAPT (Network + Web Application)</option>
                <option value="web_application">Web Application Vulnerability Scan (OWASP ZAP / Nikto)</option>
                <option value="network_infrastructure">Network Port & Service Discovery (Nmap)</option>
                <option value="compliance_baseline">CIS / Compliance Baseline Check</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Lead Analyst / Operator
              </label>
              <input
                type="text"
                value={createdBy}
                onChange={(e) => setCreatedBy(e.target.value)}
                placeholder="lead_analyst"
                className="w-full px-3 py-2 text-xs rounded-xl bg-navy-950 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-400 font-mono"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Engagement Description (Optional)
              </label>
              <input
                type="text"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Scope boundaries, audit objectives, and stakeholder expectations"
                className="w-full px-3 py-2 text-xs rounded-xl bg-navy-950 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-400"
              />
            </div>
          </div>
        </div>

        {/* ── Submit Action ───────────────────────────────────── */}
        <div className="flex items-center justify-between pt-2">
          <Link
            to="/"
            className="px-4 py-2 text-xs font-semibold rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700"
          >
            Cancel
          </Link>

          <button
            type="submit"
            disabled={submitting || !isTargetActive || (validationResult !== null && !validationResult.allowed)}
            className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:opacity-40 disabled:cursor-not-allowed text-navy-950 font-bold text-xs shadow-glow-cyan transition-all"
          >
            <Play className="w-4 h-4 fill-current" />
            <span>{submitting ? 'Verifying & Initializing...' : 'Create Scoped Assessment with AI Plan'}</span>
          </button>
        </div>
      </form>

      {/* ── Decision Trace Modal ────────────────────────────────────── */}
      {viewingDecisions && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-navy-950/80 backdrop-blur-sm overflow-y-auto">
          <div className="relative w-full max-w-3xl my-8 p-6 rounded-2xl bg-navy-900 border border-slate-700 shadow-2xl space-y-4 text-xs font-sans">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <h3 className="text-base font-bold text-slate-100 font-mono">
                  DECISION TRACE & REASONING AUDIT
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setViewingDecisions(null)}
                className="text-slate-400 hover:text-slate-100 text-sm p-1"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 max-h-[60vh] overflow-y-auto pr-1">
              {viewingDecisions.map((dec, idx) => (
                <div key={dec.id || idx} className="p-3.5 rounded-xl bg-navy-950 border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between font-mono text-[11px]">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-bold">
                        {dec.selected_tool}
                      </span>
                      <span className="text-slate-400 font-semibold">{dec.stage}</span>
                    </div>
                    <span
                      className={clsx(
                        'px-2 py-0.5 rounded text-[10px] font-bold border',
                        dec.execution_status === 'PLANNED'
                          ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                          : 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                      )}
                    >
                      {dec.execution_status}
                    </span>
                  </div>

                  <p className="text-slate-300 font-medium">{dec.rationale}</p>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 pt-2 border-t border-slate-800/80 text-[11px]">
                    <div className="p-2 rounded bg-navy-900 border border-slate-800/80">
                      <span className="text-cyan-400 font-mono font-semibold block mb-0.5">
                        🔍 Concrete Observations:
                      </span>
                      <span className="text-slate-300">{dec.evidence_and_observations}</span>
                    </div>
                    <div className="p-2 rounded bg-navy-900 border border-slate-800/80">
                      <span className="text-amber-400 font-mono font-semibold block mb-0.5">
                        🧠 AI Inference:
                      </span>
                      <span className="text-slate-300">{dec.ai_inferences}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            <div className="flex justify-end pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setViewingDecisions(null)}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300"
              >
                Close Trace
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
