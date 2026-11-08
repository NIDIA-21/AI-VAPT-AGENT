import { useState, useEffect } from 'react'
import {
  FileSearch,
  Sparkles,
  Link as LinkIcon,
  AlertOctagon,
  CheckCircle,
  FileCode,
  Shield,
  Layers,
  Terminal,
  RefreshCw,
  Clock,
  ArrowRight,
  ListOrdered,
} from 'lucide-react'
import type { Assessment, CorrelationResult, Finding } from '@/types'
import { assessmentsApi, findingsApi } from '@/services/api'
import { clsx } from 'clsx'

export default function Evidence() {
  const [assessments, setAssessments] = useState<Assessment[]>([])
  const [selectedAssessmentId, setSelectedAssessmentId] = useState<string>('')
  const [findings, setFindings] = useState<Finding[]>([])
  const [correlation, setCorrelation] = useState<CorrelationResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [correlating, setCorrelating] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Raw artifact inspection state
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null)
  const [evidenceData, setEvidenceData] = useState<any>(null)
  const [loadingEvidence, setLoadingEvidence] = useState(false)

  useEffect(() => {
    loadAssessments()
  }, [])

  const loadAssessments = async () => {
    try {
      setLoading(true)
      const data = await assessmentsApi.list()
      setAssessments(data)
      if (data.length > 0) {
        setSelectedAssessmentId(data[0].id)
        loadAssessmentFindings(data[0].id)
      }
    } catch (err: any) {
      setError(err?.userMessage || 'Failed to load assessments.')
    } finally {
      setLoading(false)
    }
  }

  const loadAssessmentFindings = async (assessmentId: string) => {
    try {
      setLoading(true)
      const data = await findingsApi.list({ assessment_id: assessmentId })
      setFindings(data)
    } catch (err: any) {
      setError(err?.userMessage || 'Failed to load findings for assessment.')
    } finally {
      setLoading(false)
    }
  }

  const handleSelectAssessment = (id: string) => {
    setSelectedAssessmentId(id)
    setCorrelation(null)
    setExpandedFindingId(null)
    setEvidenceData(null)
    loadAssessmentFindings(id)
  }

  const handleRunCorrelation = async () => {
    if (!selectedAssessmentId) return
    setCorrelating(true)
    setError(null)
    try {
      const res = await findingsApi.correlate({ assessment_id: selectedAssessmentId })
      setCorrelation(res)
    } catch (err: any) {
      setError(err?.userMessage || 'Correlation engine encountered an error.')
    } finally {
      setCorrelating(false)
    }
  }

  const inspectEvidence = async (findingId: string) => {
    if (expandedFindingId === findingId) {
      setExpandedFindingId(null)
      setEvidenceData(null)
      return
    }
    setExpandedFindingId(findingId)
    setLoadingEvidence(true)
    try {
      const data = await findingsApi.getEvidence(findingId)
      setEvidenceData(data)
    } catch (err: any) {
      alert(err?.userMessage || 'Failed to load raw evidence.')
    } finally {
      setLoadingEvidence(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
            <FileSearch className="w-6 h-6 text-cyan-400" />
            Evidence Explorer & Multi-Tool Correlation Engine
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Analyze raw scanner traces, map composite attack chains, and inspect preserved evidence without cross-tool data loss.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <select
            value={selectedAssessmentId}
            onChange={(e) => handleSelectAssessment(e.target.value)}
            className="input-field text-xs py-2 max-w-xs"
            disabled={loading || correlating}
          >
            {assessments.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name} ({a.status})
              </option>
            ))}
          </select>

          <button
            onClick={handleRunCorrelation}
            disabled={correlating || !selectedAssessmentId || findings.length === 0}
            className="btn-primary flex items-center gap-2 text-xs px-3 py-2 bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 shadow-glow-cyan"
          >
            <Sparkles className={clsx('w-3.5 h-3.5', correlating && 'animate-spin')} />
            {correlating ? 'Correlating Scanners...' : 'Run Cross-Tool Correlation'}
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded text-rose-300 text-xs">
          {error}
        </div>
      )}

      {/* AI Cross-Tool Correlation Results View */}
      {correlation && (
        <div className="card p-6 space-y-6 border-cyan-500/30 bg-slate-900/60 shadow-2xl">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <span className="text-xs uppercase font-mono tracking-wider text-cyan-400 font-semibold flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5" />
                Cross-Tool Attack Intelligence Analysis
              </span>
              <h2 className="text-base font-bold text-slate-100 mt-1">
                Target: {correlation.target_host} ({correlation.total_findings} Correlated Findings)
              </h2>
            </div>
            <div className="text-right">
              <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                Engine: {correlation.engine}
              </span>
            </div>
          </div>

          {/* Analyst Summary */}
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 leading-relaxed font-sans">
            <span className="font-semibold text-cyan-400 block mb-1">Executive Analyst Summary:</span>
            {correlation.analyst_summary}
          </div>

          {/* Attack Chains */}
          {correlation.attack_chains.length > 0 && (
            <div className="space-y-3">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <LinkIcon className="w-4 h-4 text-rose-400" />
                Discovered Attack Vectors & Composite Chains
              </h3>
              <div className="space-y-3">
                {correlation.attack_chains.map((chain) => (
                  <div key={chain.chain_id} className="p-4 rounded bg-slate-950 border border-slate-800 space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-200 text-sm">{chain.title}</span>
                      <span className="px-2 py-0.5 rounded text-xs font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30">
                        {chain.severity}
                      </span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2">
                      {chain.steps.map((st, i) => (
                        <div key={i} className="p-3 rounded bg-slate-900 border border-slate-800 text-xs space-y-1">
                          <div className="text-cyan-400 font-semibold">{st.stage}</div>
                          <div className="text-slate-300 font-mono text-[11px]">{st.observation}</div>
                          {st.inference && (
                            <div className="text-indigo-300 text-[11px] italic mt-1">
                              AI Inference: {st.inference}
                            </div>
                          )}
                          <div className="text-[10px] text-slate-500 font-mono pt-1">
                            Source: {st.source}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Suspicious Contradictions / False Positives */}
          {correlation.suspicious_false_positives.length > 0 && (
            <div className="space-y-2">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-amber-400 flex items-center gap-1.5">
                <AlertOctagon className="w-4 h-4" />
                Cross-Scanner Contradictions Flagged for Analyst Review
              </h3>
              <div className="space-y-2">
                {correlation.suspicious_false_positives.map((s, idx) => (
                  <div key={idx} className="p-3 rounded bg-amber-500/10 border border-amber-500/30 text-xs text-amber-200 space-y-1">
                    <div className="font-semibold text-amber-300">
                      Discrepancy: {s.finding_title} (Reported by {s.source_tool} on Port {s.port})
                    </div>
                    <div><strong>Observed Evidence:</strong> {s.observed_evidence}</div>
                    <div><strong>AI Inference:</strong> {s.ai_inference}</div>
                    <div className="text-amber-400/90 text-[11px]"><strong>Action:</strong> {s.recommended_action}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Remediation Roadmap */}
          {correlation.remediation_roadmap.length > 0 && (
            <div className="space-y-2">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <ListOrdered className="w-4 h-4 text-emerald-400" />
                Prioritized Remediation Roadmap
              </h3>
              <div className="divide-y divide-slate-800 border border-slate-800 rounded bg-slate-950 overflow-hidden text-xs">
                {correlation.remediation_roadmap.map((item) => (
                  <div key={item.priority_rank} className="p-3 flex items-start gap-3 hover:bg-slate-900/50 transition-colors">
                    <span className="w-6 h-6 rounded-full bg-cyan-500/20 text-cyan-400 font-bold flex items-center justify-center flex-shrink-0 text-xs">
                      #{item.priority_rank}
                    </span>
                    <div className="flex-1 space-y-0.5">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-slate-200">{item.title}</span>
                        <span className="text-[11px] font-mono text-slate-500">[{item.target}]</span>
                      </div>
                      <p className="text-slate-400 text-xs">{item.remediation_action}</p>
                    </div>
                    <div className="text-right">
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-rose-300">
                        Risk {item.risk_score}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Raw Evidence Artifacts Explorer */}
      <div className="card overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-slate-200">
              Preserved Scanner Traces & Raw Artifacts ({findings.length} findings)
            </h3>
          </div>
          <span className="text-xs text-slate-500 font-mono">
            Click any finding to inspect verified scanner payloads
          </span>
        </div>

        {findings.length === 0 ? (
          <div className="p-12 text-center text-slate-500 text-xs">
            No findings recorded for this assessment. Select another assessment or run a scan.
          </div>
        ) : (
          <div className="divide-y divide-slate-800 text-xs">
            {findings.map((f) => (
              <div key={f.id} className="transition-colors">
                <div
                  onClick={() => inspectEvidence(f.id)}
                  className="p-3 hover:bg-slate-800/40 cursor-pointer flex items-center justify-between gap-3"
                >
                  <div className="flex items-center gap-3">
                    <FileCode className="w-4 h-4 text-slate-400 flex-shrink-0" />
                    <div>
                      <span className="font-semibold text-slate-200">{f.title}</span>
                      <div className="text-[11px] text-slate-500 font-mono mt-0.5">
                        Tools: {f.source_tool} | Target: {f.host}:{f.port || '—'} {f.url_path || ''}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-cyan-400">
                      {f.confidence || 'Medium'} Confidence
                    </span>
                    <button className="btn-secondary text-[11px] px-2 py-1">
                      {expandedFindingId === f.id ? 'Collapse' : 'Inspect Traces'}
                    </button>
                  </div>
                </div>

                {/* Expanded Raw Evidence Drawer */}
                {expandedFindingId === f.id && (
                  <div className="p-4 bg-slate-950 border-t border-slate-800 space-y-3">
                    {loadingEvidence ? (
                      <div className="p-4 text-center text-slate-400 flex items-center justify-center gap-2">
                        <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
                        Loading preserved evidence...
                      </div>
                    ) : evidenceData ? (
                      <div className="space-y-3">
                        <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
                          <span>Fingerprint: {evidenceData.fingerprint}</span>
                          <span>Artifacts Preserved: {evidenceData.artifacts_count}</span>
                        </div>

                        {evidenceData.artifacts?.map((art: any, aIdx: number) => (
                          <div key={aIdx} className="p-3 rounded bg-slate-900 border border-slate-800 space-y-1.5 font-mono text-xs">
                            <div className="flex items-center justify-between text-cyan-400 font-semibold border-b border-slate-800 pb-1">
                              <span>Tool Trace #{aIdx + 1}: {art.source_tool || art.tool}</span>
                              <span className="text-[11px] text-slate-500">{art.recorded_at}</span>
                            </div>
                            <div className="text-slate-300 whitespace-pre-wrap break-all text-[11px]">
                              {art.evidence || 'No text evidence captured.'}
                            </div>
                            {art.raw && (
                              <div className="mt-2 pt-2 border-t border-slate-800 text-[10px] text-slate-400 whitespace-pre-wrap overflow-x-auto">
                                <span className="text-slate-500 font-semibold block mb-0.5">Raw Tool Artifact Structure:</span>
                                {JSON.stringify(art.raw, null, 2)}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="text-slate-500 text-xs">No extended artifact recorded.</div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
