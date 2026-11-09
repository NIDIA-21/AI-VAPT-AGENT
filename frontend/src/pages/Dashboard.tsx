import { useState, useEffect, useCallback } from 'react'
import {
  RefreshCw,
  ServerOff,
  AlertTriangle,
  Clock,
  ShieldAlert,
  CheckCircle2,
  ArrowRight,
  Shield,
  Layers,
} from 'lucide-react'
import type {
  DashboardStats,
  DashboardSeverityResponse,
  DashboardActivityResponse,
  ToolStatusItem,
} from '@/types'
import { dashboardApi } from '@/services/api'
import MetricCards from '@/components/dashboard/MetricCards'
import QuickActions from '@/components/dashboard/QuickActions'
import SeverityChart from '@/components/dashboard/SeverityChart'
import AssessmentActivityTable from '@/components/dashboard/AssessmentActivityTable'
import ToolIntegrationsGrid from '@/components/dashboard/ToolIntegrationsGrid'
import AgentActivityPanel from '@/components/dashboard/AgentActivityPanel'
import { clsx } from 'clsx'

const DEFAULT_STATS: DashboardStats = {
  total_assessments: 0,
  active_scans: 0,
  total_vulnerabilities: 0,
  critical_vulnerabilities: 0,
  active_assessments: 0,
  authorized_targets: 0,
  total_findings: 0,
  pending_approvals: 0,
  recent_scans: 0,
  severity_breakdown: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
}

const DEFAULT_SEVERITY: DashboardSeverityResponse = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  informational: 0,
  total: 0,
}

const DEFAULT_ACTIVITY: DashboardActivityResponse = {
  assessments: [],
  agent_activities: [],
  timestamp: new Date().toISOString(),
}

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats>(DEFAULT_STATS)
  const [severity, setSeverity] = useState<DashboardSeverityResponse>(DEFAULT_SEVERITY)
  const [activity, setActivity] = useState<DashboardActivityResponse>(DEFAULT_ACTIVITY)
  const [tools, setTools] = useState<ToolStatusItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [lastRefreshed, setLastRefreshed] = useState<Date | null>(null)

  const fetchDashboardData = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [statsRes, severityRes, activityRes, toolsRes] = await Promise.all([
        dashboardApi.stats(),
        dashboardApi.severity(),
        dashboardApi.activity(),
        dashboardApi.tools(),
      ])

      setStats(statsRes)
      setSeverity(severityRes)
      setActivity(activityRes)
      setTools(toolsRes.tools)
      setLastRefreshed(new Date())
    } catch (err: any) {
      setError(
        err?.userMessage ??
          'Unable to connect to the AI-VAPT Agent backend API. Ensure the FastAPI service is running on port 8000.'
      )
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchDashboardData()
  }, [fetchDashboardData])

  return (
    <div className="space-y-6 animate-fade-in pb-10">
      {/* ── Top Header Bar ───────────────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-bold text-slate-100 tracking-tight flex items-center gap-2">
            <span>Security Operations Dashboard</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Real-time vulnerability assessment, scanner telemetry, and AI security orchestration
          </p>
        </div>

        <div className="flex items-center gap-3 self-start sm:self-auto">
          {lastRefreshed && (
            <span className="text-[11px] font-mono text-slate-400 flex items-center gap-1.5">
              <Clock className="w-3 h-3 text-cyan-400" />
              <span>Synced {lastRefreshed.toLocaleTimeString()}</span>
            </span>
          )}

          <button
            onClick={fetchDashboardData}
            disabled={loading}
            className="btn-secondary text-xs py-2 px-3 flex items-center gap-1.5"
            title="Refresh all metrics from backend"
          >
            <RefreshCw className={clsx('w-3.5 h-3.5', loading && 'animate-spin text-cyan-400')} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* ── Error Notification ───────────────────────────────────────────── */}
      {error && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 flex items-start justify-between gap-3 shadow-glow-red animate-fade-in">
          <div className="flex items-start gap-3">
            <ServerOff className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-xs font-bold uppercase tracking-wider text-red-300">
                Backend Connection Error
              </p>
              <p className="text-xs text-red-400/90 mt-1 leading-relaxed">{error}</p>
            </div>
          </div>
          <button
            onClick={fetchDashboardData}
            className="px-3 py-1.5 rounded-lg bg-red-500/20 hover:bg-red-500/30 text-red-200 border border-red-500/40 text-xs font-semibold flex-shrink-0 transition-colors"
          >
            Retry
          </button>
        </div>
      )}

      {/* ── Module 8: Quick Actions ──────────────────────────────────────── */}
      <QuickActions />

      {/* ── Module 3: Primary Metric Cards ───────────────────────────────── */}
      <MetricCards stats={stats} loading={loading} />

      {/* ── End-to-End Assessment Workflow Progress Indicator ────────── */}
      <div className="card border-cyan-500/20 bg-navy-800">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-slate-800/80 mb-3 gap-2">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            <h3 className="text-xs font-mono font-bold tracking-wider text-slate-200 uppercase">
              End-to-End Assessment Lifecycle Workflow
            </h3>
          </div>
          <span className="text-[11px] font-mono text-cyan-400">
            {stats.total_findings === 0 ? 'STATUS: AWAITING SCANNER EVIDENCE' : `ACTIVE TELEMETRY: ${stats.total_findings} FINDINGS`}
          </span>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          {[
            {
              step: '1',
              title: 'TARGET REGISTRATION',
              status: stats.authorized_targets > 0 ? 'COMPLETE' : 'PENDING',
              badge: `${stats.authorized_targets} Authorized`,
              done: stats.authorized_targets > 0,
            },
            {
              step: '2',
              title: 'AI PLANNING',
              status: stats.total_assessments > 0 ? 'COMPLETE' : 'PENDING',
              badge: `${stats.total_assessments} Plans Built`,
              done: stats.total_assessments > 0,
            },
            {
              step: '3',
              title: 'SCANNER EXECUTION / IMPORT',
              status: stats.recent_scans > 0 || stats.active_scans > 0 ? 'ACTIVE' : 'AWAITING EVIDENCE',
              badge: stats.recent_scans > 0 ? `${stats.recent_scans} Jobs Run` : 'Awaiting Ingestion',
              done: stats.recent_scans > 0,
              highlight: stats.recent_scans === 0,
            },
            {
              step: '4',
              title: 'VULNERABILITY ANALYSIS',
              status: stats.total_findings > 0 ? 'PROCESSED' : 'STANDBY',
              badge: `${stats.total_findings} Normalized`,
              done: stats.total_findings > 0,
            },
            {
              step: '5',
              title: 'HUMAN REVIEW',
              status: stats.pending_approvals > 0 ? 'ACTION REQUIRED' : 'GATED',
              badge: `${stats.pending_approvals} Pending Sign-off`,
              done: stats.pending_approvals === 0 && stats.total_assessments > 0,
            },
            {
              step: '6',
              title: 'REPORT GENERATION',
              status: stats.total_assessments > 0 ? 'READY' : 'STANDBY',
              badge: 'PDF Generator Active',
              done: stats.total_assessments > 0,
            },
          ].map((item) => (
            <div
              key={item.title}
              className={clsx(
                'p-3 rounded-lg border text-xs flex flex-col justify-between transition-all',
                item.done
                  ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                  : item.highlight
                  ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-300 shadow-glow-cyan'
                  : 'bg-navy-900 border-slate-800 text-slate-400'
              )}
            >
              <div className="flex items-center justify-between mb-1.5 font-mono text-[10px]">
                <span className="font-bold">STEP 0{item.step}</span>
                {item.done ? (
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                ) : (
                  <Clock className="w-3.5 h-3.5 text-slate-500" />
                )}
              </div>
              <p className="font-bold text-[11px] text-slate-100 leading-tight mb-1.5">{item.title}</p>
              <div className="mt-auto pt-1.5 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono">
                <span className={item.done ? 'text-emerald-400' : item.highlight ? 'text-cyan-400 font-bold' : 'text-slate-500'}>
                  {item.status}
                </span>
                <span className="text-slate-400 truncate max-w-[80px]" title={item.badge}>
                  {item.badge}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── Middle Row: Vulnerability Chart + AI Agent Activity ──────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        {/* Module 4: Vulnerability Severity Chart */}
        <div className="lg:col-span-3 card">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
            <div>
              <h3 className="section-title text-sm flex items-center gap-2">
                <span>Vulnerability Severity Breakdown</span>
                <span className="text-xs font-mono font-normal text-slate-400">
                  ({severity.total} findings)
                </span>
              </h3>
              <p className="section-subtitle text-[11px]">
                CVSS-rated distribution across normalized scanner telemetry
              </p>
            </div>
          </div>

          <SeverityChart
            data={{
              critical: severity.critical,
              high: severity.high,
              medium: severity.medium,
              low: severity.low,
              informational: severity.informational,
            }}
            loading={loading}
          />
        </div>

        {/* Module 7: AI Agent Activity Stream */}
        <div className="lg:col-span-2">
          <AgentActivityPanel activities={activity.agent_activities} loading={loading} />
        </div>
      </div>

      {/* ── Module 5: Assessment Activity Table ──────────────────────────── */}
      <AssessmentActivityTable assessments={activity.assessments} loading={loading} />

      {/* ── Module 6: Scanner Integration Status Grid ────────────────────── */}
      <ToolIntegrationsGrid tools={tools} loading={loading} />
    </div>
  )
}
