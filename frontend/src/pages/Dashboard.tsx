import { useState, useEffect, useCallback } from 'react'
import {
  RefreshCw,
  ServerOff,
  AlertTriangle,
  Clock,
  ShieldAlert,
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
