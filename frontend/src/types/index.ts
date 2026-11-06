// Application-wide TypeScript types

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'informational'
export type AssessmentStatus =
  | 'draft'
  | 'planning'
  | 'pending_approval'
  | 'approved'
  | 'running'
  | 'completed'
  | 'failed'
  | 'cancelled'
export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed' | 'skipped'
export type TargetStatus =
  | 'ACTIVE'
  | 'PENDING'
  | 'EXPIRED'
  | 'REVOKED'
  | 'pending'
  | 'authorized'
  | 'suspended'
  | 'revoked'

export type ToolIntegrationState =
  | 'Available'
  | 'Not Installed'
  | 'Not Configured'
  | 'Import Only'
  | 'Planned'
  | 'Unsupported'

// ── Health ─────────────────────────────────────────────────────────────────

export interface HealthResponse {
  status: string
  version: string
  environment: string
  database: string
  timestamp: string
  scanner_availability: Record<string, boolean>
}

// ── Tools & Scanners ────────────────────────────────────────────────────────

export interface ToolStatusItem {
  name: string
  display_name: string
  category: string
  description: string
  status: ToolIntegrationState
  version: string | null
  path: string | null
  capabilities: string[]
  available: boolean
}

export interface DashboardToolsResponse {
  tools: ToolStatusItem[]
  total_tools: number
  available_count: number
  timestamp: string
}

// Legacy alias
export interface ScannerStatus {
  name: string
  available: boolean
  version: string | null
  path: string | null
  description: string
  category: string
}

export interface ScannersStatusResponse {
  scanners: ScannerStatus[]
  timestamp: string
}

// ── Target ──────────────────────────────────────────────────────────────────

export interface AuthorizedTarget {
  id: string
  name: string
  host: string
  target_url?: string | null
  purpose?: string | null
  description?: string | null
  auth_contact?: string | null
  auth_reference?: string | null
  valid_from?: string | null
  valid_to?: string | null
  permitted_ports?: number[] | string | null
  excluded_ports?: number[] | string | null
  excluded_paths?: string[] | string | null
  restrictions?: string | null
  scope_notes?: string | null
  status: TargetStatus
  authorized_by?: string | null
  authorized_at?: string | null
  revoked_by?: string | null
  revoked_at?: string | null
  revocation_reason?: string | null
  is_deleted?: boolean
  created_by?: string | null
  created_at: string
  updated_at: string
}

export interface TargetOverviewStats {
  total_targets: number
  active_targets: number
  expired_targets: number
  revoked_targets: number
  pending_targets: number
}

export interface AuthorizedTargetCreate {
  name: string
  host: string
  target_url?: string | null
  purpose?: string | null
  description?: string | null
  auth_contact?: string | null
  auth_reference?: string | null
  valid_from?: string | null
  valid_to?: string | null
  permitted_ports?: number[] | string | null
  excluded_ports?: number[] | string | null
  excluded_paths?: string[] | string | null
  restrictions?: string | null
  status?: TargetStatus
  authorized_by?: string | null
}

export interface AuthorizedTargetUpdate {
  name?: string
  host?: string
  target_url?: string | null
  purpose?: string | null
  description?: string | null
  auth_contact?: string | null
  auth_reference?: string | null
  valid_from?: string | null
  valid_to?: string | null
  permitted_ports?: number[] | string | null
  excluded_ports?: number[] | string | null
  excluded_paths?: string[] | string | null
  restrictions?: string | null
  status?: TargetStatus
}

export interface AuthorizedTargetRevoke {
  revocation_reason: string
  revoked_by?: string
}

// ── Scope Validation ────────────────────────────────────────────────────────

export interface ScopeValidationRequest {
  requested_target: string
  requested_port?: number | null
  requested_path?: string | null
  requested_protocol?: string | null
  action_type?: string
}

export interface ScopeValidationResponse {
  allowed: boolean
  reason: string
  target_id?: string | null
  target_name?: string | null
  auth_reference?: string | null
  normalized_host?: string | null
  status?: string | null
  permitted_ports?: number[] | null
  excluded_ports?: number[] | null
  excluded_paths?: string[] | null
  restrictions?: string | null
  validated_at: string
}

export interface ScopeAuditItem {
  id: string
  timestamp: string
  actor: string
  action: string
  target_id?: string | null
  detail?: string | null
  ip_address?: string | null
}

export interface ScopeAuditResponse {
  total_events: number
  events: ScopeAuditItem[]
}

// ── Assessment ──────────────────────────────────────────────────────────────

export interface Assessment {
  id: string
  name: string
  description: string | null
  target_id: string
  assessment_type?: string
  status: AssessmentStatus
  ai_plan: string | null
  validated_scope_snapshot?: Record<string, any> | string | null
  created_by: string | null
  start_time?: string | null
  created_at: string
  updated_at: string
}

// ── Finding ─────────────────────────────────────────────────────────────────

export interface Finding {
  id: string
  assessment_id: string
  scan_job_id: string | null
  title: string
  description: string | null
  severity: SeverityLevel
  cve_id: string | null
  cvss_score: number | null
  host: string | null
  port: number | null
  service: string | null
  evidence: string | null
  ai_explanation: string | null
  is_false_positive: boolean
  created_at: string
}

// ── Dashboard Stats & Severity ──────────────────────────────────────────────

export interface SeverityCount {
  critical: number
  high: number
  medium: number
  low: number
  informational: number
}

export interface DashboardStats {
  total_assessments: number
  active_scans: number
  total_vulnerabilities: number
  critical_vulnerabilities: number
  active_assessments: number
  authorized_targets: number
  total_findings: number
  pending_approvals: number
  recent_scans: number
  severity_breakdown: SeverityCount
}

export interface DashboardSeverityResponse {
  critical: number
  high: number
  medium: number
  low: number
  informational: number
  total: number
}

// ── Dashboard Activity ──────────────────────────────────────────────────────

export interface AssessmentActivityItem {
  id: string
  name: string
  target_id: string
  target_host: string
  assessment_type: string
  status: string
  start_time: string | null
  findings_count: number
  created_at: string
}

export interface AgentActivityItem {
  id: string
  timestamp: string
  category: 'planning' | 'tool_selection' | 'scan_status' | 'analysis' | 'warning' | 'system' | string
  description: string
  status: 'info' | 'success' | 'warning' | 'failed' | string
  actor: string
  resource_id: string | null
}

export interface DashboardActivityResponse {
  assessments: AssessmentActivityItem[]
  agent_activities: AgentActivityItem[]
  timestamp: string
}

// ── Audit Log ────────────────────────────────────────────────────────────────

export interface AuditLogEntry {
  id: string
  actor: string
  action: string
  resource_type: string | null
  resource_id: string | null
  detail: string | null
  ip_address: string | null
  created_at: string
}
