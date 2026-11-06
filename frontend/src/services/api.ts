/**
 * API service layer — all backend communication goes through here.
 * The base URL is read from the Vite proxy or VITE_API_URL env var.
 * API keys are NEVER stored or transmitted from the frontend.
 */
import axios from 'axios'
import type {
  DashboardStats,
  DashboardSeverityResponse,
  DashboardActivityResponse,
  DashboardToolsResponse,
  HealthResponse,
  ScannersStatusResponse,
  AuthorizedTarget,
  TargetOverviewStats,
  AuthorizedTargetCreate,
  AuthorizedTargetUpdate,
  AuthorizedTargetRevoke,
  ScopeValidationRequest,
  ScopeValidationResponse,
  ScopeAuditResponse,
  Assessment,
} from '@/types'

const api = axios.create({
  baseURL: '/api/v1',
  timeout: 15_000,
  headers: { 'Content-Type': 'application/json' },
})

// ── Interceptors ──────────────────────────────────────────────────────────────

api.interceptors.response.use(
  (res) => res,
  (err) => {
    // Normalise error messages for UI consumption
    const detail = err?.response?.data?.detail ?? err?.message ?? 'Unknown error'
    err.userMessage = Array.isArray(detail)
      ? detail.map((d: { msg: string }) => d.msg).join('; ')
      : String(detail)
    return Promise.reject(err)
  }
)

// ── Health ─────────────────────────────────────────────────────────────────

export const healthApi = {
  check: () => api.get<HealthResponse>('/health').then((r) => r.data),
  scanners: () =>
    api.get<ScannersStatusResponse>('/health/scanners').then((r) => r.data),
}

// ── Dashboard ──────────────────────────────────────────────────────────────

export const dashboardApi = {
  stats: () =>
    api.get<DashboardStats>('/dashboard/stats').then((r) => r.data),
  severity: () =>
    api.get<DashboardSeverityResponse>('/dashboard/severity').then((r) => r.data),
  activity: () =>
    api.get<DashboardActivityResponse>('/dashboard/activity').then((r) => r.data),
  tools: () =>
    api.get<DashboardToolsResponse>('/dashboard/tools').then((r) => r.data),
}

// ── Targets ────────────────────────────────────────────────────────────────

export const targetsApi = {
  list: (params?: { status?: string; search?: string }) =>
    api.get<AuthorizedTarget[]>('/targets', { params }).then((r) => r.data),
  overviewStats: () =>
    api.get<TargetOverviewStats>('/targets/stats/overview').then((r) => r.data),
  get: (id: string) =>
    api.get<AuthorizedTarget>(`/targets/${id}`).then((r) => r.data),
  create: (payload: AuthorizedTargetCreate) =>
    api.post<AuthorizedTarget>('/targets', payload).then((r) => r.data),
  update: (id: string, payload: AuthorizedTargetUpdate) =>
    api.put<AuthorizedTarget>(`/targets/${id}`, payload).then((r) => r.data),
  revoke: (id: string, payload: AuthorizedTargetRevoke) =>
    api.post<AuthorizedTarget>(`/targets/${id}/revoke`, payload).then((r) => r.data),
  authorize: (id: string, authorizedBy = 'operator') =>
    api
      .patch<AuthorizedTarget>(`/targets/${id}/authorize`, null, {
        params: { authorized_by: authorizedBy },
      })
      .then((r) => r.data),
  delete: (id: string, hardDelete = false) =>
    api.delete(`/targets/${id}`, { params: { hard_delete: hardDelete } }).then((r) => r.data),
}

// ── Scope Validation ────────────────────────────────────────────────────────

export const scopeApi = {
  validate: (payload: ScopeValidationRequest) =>
    api.post<ScopeValidationResponse>('/scope/validate', payload).then((r) => r.data),
  audit: (params?: { target_id?: string; limit?: number; offset?: number }) =>
    api.get<ScopeAuditResponse>('/scope/audit', { params }).then((r) => r.data),
}

// ── Assessments ────────────────────────────────────────────────────────────

export const assessmentsApi = {
  list: () => api.get<Assessment[]>('/assessments').then((r) => r.data),
  create: (payload: {
    name: string
    description?: string
    target_id: string
    assessment_type?: string
    created_by?: string
  }) => api.post<Assessment>('/assessments', payload).then((r) => r.data),
  get: (id: string) => api.get<Assessment>(`/assessments/${id}`).then((r) => r.data),
  delete: (id: string) => api.delete(`/assessments/${id}`).then((r) => r.data),
}

export default api
