"""Pydantic schemas for API request/response validation."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, model_validator


# ── Health ─────────────────────────────────────────────────────────────────────


class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    database: str
    timestamp: datetime
    scanner_availability: Dict[str, bool]


# ── Authorized Target ──────────────────────────────────────────────────────────


class AuthorizedTargetCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    host: str = Field(..., min_length=1, max_length=255)
    target_url: Optional[str] = None
    purpose: Optional[str] = "Vulnerability Assessment"
    description: Optional[str] = None
    auth_contact: Optional[str] = None
    auth_reference: Optional[str] = None
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    permitted_ports: Optional[Union[List[int], str]] = None
    excluded_ports: Optional[Union[List[int], str]] = None
    excluded_paths: Optional[Union[List[str], str]] = None
    restrictions: Optional[str] = None
    scope_notes: Optional[str] = None
    status: Optional[str] = "ACTIVE"
    authorized_by: Optional[str] = None


class AuthorizedTargetUpdate(BaseModel):
    name: Optional[str] = None
    host: Optional[str] = None
    target_url: Optional[str] = None
    purpose: Optional[str] = None
    description: Optional[str] = None
    auth_contact: Optional[str] = None
    auth_reference: Optional[str] = None
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    permitted_ports: Optional[Union[List[int], str]] = None
    excluded_ports: Optional[Union[List[int], str]] = None
    excluded_paths: Optional[Union[List[str], str]] = None
    restrictions: Optional[str] = None
    scope_notes: Optional[str] = None
    status: Optional[str] = None
    authorized_by: Optional[str] = None


class AuthorizedTargetRevoke(BaseModel):
    revoked_by: str = Field(..., min_length=1, max_length=255)
    revocation_reason: str = Field(..., min_length=3)


class AuthorizedTargetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    host: str
    target_url: Optional[str] = None
    purpose: Optional[str] = "Vulnerability Assessment"
    description: Optional[str] = None
    auth_contact: Optional[str] = None
    auth_reference: Optional[str] = None
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    permitted_ports: Optional[str] = None
    excluded_ports: Optional[str] = None
    excluded_paths: Optional[str] = None
    restrictions: Optional[str] = None
    scope_notes: Optional[str] = None
    status: str
    authorized_by: Optional[str] = None
    authorized_at: Optional[datetime] = None
    revoked_by: Optional[str] = None
    revoked_at: Optional[datetime] = None
    revocation_reason: Optional[str] = None
    is_deleted: bool = False
    created_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class TargetOverviewStats(BaseModel):
    total: int = 0
    active: int = 0
    expired: int = 0
    revoked: int = 0
    pending: int = 0


# ── Scope Validation ───────────────────────────────────────────────────────────


class ScopeValidationRequest(BaseModel):
    requested_target: str = Field(..., min_length=1, max_length=255)
    target_id: Optional[str] = None
    requested_port: Optional[int] = None
    requested_path: Optional[str] = None
    requested_protocol: Optional[str] = None
    requested_action: Optional[str] = "assessment"


class ScopeValidationResponse(BaseModel):
    allowed: bool
    target_id: Optional[str] = None
    target_name: Optional[str] = None
    requested_target: str
    requested_port: Optional[int] = None
    requested_path: Optional[str] = None
    requested_protocol: Optional[str] = None
    reason: str
    validation_timestamp: datetime
    audit_event_id: Optional[str] = None


class ScopeAuditItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    actor: str
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    detail: Optional[str] = None
    ip_address: Optional[str] = None
    created_at: datetime
    timestamp: Optional[datetime] = None

    @model_validator(mode="after")
    def populate_timestamp(self) -> ScopeAuditItem:
        if self.timestamp is None and self.created_at is not None:
            self.timestamp = self.created_at
        return self


class ScopeAuditResponse(BaseModel):
    events: List[ScopeAuditItem]
    total_events: int
    timestamp: datetime


# ── Assessment ─────────────────────────────────────────────────────────────────


class AssessmentCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    target_id: str
    assessment_type: Optional[str] = "Network & Web"
    ai_plan: Optional[str] = None
    decision_ids: Optional[List[str]] = None
    created_by: Optional[str] = None


class AssessmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: Optional[str]
    target_id: str
    assessment_type: Optional[str] = "Network & Web"
    status: str
    ai_plan: Optional[str]
    validated_scope_snapshot: Optional[str] = None
    created_by: Optional[str]
    start_time: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


# ── Dashboard Stats ────────────────────────────────────────────────────────────


class SeverityCount(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0


class DashboardStats(BaseModel):
    # Phase 2 4 primary metric cards
    total_assessments: int = 0
    active_scans: int = 0
    total_vulnerabilities: int = 0
    critical_vulnerabilities: int = 0

    # Extended context
    active_assessments: int = 0
    authorized_targets: int = 0
    total_findings: int = 0
    pending_approvals: int = 0
    recent_scans: int = 0
    severity_breakdown: SeverityCount = Field(default_factory=SeverityCount)


class DashboardSeverityResponse(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0
    total: int = 0


# ── Tools & Scanners Status ───────────────────────────────────────────────────


class ToolStatus(BaseModel):
    name: str
    display_name: str
    category: str
    description: str
    status: str  # Available, Not Installed, Not Configured, Import Only, Planned, Unsupported
    version: Optional[str] = None
    path: Optional[str] = None
    capabilities: List[str] = Field(default_factory=list)
    available: bool = False


class DashboardToolsResponse(BaseModel):
    tools: List[ToolStatus]
    total_tools: int
    available_count: int
    timestamp: datetime


# Legacy wrapper for scanner status
class ScannerStatus(BaseModel):
    name: str
    available: bool
    version: Optional[str]
    path: Optional[str]
    description: str
    category: str


class ScannersStatusResponse(BaseModel):
    scanners: List[ScannerStatus]
    timestamp: datetime


# ── Dashboard Activity ─────────────────────────────────────────────────────────


class AssessmentActivityItem(BaseModel):
    id: str
    name: str
    target_id: str
    target_host: str
    assessment_type: str = "Network & Web"
    status: str
    start_time: Optional[datetime] = None
    findings_count: int = 0
    created_at: datetime


class AgentActivityItem(BaseModel):
    id: str
    timestamp: datetime
    category: str  # planning, tool_selection, scan_status, analysis, warning, system
    description: str
    status: str    # info, success, warning, failed
    actor: str = "AI Agent"
    resource_id: Optional[str] = None


class DashboardActivityResponse(BaseModel):
    assessments: List[AssessmentActivityItem] = Field(default_factory=list)
    agent_activities: List[AgentActivityItem] = Field(default_factory=list)
    timestamp: datetime


# ── Audit Log ──────────────────────────────────────────────────────────────────


class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    actor: str
    action: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    detail: Optional[str]
    ip_address: Optional[str]
    created_at: datetime


# ── Generic ────────────────────────────────────────────────────────────────────


class MessageResponse(BaseModel):
    message: str
    data: Optional[Any] = None


# ── Sprint 4: Conversational AI Agent & Decision Trace Schemas ────────────────


class AgentChatRequest(BaseModel):
    message: str = Field(..., min_length=1)
    session_id: Optional[str] = None
    target_id: Optional[str] = None
    user_name: Optional[str] = "security_analyst"


class AgentChatResponse(BaseModel):
    session_id: str
    message_id: str
    role: str
    content: str
    engine_info: Dict[str, Any]
    plan: Optional[Dict[str, Any]] = None
    decisions: Optional[List[Dict[str, Any]]] = None
    created_at: str


class AgentChatMessageItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    session_id: str
    role: str
    content: str
    meta_info: Optional[str] = None
    created_at: datetime


class AgentChatSessionItem(BaseModel):
    id: str
    title: str
    target_id: Optional[str] = None
    target_host: Optional[str] = None
    message_count: int = 0
    created_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class AgentChatSessionDetail(BaseModel):
    id: str
    title: str
    target_id: Optional[str] = None
    created_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    messages: List[AgentChatMessageItem] = Field(default_factory=list)


class AgentPlanRequest(BaseModel):
    target_id: str = Field(..., min_length=1)
    requirements: str = Field(default="Comprehensive vulnerability assessment with web and network discovery.")
    assessment_type: Optional[str] = "full_vapt"
    selected_categories: Optional[List[str]] = None
    operator: Optional[str] = "security_analyst"


class AgentDecisionItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    assessment_id: Optional[str] = None
    target_id: Optional[str] = None
    session_id: Optional[str] = None
    stage: str
    selected_tool: str
    rationale: str
    evidence_and_observations: str
    ai_inferences: str
    execution_status: str
    parameters: Optional[str] = None
    created_at: datetime


# ── Phase 5: Tool Integrations & Normalized Findings Schemas ─────────────────


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    assessment_id: str
    scan_job_id: Optional[str] = None
    source_tool: str
    title: str
    description: Optional[str] = None
    severity: str
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    host: Optional[str] = None
    port: Optional[int] = None
    url_path: Optional[str] = None
    service: Optional[str] = None
    evidence: Optional[str] = None
    scanner_reference: Optional[str] = None
    confidence: Optional[str] = "Medium"
    validation_status: str = "UNVALIDATED"
    fingerprint: Optional[str] = None
    risk_score: Optional[float] = None
    risk_explanation: Optional[str] = None
    raw_evidence_artifacts: Optional[str] = None
    is_false_positive: bool = False
    created_at: datetime


class FindingStatusUpdate(BaseModel):
    validation_status: str = Field(..., description="CONFIRMED, FALSE_POSITIVE, or INVESTIGATING")
    notes: Optional[str] = None


class ScanJobResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    assessment_id: str
    scanner: str
    status: str
    target_host: Optional[str] = None
    parameters: Optional[str] = None
    scope_snapshot: Optional[str] = None
    raw_output: Optional[str] = None
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    created_at: datetime
    findings_count: Optional[int] = 0


class NmapExecuteRequest(BaseModel):
    target_id: str = Field(..., description="Authorized target UUID")
    assessment_id: Optional[str] = None
    ports_override: Optional[List[int]] = None


class ReportImportRequest(BaseModel):
    target_host: str = Field(..., description="Target hostname or IP matching registered scope")
    assessment_id: Optional[str] = None
    report_content: str = Field(..., description="Raw JSON or XML report text")
    format: Optional[str] = "json"


class CorrelationRequest(BaseModel):
    assessment_id: str = Field(..., description="Assessment UUID to run multi-tool correlation against")



# ── Final Phase: Human-in-the-Loop Approval & PDF Report Schemas ─────────────


class ApprovalRequestCreate(BaseModel):
    assessment_id: str
    target_id: str
    target_host: str
    requested_action: str
    validation_purpose: str
    supporting_evidence: Optional[str] = None
    risk_information: str
    requested_by: Optional[str] = "ai_agent"


class ApprovalRequestResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    assessment_id: str
    target_id: str
    target_host: str
    requested_action: str
    validation_purpose: str
    supporting_evidence: Optional[str] = None
    risk_information: str
    requested_by: str
    status: str
    reviewed_by: Optional[str] = None
    decision_timestamp: Optional[datetime] = None
    rejection_reason: Optional[str] = None
    decision_notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class ApprovalDecisionRequest(BaseModel):
    analyst_id: str = Field(..., min_length=1, description="Analyst identity performing approval")
    notes: Optional[str] = None


class ApprovalRejectionRequest(BaseModel):
    analyst_id: str = Field(..., min_length=1, description="Analyst identity performing rejection")
    rejection_reason: str = Field(..., min_length=3, description="Mandatory rationale for rejection")
    notes: Optional[str] = None


class ReportSummaryResponse(BaseModel):
    assessment_id: str
    assessment_name: str
    target_id: str
    target_name: str
    target_host: str
    auth_reference: Optional[str] = None
    assessment_status: str
    assessment_type: str
    start_time: Optional[datetime] = None
    completion_date: Optional[datetime] = None
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    informational_findings: int
    false_positives_count: int
    confirmed_findings_count: int
    scanner_jobs: List[Dict[str, Any]]
    approvals_summary: Dict[str, int]
    assessment_limitations: str
    generated_at: datetime
