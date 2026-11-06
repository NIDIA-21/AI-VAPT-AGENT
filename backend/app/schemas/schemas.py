"""Pydantic schemas for API request/response validation."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field


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
