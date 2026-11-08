"""
ORM models — Phase 1 baseline schema.
Compatible with Python 3.14 + SQLAlchemy 2.0.36
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Float,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    return str(uuid.uuid4())


# ── Enums ─────────────────────────────────────────────────────────────────────


class TargetStatus(str, PyEnum):
    ACTIVE = "ACTIVE"
    PENDING = "PENDING"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class AssessmentStatus(str, PyEnum):
    DRAFT = "draft"
    PLANNING = "planning"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SeverityLevel(str, PyEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


class ScanStatus(str, PyEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


# ── Models ────────────────────────────────────────────────────────────────────


class AuthorizedTarget(Base):
    """Explicit allowlist of targets the operator has authorised for testing."""

    __tablename__ = "authorized_targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    target_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    purpose: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, default="Vulnerability Assessment")
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    auth_contact: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    auth_reference: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    valid_from: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    valid_to: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    permitted_ports: Mapped[Optional[str]] = mapped_column(Text, nullable=True)   # JSON string e.g. [80, 443]
    excluded_ports: Mapped[Optional[str]] = mapped_column(Text, nullable=True)    # JSON string e.g. [22, 3389]
    excluded_paths: Mapped[Optional[str]] = mapped_column(Text, nullable=True)    # JSON string e.g. ["/admin"]
    restrictions: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    scope_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default=TargetStatus.PENDING.value)
    authorized_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    authorized_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    assessments: Mapped[list["Assessment"]] = relationship(
        back_populates="target", cascade="all, delete-orphan", lazy="selectin"
    )

    __table_args__ = (UniqueConstraint("host", name="uq_target_host"),)


class Assessment(Base):
    """A single VAPT engagement scoped to one authorised target."""

    __tablename__ = "assessments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    target_id: Mapped[str] = mapped_column(ForeignKey("authorized_targets.id"))
    assessment_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, default="Network & Web")
    status: Mapped[str] = mapped_column(String(32), default=AssessmentStatus.DRAFT.value)
    ai_plan: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    validated_scope_snapshot: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    start_time: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    target: Mapped["AuthorizedTarget"] = relationship(back_populates="assessments")
    scans: Mapped[list["ScanJob"]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )
    approvals: Mapped[list["ApprovalRequest"]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan", lazy="selectin"
    )


class ScanJob(Base):
    """Individual scanner execution within an assessment."""

    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id"))
    scanner: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default=ScanStatus.QUEUED.value)
    target_host: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    parameters: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    scope_snapshot: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    raw_output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    assessment: Mapped["Assessment"] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan_job", cascade="all, delete-orphan"
    )


class Finding(Base):
    """Normalised vulnerability / observation from a scanner."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id"))
    scan_job_id: Mapped[Optional[str]] = mapped_column(ForeignKey("scan_jobs.id"), nullable=True)
    source_tool: Mapped[str] = mapped_column(String(64), default="Nmap")
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(32), default=SeverityLevel.INFO.value)
    cve_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    cwe_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    host: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    url_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    service: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    scanner_reference: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    confidence: Mapped[Optional[str]] = mapped_column(String(32), default="Medium")
    validation_status: Mapped[str] = mapped_column(String(64), default="UNVALIDATED")
    fingerprint: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    risk_explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    raw_evidence_artifacts: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    assessment: Mapped["Assessment"] = relationship(back_populates="findings")
    scan_job: Mapped[Optional["ScanJob"]] = relationship(back_populates="findings")


class AuditLog(Base):
    """Immutable audit trail for all security-relevant actions."""

    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    resource_type: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    resource_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ── Sprint 4: Conversational AI Agent & Decision Trace Models ─────────────────


class AgentChatSession(Base):
    """Conversational session between security analyst and AI assistant."""

    __tablename__ = "agent_chat_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    title: Mapped[str] = mapped_column(String(255), default="New Assessment Planning Session")
    target_id: Mapped[Optional[str]] = mapped_column(ForeignKey("authorized_targets.id"), nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, default="analyst")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    messages: Mapped[list["AgentChatMessage"]] = relationship(
        back_populates="session", cascade="all, delete-orphan", lazy="selectin", order_by="AgentChatMessage.created_at"
    )


class AgentChatMessage(Base):
    """A message in an AI agent chat conversation."""

    __tablename__ = "agent_chat_messages"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    session_id: Mapped[str] = mapped_column(ForeignKey("agent_chat_sessions.id"))
    role: Mapped[str] = mapped_column(String(32), nullable=False)  # user, assistant, system
    content: Mapped[str] = mapped_column(Text, nullable=False)
    meta_info: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON metadata (plan, tools, engine)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    session: Mapped["AgentChatSession"] = relationship(back_populates="messages")


class AgentDecision(Base):
    """Explicit decision trace generated by AI Agent and assessment planner."""

    __tablename__ = "agent_decisions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    assessment_id: Mapped[Optional[str]] = mapped_column(ForeignKey("assessments.id"), nullable=True)
    target_id: Mapped[Optional[str]] = mapped_column(ForeignKey("authorized_targets.id"), nullable=True)
    session_id: Mapped[Optional[str]] = mapped_column(ForeignKey("agent_chat_sessions.id"), nullable=True)
    stage: Mapped[str] = mapped_column(String(64), nullable=False)  # RECONNAISSANCE, PORT_DISCOVERY, etc.
    selected_tool: Mapped[str] = mapped_column(String(64), nullable=False)  # Nmap, OWASP ZAP, Nikto, etc.
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_and_observations: Mapped[str] = mapped_column(Text, nullable=False)  # Concrete observations
    ai_inferences: Mapped[str] = mapped_column(Text, nullable=False)  # Deductions
    execution_status: Mapped[str] = mapped_column(String(32), default="PLANNED")  # PLANNED, PENDING_APPROVAL, etc.
    parameters: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON config
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ApprovalStatus(str, PyEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class ApprovalRequest(Base):
    """Human-in-the-loop review and approval workflow for validation actions."""

    __tablename__ = "approval_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id"))
    target_id: Mapped[str] = mapped_column(ForeignKey("authorized_targets.id"))
    target_host: Mapped[str] = mapped_column(String(255), nullable=False)
    requested_action: Mapped[str] = mapped_column(String(128), nullable=False)
    validation_purpose: Mapped[str] = mapped_column(Text, nullable=False)
    supporting_evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    risk_information: Mapped[str] = mapped_column(Text, nullable=False)
    requested_by: Mapped[str] = mapped_column(String(255), default="ai_agent")
    status: Mapped[str] = mapped_column(String(32), default=ApprovalStatus.PENDING.value)

    reviewed_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    decision_timestamp: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    rejection_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    decision_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    assessment: Mapped["Assessment"] = relationship(back_populates="approvals", lazy="selectin")
    target: Mapped["AuthorizedTarget"] = relationship(lazy="selectin")
