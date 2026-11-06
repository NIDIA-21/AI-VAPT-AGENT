"""
Dashboard endpoints for cybersecurity metrics, severity breakdowns,
activity audit trails, and scanner integrations.
All endpoints use real SQLAlchemy queries and handle empty database states cleanly.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter
from sqlalchemy import func, select

from app.database.session import AsyncSessionLocal
from app.models.models import (
    Assessment,
    AssessmentStatus,
    AuditLog,
    AuthorizedTarget,
    Finding,
    ScanJob,
    ScanStatus,
    SeverityLevel,
    TargetStatus,
)
from app.scanners.probe import probe_all_scanners
from app.schemas.schemas import (
    AgentActivityItem,
    AssessmentActivityItem,
    DashboardActivityResponse,
    DashboardSeverityResponse,
    DashboardStats,
    DashboardToolsResponse,
    SeverityCount,
    ToolStatus,
)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats():
    """
    Primary metric cards data:
    1. Total Assessments
    2. Active Scans
    3. Total Vulnerabilities
    4. Critical Vulnerabilities
    Plus auxiliary metrics.
    When database is empty, all values return 0.
    """
    async with AsyncSessionLocal() as session:
        # Total assessments
        total_assessments = (
            await session.scalar(select(func.count()).select_from(Assessment))
        ) or 0

        # Active scans
        active_scans = (
            await session.scalar(
                select(func.count())
                .select_from(ScanJob)
                .where(ScanJob.status.in_([ScanStatus.RUNNING.value, ScanStatus.QUEUED.value]))
            )
        ) or 0

        # Total vulnerabilities / findings
        total_vulnerabilities = (
            await session.scalar(select(func.count()).select_from(Finding))
        ) or 0

        # Critical vulnerabilities
        critical_vulnerabilities = (
            await session.scalar(
                select(func.count())
                .select_from(Finding)
                .where(Finding.severity == SeverityLevel.CRITICAL.value)
            )
        ) or 0

        # Active assessments
        active_assessments = (
            await session.scalar(
                select(func.count())
                .select_from(Assessment)
                .where(
                    Assessment.status.in_([
                        AssessmentStatus.RUNNING.value,
                        AssessmentStatus.PLANNING.value,
                        AssessmentStatus.APPROVED.value,
                    ])
                )
            )
        ) or 0

        # Authorized targets
        authorized_targets = (
            await session.scalar(
                select(func.count())
                .select_from(AuthorizedTarget)
                .where(
                    AuthorizedTarget.status.in_([TargetStatus.ACTIVE.value, "AUTHORIZED", "authorized"]),
                    AuthorizedTarget.is_deleted == False,
                )
            )
        ) or 0

        # Pending approvals
        pending_approvals = (
            await session.scalar(
                select(func.count())
                .select_from(Assessment)
                .where(Assessment.status == AssessmentStatus.PENDING_APPROVAL.value)
            )
        ) or 0

        # Severity breakdown
        sev_rows = (
            await session.execute(
                select(Finding.severity, func.count().label("cnt"))
                .group_by(Finding.severity)
            )
        ).all()
        sev: dict[str, int] = {row.severity: row.cnt for row in sev_rows}

    return DashboardStats(
        total_assessments=total_assessments,
        active_scans=active_scans,
        total_vulnerabilities=total_vulnerabilities,
        critical_vulnerabilities=critical_vulnerabilities,
        active_assessments=active_assessments,
        authorized_targets=authorized_targets,
        total_findings=total_vulnerabilities,
        pending_approvals=pending_approvals,
        recent_scans=active_scans,
        severity_breakdown=SeverityCount(
            critical=sev.get(SeverityLevel.CRITICAL.value, 0),
            high=sev.get(SeverityLevel.HIGH.value, 0),
            medium=sev.get(SeverityLevel.MEDIUM.value, 0),
            low=sev.get(SeverityLevel.LOW.value, 0),
            informational=sev.get(SeverityLevel.INFO.value, 0),
        ),
    )


@router.get("/severity", response_model=DashboardSeverityResponse)
async def get_dashboard_severity():
    """
    Vulnerability severity breakdown for chart visualization.
    Returns 0 for all tiers if database has no findings.
    """
    async with AsyncSessionLocal() as session:
        sev_rows = (
            await session.execute(
                select(Finding.severity, func.count().label("cnt"))
                .group_by(Finding.severity)
            )
        ).all()
        sev: dict[str, int] = {row.severity: row.cnt for row in sev_rows}

    critical = sev.get(SeverityLevel.CRITICAL.value, 0)
    high = sev.get(SeverityLevel.HIGH.value, 0)
    medium = sev.get(SeverityLevel.MEDIUM.value, 0)
    low = sev.get(SeverityLevel.LOW.value, 0)
    informational = sev.get(SeverityLevel.INFO.value, 0)
    total = critical + high + medium + low + informational

    return DashboardSeverityResponse(
        critical=critical,
        high=high,
        medium=medium,
        low=low,
        informational=informational,
        total=total,
    )


@router.get("/activity", response_model=DashboardActivityResponse)
async def get_dashboard_activity():
    """
    Returns recent assessment engagements and AI agent / system audit events.
    Returns empty lists if no assessments or events exist yet.
    """
    assessments_list: list[AssessmentActivityItem] = []
    agent_activities: list[AgentActivityItem] = []

    async with AsyncSessionLocal() as session:
        # 1. Fetch recent assessments with target info and findings count
        assessment_query = (
            select(
                Assessment,
                AuthorizedTarget.host.label("target_host"),
                func.count(Finding.id).label("findings_count"),
            )
            .join(AuthorizedTarget, Assessment.target_id == AuthorizedTarget.id, isouter=True)
            .join(Finding, Assessment.id == Finding.assessment_id, isouter=True)
            .group_by(Assessment.id, AuthorizedTarget.host)
            .order_by(Assessment.created_at.desc())
            .limit(10)
        )
        res = await session.execute(assessment_query)
        for row in res.all():
            asm, target_host, f_count = row[0], row[1], row[2]
            assessments_list.append(
                AssessmentActivityItem(
                    id=asm.id,
                    name=asm.name,
                    target_id=asm.target_id,
                    target_host=target_host or "Unknown Host",
                    assessment_type=getattr(asm, "assessment_type", None) or "Network & Web",
                    status=asm.status,
                    start_time=getattr(asm, "start_time", None) or asm.created_at,
                    findings_count=f_count or 0,
                    created_at=asm.created_at,
                )
            )

        # 2. Fetch recent audit logs for AI Agent activity stream
        audit_query = select(AuditLog).order_by(AuditLog.created_at.desc()).limit(20)
        audit_res = await session.execute(audit_query)
        for log in audit_res.scalars().all():
            action_lower = log.action.lower()
            if "plan" in action_lower:
                category = "planning"
            elif "tool" in action_lower or "scanner" in action_lower:
                category = "tool_selection"
            elif "scan" in action_lower:
                category = "scan_status"
            elif "finding" in action_lower or "analysis" in action_lower or "cve" in action_lower:
                category = "analysis"
            elif "fail" in action_lower or "warn" in action_lower or "reject" in action_lower:
                category = "warning"
            else:
                category = "system"

            if "fail" in action_lower or "reject" in action_lower:
                status = "failed"
            elif "warn" in action_lower:
                status = "warning"
            elif "authorized" in action_lower or "completed" in action_lower or "approved" in action_lower:
                status = "success"
            else:
                status = "info"

            agent_activities.append(
                AgentActivityItem(
                    id=log.id,
                    timestamp=log.created_at,
                    category=category,
                    description=log.detail or f"{log.actor}: {log.action}",
                    status=status,
                    actor=log.actor or "AI Agent",
                    resource_id=log.resource_id,
                )
            )

    return DashboardActivityResponse(
        assessments=assessments_list,
        agent_activities=agent_activities,
        timestamp=datetime.now(timezone.utc),
    )


@router.get("/tools", response_model=DashboardToolsResponse)
async def get_dashboard_tools():
    """
    Status of the 7 cybersecurity scanner integrations:
    Nmap, OWASP ZAP, Nikto, Nessus, OpenVAS, Burp Suite, Metasploit.
    Safe path checking only; no scans executed.
    """
    scanners = probe_all_scanners()
    tools = [
        ToolStatus(
            name=s.name,
            display_name=s.display_name,
            category=s.category,
            description=s.description,
            status=s.status,
            version=s.version,
            path=s.path,
            capabilities=s.capabilities,
            available=s.available,
        )
        for s in scanners
    ]
    available_count = sum(1 for t in tools if t.status == "Available")

    return DashboardToolsResponse(
        tools=tools,
        total_tools=len(tools),
        available_count=available_count,
        timestamp=datetime.now(timezone.utc),
    )
