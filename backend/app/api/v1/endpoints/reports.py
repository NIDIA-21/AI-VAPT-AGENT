"""
VAPT Assessment Reporting API Endpoints.
Provides report summaries and generates audit-grade PDF reports directly from actual stored findings.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.models.models import (
    ApprovalRequest,
    Assessment,
    AuthorizedTarget,
    Finding,
    ScanJob,
)
from app.reports.pdf_generator import VAPTReportGenerator
from app.schemas.schemas import ReportSummaryResponse

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/assessments", response_model=List[Dict[str, Any]])
async def list_reportable_assessments(
    db: AsyncSession = Depends(get_db),
):
    """
    Returns list of all assessments with target name and findings count.
    """
    q = (
        select(Assessment, AuthorizedTarget)
        .join(AuthorizedTarget, Assessment.target_id == AuthorizedTarget.id)
        .order_by(Assessment.created_at.desc())
    )
    res = await db.execute(q)
    rows = res.all()

    result = []
    for a, t in rows:
        cnt_q = select(func.count(Finding.id)).where(Finding.assessment_id == a.id)
        cnt = (await db.execute(cnt_q)).scalar() or 0
        result.append({
            "id": a.id,
            "name": a.name,
            "target_id": t.id,
            "target_name": t.name,
            "target_host": t.host,
            "status": a.status,
            "findings_count": cnt,
            "created_at": a.created_at,
        })
    return result


@router.get("/assessments/{assessment_id}/summary", response_model=ReportSummaryResponse)
async def get_report_summary(
    assessment_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Returns comprehensive report metadata, severity counts, and scanner statistics.
    All data derived strictly from actual database records.
    """
    assessment = await db.get(Assessment, assessment_id)
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment '{assessment_id}' not found.",
        )

    target = await db.get(AuthorizedTarget, assessment.target_id)
    if not target:
        target = (await db.scalars(select(AuthorizedTarget).where(AuthorizedTarget.is_deleted == False))).first()
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target '{assessment.target_id}' not found.",
        )

    # Fetch findings
    f_res = await db.execute(select(Finding).where(Finding.assessment_id == assessment.id))
    findings = f_res.scalars().all()

    # Fetch scan jobs
    s_res = await db.execute(select(ScanJob).where(ScanJob.assessment_id == assessment.id).order_by(ScanJob.created_at.desc()))
    scans = s_res.scalars().all()

    # Fetch approvals
    a_res = await db.execute(select(ApprovalRequest).where(ApprovalRequest.assessment_id == assessment.id))
    approvals = a_res.scalars().all()

    crit = sum(1 for f in findings if f.severity.lower() == "critical" and not f.is_false_positive)
    high = sum(1 for f in findings if f.severity.lower() == "high" and not f.is_false_positive)
    med = sum(1 for f in findings if f.severity.lower() == "medium" and not f.is_false_positive)
    low = sum(1 for f in findings if f.severity.lower() == "low" and not f.is_false_positive)
    info = sum(1 for f in findings if f.severity.lower() in ["info", "informational"] and not f.is_false_positive)
    fp = sum(1 for f in findings if f.is_false_positive)
    confirmed = sum(1 for f in findings if f.validation_status == "CONFIRMED" and not f.is_false_positive)

    scanner_job_list = [
        {
            "id": s.id,
            "scanner": s.scanner,
            "status": s.status,
            "target_host": s.target_host,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "finished_at": s.finished_at.isoformat() if s.finished_at else None,
            "error_message": s.error_message,
        }
        for s in scans
    ]

    approvals_summary = {
        "PENDING": sum(1 for a in approvals if a.status == "PENDING"),
        "APPROVED": sum(1 for a in approvals if a.status == "APPROVED"),
        "REJECTED": sum(1 for a in approvals if a.status == "REJECTED"),
        "EXPIRED": sum(1 for a in approvals if a.status == "EXPIRED"),
    }

    limitations = (
        f"Testing was strictly constrained to registered target {target.host}. "
        "Intrusive exploits were disabled or held under human approval gate. "
        "No arbitrary CIDR scanning was permitted. Only confirmed scanner evidence was recorded."
    )

    return ReportSummaryResponse(
        assessment_id=assessment.id,
        assessment_name=assessment.name,
        target_id=target.id,
        target_name=target.name,
        target_host=target.host,
        auth_reference=target.auth_reference,
        assessment_status=assessment.status,
        assessment_type=assessment.assessment_type or "Network & Web VAPT",
        start_time=assessment.start_time or assessment.created_at,
        completion_date=assessment.updated_at,
        total_findings=len(findings),
        critical_findings=crit,
        high_findings=high,
        medium_findings=med,
        low_findings=low,
        informational_findings=info,
        false_positives_count=fp,
        confirmed_findings_count=confirmed,
        scanner_jobs=scanner_job_list,
        approvals_summary=approvals_summary,
        assessment_limitations=limitations,
        generated_at=datetime.now(timezone.utc),
    )


@router.get("/assessments/{assessment_id}/pdf")
async def download_assessment_pdf(
    assessment_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Generates and downloads the professional VAPT PDF report using actual database findings.
    """
    assessment = await db.get(Assessment, assessment_id)
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found.")

    target = await db.get(AuthorizedTarget, assessment.target_id)
    if not target:
        target = (await db.scalars(select(AuthorizedTarget).where(AuthorizedTarget.is_deleted == False))).first()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found.")

    f_res = await db.execute(select(Finding).where(Finding.assessment_id == assessment.id))
    findings = f_res.scalars().all()

    s_res = await db.execute(select(ScanJob).where(ScanJob.assessment_id == assessment.id))
    scans = s_res.scalars().all()

    a_res = await db.execute(select(ApprovalRequest).where(ApprovalRequest.assessment_id == assessment.id))
    approvals = a_res.scalars().all()

    generator = VAPTReportGenerator(
        assessment=assessment,
        target=target,
        findings=findings,
        scans=scans,
        approvals=approvals,
    )

    try:
        pdf_bytes = generator.generate_pdf()
    except Exception as exc:
        logger.error(f"Error generating VAPT PDF: {exc}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"PDF Generation Failed: {str(exc)}")

    clean_name = "".join(c for c in assessment.name if c.isalnum() or c in ("-", "_")).rstrip() or "Assessment"
    filename = f"VAPT_Report_{clean_name}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M')}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache",
        },
    )
