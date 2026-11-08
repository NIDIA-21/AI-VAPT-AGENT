"""
Scanner Orchestration and Report Import API Endpoints.
Supports safe scoped live Nmap scanning and genuine OWASP ZAP & Nikto report imports.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.models.models import Assessment, AuthorizedTarget, Finding, ScanJob
from app.scanners.nmap_runner import (
    get_nmap_status,
    import_nmap_xml_report,
    run_scoped_nmap_scan,
)
from app.scanners.parsers import NiktoParser, ZapParser
from app.schemas.schemas import (
    NmapExecuteRequest,
    ReportImportRequest,
    ScanJobResponse,
)
from app.services.deduplicator import deduplicate_and_persist_findings
from app.services.scope_validator import ScopeValidationService

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/status", response_model=Dict[str, Any])
async def get_scanners_status():
    """
    Returns the real-time operational status of all supported cybersecurity tools.
    Displays LIVE, IMPORT ONLY, or NOT INSTALLED honestly.
    """
    nmap_info = await get_nmap_status()

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tools": {
            "nmap": {
                "name": "Nmap Network Scanner",
                "mode": nmap_info.get("mode", "IMPORT ONLY"),
                "status": nmap_info.get("status", "NOT INSTALLED"),
                "version": nmap_info.get("version", "Unknown"),
                "path": nmap_info.get("path"),
                "capabilities": ["Host Discovery", "Port Scanning", "Service Detection", "XML Report Import"],
                "is_live_capable": nmap_info.get("installed", False),
                "note": nmap_info.get("note"),
            },
            "owasp_zap": {
                "name": "OWASP ZAP",
                "mode": "IMPORT ONLY",
                "status": "IMPORT ONLY",
                "version": "Official JSON & XML Parser v2.14+",
                "path": None,
                "capabilities": ["DAST Vulnerability Ingestion", "Alert Classification", "CWE Mapping", "Raw Evidence Preservation"],
                "is_live_capable": False,
                "note": "Report ingestion mode active. Upload official ZAP JSON or XML reports to populate findings.",
            },
            "nikto": {
                "name": "Nikto Web Scanner",
                "mode": "IMPORT ONLY",
                "status": "IMPORT ONLY",
                "version": "Nikto 2.1+ JSON & XML Parser",
                "path": None,
                "capabilities": ["Web Server Misconfiguration Ingestion", "OSVDB ID Tracking", "HTTP Evidence Preservation"],
                "is_live_capable": False,
                "note": "Report ingestion mode active. Upload official Nikto JSON or XML reports to populate findings.",
            },
        },
    }


@router.post("/nmap/execute", response_model=ScanJobResponse)
async def execute_nmap_scan(
    payload: NmapExecuteRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Executes a scoped Nmap scan. Checks target authorization and strictly enforces scope.
    """
    target = await db.get(AuthorizedTarget, payload.target_id)
    if not target or target.is_deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target '{payload.target_id}' not found.",
        )

    # Resolve or create assessment
    assessment_id = payload.assessment_id
    if not assessment_id:
        # Fetch latest assessment for target or create one
        q = (
            select(Assessment)
            .where(Assessment.target_id == target.id)
            .order_by(Assessment.created_at.desc())
        )
        res = await db.execute(q)
        latest_assessment = res.scalars().first()
        if latest_assessment:
            assessment_id = latest_assessment.id
        else:
            new_assessment = Assessment(
                name=f"Assessment for {target.name}",
                target_id=target.id,
                status="ACTIVE",
            )
            db.add(new_assessment)
            await db.commit()
            await db.refresh(new_assessment)
            assessment_id = new_assessment.id

    try:
        job = await run_scoped_nmap_scan(
            target=target,
            assessment_id=assessment_id,
            session=db,
            ports_override=payload.ports_override,
        )
        return job
    except PermissionError as pe:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(pe),
        )


@router.post("/import/nmap", response_model=ScanJobResponse)
async def import_nmap_report(
    payload: ReportImportRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Imports and normalizes an Nmap XML scan report.
    """
    # 1. Scope check for the target_host
    scope_result = await ScopeValidationService.validate_scope(
        session=db,
        requested_target=payload.target_host,
        requested_action="report_import",
    )
    if not scope_result.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Scope violation: Host {payload.target_host} is not in registered active scope. {scope_result.reason}",
        )

    # 2. Resolve assessment
    assessment_id = payload.assessment_id
    if not assessment_id:
        target_res = await db.execute(
            select(AuthorizedTarget).where(
                AuthorizedTarget.host == payload.target_host.strip().lower(),
                AuthorizedTarget.is_deleted == False,
            )
        )
        target = target_res.scalars().first()
        if target:
            a_res = await db.execute(
                select(Assessment).where(Assessment.target_id == target.id).order_by(Assessment.created_at.desc())
            )
            latest_a = a_res.scalars().first()
            if latest_a:
                assessment_id = latest_a.id
            else:
                new_a = Assessment(name=f"Assessment for {payload.target_host}", target_id=target.id, status="ACTIVE")
                db.add(new_a)
                await db.commit()
                await db.refresh(new_a)
                assessment_id = new_a.id
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Assessment ID required or registered target must exist.",
            )

    try:
        job, parsed_findings = await import_nmap_xml_report(
            xml_content=payload.report_content,
            assessment_id=assessment_id,
            target_host=payload.target_host,
            session=db,
        )
        job.findings_count = len(parsed_findings)
        return job
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(ve))


@router.post("/import/zap", response_model=ScanJobResponse)
async def import_zap_report(
    payload: ReportImportRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Imports and normalizes an OWASP ZAP JSON or XML report.
    """
    # 1. Scope check
    scope_result = await ScopeValidationService.validate_scope(
        session=db,
        requested_target=payload.target_host,
        requested_action="report_import",
    )
    if not scope_result.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Scope violation: Host {payload.target_host} is not an authorized target. {scope_result.reason}",
        )

    # 2. Resolve assessment
    assessment_id = payload.assessment_id
    if not assessment_id:
        target_res = await db.execute(
            select(AuthorizedTarget).where(
                AuthorizedTarget.host == payload.target_host.strip().lower(),
                AuthorizedTarget.is_deleted == False,
            )
        )
        target = target_res.scalars().first()
        if not target:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not registered in active scope.")
        new_a = Assessment(name=f"DAST Assessment for {payload.target_host}", target_id=target.id, status="ACTIVE")
        db.add(new_a)
        await db.commit()
        await db.refresh(new_a)
        assessment_id = new_a.id

    # 3. Parse report
    try:
        if (payload.format or "json").lower() == "xml" or payload.report_content.strip().startswith("<"):
            parsed = ZapParser.parse_xml(payload.report_content, default_host=payload.target_host)
        else:
            parsed = ZapParser.parse_json(payload.report_content, default_host=payload.target_host)
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(ve))

    # 4. Create ScanJob record
    job = ScanJob(
        assessment_id=assessment_id,
        scanner="OWASP ZAP (Imported)",
        status="COMPLETED",
        target_host=payload.target_host,
        parameters=json.dumps({"format": payload.format, "findings_extracted": len(parsed)}),
        raw_output=payload.report_content,
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    # 5. Persist with deduplication & risk scoring
    await deduplicate_and_persist_findings(
        parsed_findings=parsed,
        assessment_id=assessment_id,
        scan_job_id=job.id,
        session=db,
    )

    job.findings_count = len(parsed)
    return job


@router.post("/import/nikto", response_model=ScanJobResponse)
async def import_nikto_report(
    payload: ReportImportRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Imports and normalizes a Nikto JSON or XML report.
    """
    # 1. Scope check
    scope_result = await ScopeValidationService.validate_scope(
        session=db,
        requested_target=payload.target_host,
        requested_action="report_import",
    )
    if not scope_result.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Scope violation: Host {payload.target_host} is not an authorized target. {scope_result.reason}",
        )

    # 2. Resolve assessment
    assessment_id = payload.assessment_id
    if not assessment_id:
        target_res = await db.execute(
            select(AuthorizedTarget).where(
                AuthorizedTarget.host == payload.target_host.strip().lower(),
                AuthorizedTarget.is_deleted == False,
            )
        )
        target = target_res.scalars().first()
        if not target:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not registered in active scope.")
        new_a = Assessment(name=f"Web Misconfig Scan for {payload.target_host}", target_id=target.id, status="ACTIVE")
        db.add(new_a)
        await db.commit()
        await db.refresh(new_a)
        assessment_id = new_a.id

    # 3. Parse report
    try:
        if (payload.format or "json").lower() == "xml" or payload.report_content.strip().startswith("<"):
            parsed = NiktoParser.parse_xml(payload.report_content, default_host=payload.target_host)
        else:
            parsed = NiktoParser.parse_json(payload.report_content, default_host=payload.target_host)
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(ve))

    # 4. Create ScanJob record
    job = ScanJob(
        assessment_id=assessment_id,
        scanner="Nikto (Imported)",
        status="COMPLETED",
        target_host=payload.target_host,
        parameters=json.dumps({"format": payload.format, "findings_extracted": len(parsed)}),
        raw_output=payload.report_content,
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    # 5. Persist with deduplication & risk scoring
    await deduplicate_and_persist_findings(
        parsed_findings=parsed,
        assessment_id=assessment_id,
        scan_job_id=job.id,
        session=db,
    )

    job.findings_count = len(parsed)
    return job


@router.get("/jobs", response_model=List[ScanJobResponse])
async def list_scan_jobs(
    assessment_id: Optional[str] = None,
    scanner: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    db: AsyncSession = Depends(get_db),
):
    """
    Returns scan execution jobs with status, target, and timing.
    """
    query = select(ScanJob).order_by(ScanJob.created_at.desc())
    if assessment_id:
        query = query.where(ScanJob.assessment_id == assessment_id)
    if scanner:
        query = query.where(ScanJob.scanner.ilike(f"%{scanner}%"))
    if status_filter:
        query = query.where(ScanJob.status == status_filter.upper())

    result = await db.execute(query)
    jobs = result.scalars().all()

    # Annotate findings count for each job
    response = []
    for job in jobs:
        cnt_q = select(func.count(Finding.id)).where(Finding.scan_job_id == job.id)
        cnt = (await db.execute(cnt_q)).scalar() or 0
        j_dict = {
            "id": job.id,
            "assessment_id": job.assessment_id,
            "scanner": job.scanner,
            "status": job.status,
            "target_host": job.target_host,
            "parameters": job.parameters,
            "scope_snapshot": job.scope_snapshot,
            "raw_output": job.raw_output,
            "error_message": job.error_message,
            "started_at": job.started_at,
            "finished_at": job.finished_at,
            "created_at": job.created_at,
            "findings_count": cnt,
        }
        response.append(ScanJobResponse(**j_dict))

    return response


@router.get("/jobs/{job_id}", response_model=ScanJobResponse)
async def get_scan_job(
    job_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Returns single scan job details including raw output.
    """
    job = await db.get(ScanJob, job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found.")

    cnt_q = select(func.count(Finding.id)).where(Finding.scan_job_id == job.id)
    cnt = (await db.execute(cnt_q)).scalar() or 0

    j_dict = {
        "id": job.id,
        "assessment_id": job.assessment_id,
        "scanner": job.scanner,
        "status": job.status,
        "target_host": job.target_host,
        "parameters": job.parameters,
        "scope_snapshot": job.scope_snapshot,
        "raw_output": job.raw_output,
        "error_message": job.error_message,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "created_at": job.created_at,
        "findings_count": cnt,
    }
    return ScanJobResponse(**j_dict)
