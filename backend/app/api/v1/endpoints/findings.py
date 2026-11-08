"""
Normalized Vulnerability Findings & Multi-Tool Evidence API Endpoints.
Provides filtered finding queries, evidence explorer data, false-positive tagging,
and AI cross-tool correlation.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.correlator import CorrelationResult, VulnerabilityCorrelator
from app.database.session import get_db
from app.models.models import Assessment, Finding
from app.schemas.schemas import (
    CorrelationRequest,
    FindingResponse,
    FindingStatusUpdate,
)
from app.services.risk_prioritizer import RiskPrioritizer

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("", response_model=List[FindingResponse])
async def list_findings(
    assessment_id: Optional[str] = None,
    severity: Optional[str] = None,
    host: Optional[str] = None,
    source_tool: Optional[str] = None,
    search: Optional[str] = None,
    validation_status: Optional[str] = None,
    is_false_positive: Optional[bool] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Returns normalized findings sorted by multi-factor risk score descending.
    """
    query = select(Finding).order_by(Finding.risk_score.desc().nullslast(), Finding.created_at.desc())

    if assessment_id:
        query = query.where(Finding.assessment_id == assessment_id)
    if severity:
        query = query.where(Finding.severity == severity.lower())
    if host:
        query = query.where(Finding.host.ilike(f"%{host}%"))
    if source_tool:
        query = query.where(Finding.source_tool.ilike(f"%{source_tool}%"))
    if validation_status:
        query = query.where(Finding.validation_status == validation_status.upper())
    if is_false_positive is not None:
        query = query.where(Finding.is_false_positive == is_false_positive)
    if search:
        search_filter = or_(
            Finding.title.ilike(f"%{search}%"),
            Finding.description.ilike(f"%{search}%"),
            Finding.cve_id.ilike(f"%{search}%"),
            Finding.cwe_id.ilike(f"%{search}%"),
            Finding.host.ilike(f"%{search}%"),
            Finding.url_path.ilike(f"%{search}%"),
        )
        query = query.where(search_filter)

    result = await db.execute(query)
    findings = result.scalars().all()
    return findings


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieves full details of a specific finding.
    """
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found.",
        )
    return finding


@router.get("/{finding_id}/evidence", response_model=Dict[str, Any])
async def get_finding_evidence(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Returns full raw evidence artifacts for the Evidence Explorer.
    """
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")

    artifacts: List[Dict[str, Any]] = []
    if finding.raw_evidence_artifacts:
        try:
            artifacts = json.loads(finding.raw_evidence_artifacts)
        except Exception:
            artifacts = [{"raw_text": finding.raw_evidence_artifacts}]
    elif finding.evidence:
        artifacts = [{"evidence": finding.evidence, "source_tool": finding.source_tool}]

    return {
        "finding_id": finding.id,
        "title": finding.title,
        "source_tool": finding.source_tool,
        "host": finding.host,
        "port": finding.port,
        "url_path": finding.url_path,
        "fingerprint": finding.fingerprint,
        "risk_explanation": finding.risk_explanation,
        "artifacts_count": len(artifacts),
        "artifacts": artifacts,
    }


@router.post("/{finding_id}/status", response_model=FindingResponse)
async def update_finding_status(
    finding_id: str,
    payload: FindingStatusUpdate,
    db: AsyncSession = Depends(get_db),
):
    """
    Updates the analyst validation status (CONFIRMED, FALSE_POSITIVE, INVESTIGATING).
    Recalculates risk score when status changes.
    """
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")

    new_status = payload.validation_status.upper()
    finding.validation_status = new_status

    if new_status == "FALSE_POSITIVE":
        finding.is_false_positive = True
        score, explanation = RiskPrioritizer.calculate_risk(
            severity=finding.severity,
            cvss_score=finding.cvss_score,
            host=finding.host,
            port=finding.port,
            cve_id=finding.cve_id,
            cwe_id=finding.cwe_id,
            evidence=finding.evidence,
            confidence=finding.confidence,
            is_false_positive=True,
        )
        finding.risk_score = score
        finding.risk_explanation = explanation
        if payload.notes:
            finding.description = (finding.description or "") + f"\n\n[Analyst FP Note]: {payload.notes}"
    elif new_status == "CONFIRMED":
        finding.is_false_positive = False
        finding.confidence = "Confirmed"
        score, explanation = RiskPrioritizer.calculate_risk(
            severity=finding.severity,
            cvss_score=finding.cvss_score,
            host=finding.host,
            port=finding.port,
            cve_id=finding.cve_id,
            cwe_id=finding.cwe_id,
            evidence=finding.evidence,
            confidence="Confirmed",
            is_false_positive=False,
        )
        finding.risk_score = score
        finding.risk_explanation = explanation

    await db.commit()
    await db.refresh(finding)
    return finding


@router.post("/correlate", response_model=CorrelationResult)
async def correlate_findings(
    payload: CorrelationRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Executes AI vulnerability correlation across all tools for the given assessment.
    Maps attack chains, highlights contradictions/false positives, and provides prioritized remediation.
    """
    assessment = await db.get(Assessment, payload.assessment_id)
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment '{payload.assessment_id}' not found.",
        )

    # Fetch all findings for assessment
    q = select(Finding).where(Finding.assessment_id == assessment.id)
    res = await db.execute(q)
    findings = res.scalars().all()

    # Determine target host
    target_host = "target.local"
    if assessment.target:
        target_host = assessment.target.host

    result = await VulnerabilityCorrelator.correlate_assessment(
        assessment_id=assessment.id,
        target_host=target_host,
        findings=findings,
    )
    return result
