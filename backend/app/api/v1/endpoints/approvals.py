"""
Human-in-the-Loop Approval Management API Endpoints.
Ensures explicit analyst review before elevated or intrusive validation actions.
Strict Security Rule: An approval CANNOT override target authorization or scope restrictions.
Zero Autonomous Exploitation: Metasploit and intrusive exploits are strictly gated.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.models.models import (
    ApprovalRequest,
    ApprovalStatus,
    Assessment,
    AuditLog,
    AuthorizedTarget,
    TargetStatus,
)
from app.schemas.schemas import (
    ApprovalDecisionRequest,
    ApprovalRejectionRequest,
    ApprovalRequestCreate,
    ApprovalRequestResponse,
)
from app.services.scope_validator import ScopeValidationService

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("", response_model=List[ApprovalRequestResponse])
async def list_approvals(
    assessment_id: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    db: AsyncSession = Depends(get_db),
):
    """
    Returns approval requests ordered by request timestamp descending.
    """
    query = select(ApprovalRequest).order_by(ApprovalRequest.created_at.desc())
    if assessment_id:
        query = query.where(ApprovalRequest.assessment_id == assessment_id)
    if status_filter:
        query = query.where(ApprovalRequest.status == status_filter.upper())

    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{approval_id}", response_model=ApprovalRequestResponse)
async def get_approval(
    approval_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieves full details of a specific approval request.
    """
    req = await db.get(ApprovalRequest, approval_id)
    if not req:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Approval request '{approval_id}' not found.",
        )
    return req


@router.post("", response_model=ApprovalRequestResponse, status_code=status.HTTP_201_CREATED)
async def create_approval_request(
    payload: ApprovalRequestCreate,
    db: AsyncSession = Depends(get_db),
):
    """
    Creates a new human-in-the-loop approval request for an intrusive or validation action.
    """
    target = await db.get(AuthorizedTarget, payload.target_id)
    if not target or target.is_deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Authorized target '{payload.target_id}' not found.",
        )

    assessment = await db.get(Assessment, payload.assessment_id)
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment '{payload.assessment_id}' not found.",
        )

    req = ApprovalRequest(
        assessment_id=payload.assessment_id,
        target_id=payload.target_id,
        target_host=payload.target_host.strip().lower(),
        requested_action=payload.requested_action,
        validation_purpose=payload.validation_purpose,
        supporting_evidence=payload.supporting_evidence,
        risk_information=payload.risk_information,
        requested_by=payload.requested_by or "ai_agent",
        status=ApprovalStatus.PENDING.value,
    )
    db.add(req)

    audit = AuditLog(
        actor=payload.requested_by or "ai_agent",
        action="approval.requested",
        resource_type="approval_request",
        resource_id=req.id,
        detail=f"Approval requested for action '{payload.requested_action}' on target '{payload.target_host}'",
    )
    db.add(audit)

    await db.commit()
    await db.refresh(req)
    return req


@router.post("/{approval_id}/approve", response_model=ApprovalRequestResponse)
async def approve_request(
    approval_id: str,
    payload: ApprovalDecisionRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Approves a validation request after rigorous scope re-verification.
    Strict Security Rule: An approval CANNOT override target authorization or scope restrictions.
    """
    req = await db.get(ApprovalRequest, approval_id)
    if not req:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Approval request not found.")

    if req.status != ApprovalStatus.PENDING.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot approve request in '{req.status}' state. Only PENDING requests can be decided.",
        )

    # Re-verify scope: Target must still be ACTIVE and authorized
    scope_result = await ScopeValidationService.validate_scope(
        session=db,
        requested_target=req.target_host,
        target_id=req.target_id,
        requested_action=req.requested_action,
        actor=payload.analyst_id,
    )

    if not scope_result.allowed:
        # Security Policy: Scope violations strictly prevent approval
        audit_fail = AuditLog(
            actor=payload.analyst_id,
            action="approval.denied_by_scope",
            resource_type="approval_request",
            resource_id=req.id,
            detail=f"Approval blocked by scope validation: {scope_result.reason}",
        )
        db.add(audit_fail)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Approval Rejected: Cannot approve action because target is outside authorized scope. {scope_result.reason}",
        )

    # Apply Approval
    req.status = ApprovalStatus.APPROVED.value
    req.reviewed_by = payload.analyst_id
    req.decision_timestamp = datetime.now(timezone.utc)
    req.decision_notes = payload.notes

    audit = AuditLog(
        actor=payload.analyst_id,
        action="approval.granted",
        resource_type="approval_request",
        resource_id=req.id,
        detail=f"Analyst '{payload.analyst_id}' approved action '{req.requested_action}' for target '{req.target_host}'. Notes: {payload.notes or 'None'}",
    )
    db.add(audit)

    await db.commit()
    await db.refresh(req)
    return req


@router.post("/{approval_id}/reject", response_model=ApprovalRequestResponse)
async def reject_request(
    approval_id: str,
    payload: ApprovalRejectionRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Rejects a validation request, recording mandatory analyst rejection rationale.
    """
    req = await db.get(ApprovalRequest, approval_id)
    if not req:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Approval request not found.")

    if req.status != ApprovalStatus.PENDING.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot reject request in '{req.status}' state. Only PENDING requests can be decided.",
        )

    req.status = ApprovalStatus.REJECTED.value
    req.reviewed_by = payload.analyst_id
    req.rejection_reason = payload.rejection_reason
    req.decision_timestamp = datetime.now(timezone.utc)
    req.decision_notes = payload.notes

    audit = AuditLog(
        actor=payload.analyst_id,
        action="approval.rejected",
        resource_type="approval_request",
        resource_id=req.id,
        detail=f"Analyst '{payload.analyst_id}' rejected action '{req.requested_action}' for target '{req.target_host}'. Reason: {payload.rejection_reason}",
    )
    db.add(audit)

    await db.commit()
    await db.refresh(req)
    return req
