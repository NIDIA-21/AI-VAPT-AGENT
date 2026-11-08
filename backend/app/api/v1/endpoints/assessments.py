"""Assessment lifecycle endpoints."""
from __future__ import annotations

import json
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.models.models import AgentDecision, Assessment, AssessmentStatus, AuditLog, AuthorizedTarget
from app.schemas.schemas import AssessmentCreate, AssessmentResponse, MessageResponse
from app.services.scope_validator import ScopeValidationService

router = APIRouter(prefix="/assessments", tags=["assessments"])


@router.get("", response_model=List[AssessmentResponse])
async def list_assessments(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Assessment).order_by(Assessment.created_at.desc())
    )
    return result.scalars().all()


@router.post("", response_model=AssessmentResponse, status_code=status.HTTP_201_CREATED)
async def create_assessment(payload: AssessmentCreate, db: AsyncSession = Depends(get_db)):
    """
    Create an assessment — strictly against an explicitly authorized and active target.
    Mandatory Scope Validation is executed prior to assessment initialization.
    Rejects expired, revoked, or unapproved targets.
    Attaches the validated scope snapshot to the assessment record.
    """
    # 1. Fetch Target
    target = await db.get(AuthorizedTarget, payload.target_id)
    if not target or target.is_deleted:
        raise HTTPException(status_code=404, detail="Target not found in registered scope.")

    # 2. Strict Scope Validation Engine Check
    val_result = await ScopeValidationService.validate_scope(
        session=db,
        requested_target=target.host,
        target_id=target.id,
        requested_action="assessment_creation",
        actor=payload.created_by or "operator",
    )

    if not val_result.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Target scope validation failed: {val_result.reason}",
        )

    # 3. Create Validated Scope Snapshot
    scope_snapshot = {
        "target_id": target.id,
        "target_name": target.name,
        "host": target.host,
        "auth_reference": target.auth_reference,
        "auth_contact": target.auth_contact,
        "valid_from": target.valid_from.isoformat() if target.valid_from else None,
        "valid_to": target.valid_to.isoformat() if target.valid_to else None,
        "permitted_ports": target.permitted_ports,
        "excluded_ports": target.excluded_ports,
        "excluded_paths": target.excluded_paths,
        "restrictions": target.restrictions,
        "validated_at": val_result.validation_timestamp.isoformat(),
        "audit_event_id": val_result.audit_event_id,
    }

    assessment = Assessment(
        name=payload.name.strip(),
        description=payload.description,
        target_id=payload.target_id,
        assessment_type=payload.assessment_type or "Network & Web",
        status=AssessmentStatus.DRAFT.value,
        ai_plan=payload.ai_plan,
        validated_scope_snapshot=json.dumps(scope_snapshot),
        created_by=payload.created_by or "lead_analyst",
    )
    db.add(assessment)
    await db.flush()

    # Link decisions if IDs provided
    if payload.decision_ids:
        for dec_id in payload.decision_ids:
            dec = await db.get(AgentDecision, dec_id)
            if dec:
                dec.assessment_id = assessment.id

    db.add(
        AuditLog(
            actor=payload.created_by or "lead_analyst",
            action="assessment.created",
            resource_type="assessment",
            resource_id=assessment.id,
            detail=f"Assessment '{payload.name}' created with validated scope for target {target.host} (Scope Ref: {target.auth_reference or 'Active'})",
        )
    )

    return assessment


@router.get("/{assessment_id}", response_model=AssessmentResponse)
async def get_assessment(assessment_id: str, db: AsyncSession = Depends(get_db)):
    assessment = await db.get(Assessment, assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    return assessment


@router.delete("/{assessment_id}", response_model=MessageResponse)
async def delete_assessment(assessment_id: str, db: AsyncSession = Depends(get_db)):
    assessment = await db.get(Assessment, assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    if assessment.status == AssessmentStatus.RUNNING.value:
        raise HTTPException(status_code=409, detail="Cannot delete a running assessment.")
    await db.delete(assessment)
    return MessageResponse(message=f"Assessment '{assessment.name}' deleted.")
