"""Scope validation and audit endpoints."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.models.models import AuditLog
from app.schemas.schemas import (
    ScopeAuditItem,
    ScopeAuditResponse,
    ScopeValidationRequest,
    ScopeValidationResponse,
)
from app.services.scope_validator import ScopeValidationService

router = APIRouter(prefix="/scope", tags=["scope"])


@router.post("/validate", response_model=ScopeValidationResponse)
async def validate_scope(
    payload: ScopeValidationRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Centralized Scope Validation API.
    Every scanner adapter and execution module MUST call this endpoint
    before performing network operations.

    Default-Deny behavior.
    Excluded resources always take precedence over permitted resources.
    """
    client_ip = request.client.host if request.client else None
    result = await ScopeValidationService.validate_scope(
        session=db,
        requested_target=payload.requested_target,
        target_id=payload.target_id,
        requested_port=payload.requested_port,
        requested_path=payload.requested_path,
        requested_protocol=payload.requested_protocol,
        requested_action=payload.requested_action or "assessment",
        actor="operator_api",
        ip_address=client_ip,
    )

    return ScopeValidationResponse(
        allowed=result.allowed,
        target_id=result.target_id,
        target_name=result.target_name,
        requested_target=result.requested_target or payload.requested_target,
        requested_port=result.requested_port,
        requested_path=result.requested_path,
        requested_protocol=result.requested_protocol,
        reason=result.reason,
        validation_timestamp=result.validation_timestamp,
        audit_event_id=result.audit_event_id,
    )


@router.get("/audit", response_model=ScopeAuditResponse)
async def get_scope_audit(
    limit: int = Query(50, ge=1, le=200),
    action_filter: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieves the immutable audit trail of scope validation approvals,
    rejections, target registrations, and authorization revocations.
    """
    query = select(AuditLog).where(
        AuditLog.action.like("%scope%") | AuditLog.action.like("%target%")
    )

    if action_filter:
        query = query.where(AuditLog.action == action_filter)

    query = query.order_by(AuditLog.created_at.desc()).limit(limit)
    res = await db.execute(query)
    logs = res.scalars().all()

    audit_items = [
        ScopeAuditItem(
            id=log.id,
            actor=log.actor,
            action=log.action,
            resource_type=log.resource_type,
            resource_id=log.resource_id,
            detail=log.detail,
            ip_address=log.ip_address,
            created_at=log.created_at,
            timestamp=log.created_at,
        )
        for log in logs
    ]

    return ScopeAuditResponse(
        events=audit_items,
        total_events=len(audit_items),
        timestamp=datetime.now(timezone.utc),
    )
