"""Authorized target registration and authorization management."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.models.models import Assessment, AuditLog, AuthorizedTarget, TargetStatus
from app.schemas.schemas import (
    AuthorizedTargetCreate,
    AuthorizedTargetResponse,
    AuthorizedTargetRevoke,
    AuthorizedTargetUpdate,
    MessageResponse,
    TargetOverviewStats,
)
from app.services.scope_validator import (
    normalize_and_validate_host,
    parse_paths_input,
    parse_ports_input,
)

router = APIRouter(prefix="/targets", tags=["targets"])


def _update_expiration_status(target: AuthorizedTarget) -> None:
    """Updates target status to EXPIRED if current UTC time exceeds valid_to."""
    if target.is_deleted:
        return
    status_upper = (target.status or "").upper()
    if status_upper in (TargetStatus.REVOKED.value, TargetStatus.PENDING.value):
        return

    now_utc = datetime.now(timezone.utc)
    valid_to = target.valid_to
    if valid_to:
        if valid_to.tzinfo is None:
            valid_to = valid_to.replace(tzinfo=timezone.utc)
        if now_utc > valid_to:
            target.status = TargetStatus.EXPIRED.value


@router.get("", response_model=List[AuthorizedTargetResponse])
async def list_targets(
    status_filter: Optional[str] = Query(None, alias="status"),
    include_deleted: bool = False,
    db: AsyncSession = Depends(get_db),
):
    """
    List all registered targets.
    Automatically checks and updates expired target statuses.
    """
    query = select(AuthorizedTarget)
    if not include_deleted:
        query = query.where(AuthorizedTarget.is_deleted == False)

    query = query.order_by(AuthorizedTarget.created_at.desc())
    result = await db.execute(query)
    targets = result.scalars().all()

    # Update expiration dynamically
    for t in targets:
        _update_expiration_status(t)

    if status_filter:
        s_upper = status_filter.upper()
        return [t for t in targets if (t.status or "").upper() == s_upper]

    return targets


@router.get("/stats/overview", response_model=TargetOverviewStats)
async def get_target_overview_stats(db: AsyncSession = Depends(get_db)):
    """Summary overview counts of all registered targets."""
    targets = (
        await db.execute(
            select(AuthorizedTarget).where(AuthorizedTarget.is_deleted == False)
        )
    ).scalars().all()

    total = len(targets)
    active = 0
    expired = 0
    revoked = 0
    pending = 0

    for t in targets:
        _update_expiration_status(t)
        st = (t.status or "").upper()
        if st in (TargetStatus.ACTIVE.value, "AUTHORIZED"):
            active += 1
        elif st == TargetStatus.EXPIRED.value:
            expired += 1
        elif st == TargetStatus.REVOKED.value:
            revoked += 1
        elif st == TargetStatus.PENDING.value:
            pending += 1

    return TargetOverviewStats(
        total=total,
        active=active,
        expired=expired,
        revoked=revoked,
        pending=pending,
    )


@router.post("", response_model=AuthorizedTargetResponse, status_code=status.HTTP_201_CREATED)
async def create_target(payload: AuthorizedTargetCreate, db: AsyncSession = Depends(get_db)):
    """
    Register a new authorized target.
    Strictly validates IPv4, IPv6, and domain names.
    Rejects wildcards and CIDR ranges.
    """
    # 1. Host syntax normalization & validation
    try:
        norm_host = normalize_and_validate_host(payload.host)
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(err),
        )

    # 2. Check for duplicate host
    existing = await db.scalar(
        select(AuthorizedTarget).where(AuthorizedTarget.host == norm_host)
    )
    if existing:
        if not existing.is_deleted:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Target host '{norm_host}' is already registered (Target ID: {existing.id}).",
            )
        else:
            # Re-registering previously decommissioned target: purge old record cleanly
            await db.delete(existing)
            await db.flush()

    # 3. Port parsing and validation
    try:
        permitted_ports = parse_ports_input(payload.permitted_ports)
        excluded_ports = parse_ports_input(payload.excluded_ports)
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Port specification error: {err}",
        )

    # 4. Path normalization
    excluded_paths = parse_paths_input(payload.excluded_paths)

    # 5. Date validation
    if payload.valid_from and payload.valid_to:
        if payload.valid_to <= payload.valid_from:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Authorization expiration date (valid_to) must be strictly after start date (valid_from).",
            )

    # Determine initial status
    initial_status = (payload.status or TargetStatus.ACTIVE.value).upper()
    now_utc = datetime.now(timezone.utc)
    if payload.valid_to:
        v_to = payload.valid_to.replace(tzinfo=timezone.utc) if payload.valid_to.tzinfo is None else payload.valid_to
        if now_utc > v_to:
            initial_status = TargetStatus.EXPIRED.value

    target = AuthorizedTarget(
        name=payload.name.strip(),
        host=norm_host,
        target_url=payload.target_url.strip() if payload.target_url else None,
        purpose=payload.purpose or "Vulnerability Assessment",
        description=payload.description,
        auth_contact=payload.auth_contact,
        auth_reference=payload.auth_reference,
        valid_from=payload.valid_from,
        valid_to=payload.valid_to,
        permitted_ports=json.dumps(permitted_ports) if permitted_ports else None,
        excluded_ports=json.dumps(excluded_ports) if excluded_ports else None,
        excluded_paths=json.dumps(excluded_paths) if excluded_paths else None,
        restrictions=payload.restrictions,
        scope_notes=payload.scope_notes,
        status=initial_status,
        authorized_by=payload.authorized_by or "lead_analyst",
        authorized_at=now_utc if initial_status in (TargetStatus.ACTIVE.value, "AUTHORIZED") else None,
        created_by=payload.authorized_by or "lead_analyst",
    )
    db.add(target)
    await db.flush()

    # Immutable Audit Log
    db.add(
        AuditLog(
            actor=payload.authorized_by or "lead_analyst",
            action="target.registered",
            resource_type="authorized_target",
            resource_id=target.id,
            detail=json.dumps({
                "host": norm_host,
                "name": target.name,
                "status": target.status,
                "auth_reference": target.auth_reference,
                "permitted_ports": permitted_ports,
                "excluded_ports": excluded_ports,
                "excluded_paths": excluded_paths,
            }),
        )
    )

    return target


@router.get("/{target_id}", response_model=AuthorizedTargetResponse)
async def get_target(target_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieve full target record with authorization parameters."""
    target = await db.get(AuthorizedTarget, target_id)
    if not target or target.is_deleted:
        raise HTTPException(status_code=404, detail="Authorized target not found.")
    _update_expiration_status(target)
    return target


@router.put("/{target_id}", response_model=AuthorizedTargetResponse)
async def update_target(
    target_id: str,
    payload: AuthorizedTargetUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update target scope, port permissions, exclusion paths, or validity window."""
    target = await db.get(AuthorizedTarget, target_id)
    if not target or target.is_deleted:
        raise HTTPException(status_code=404, detail="Authorized target not found.")

    # Host update validation if changing
    if payload.host and payload.host != target.host:
        try:
            norm_host = normalize_and_validate_host(payload.host)
        except ValueError as err:
            raise HTTPException(status_code=422, detail=str(err))

        # Check collision
        existing = await db.scalar(
            select(AuthorizedTarget).where(
                AuthorizedTarget.host == norm_host,
                AuthorizedTarget.id != target_id,
                AuthorizedTarget.is_deleted == False,
            )
        )
        if existing:
            raise HTTPException(
                status_code=409,
                detail=f"Target host '{norm_host}' already belongs to another registered target.",
            )
        target.host = norm_host

    if payload.name is not None:
        target.name = payload.name.strip()
    if payload.target_url is not None:
        target.target_url = payload.target_url.strip() if payload.target_url else None
    if payload.purpose is not None:
        target.purpose = payload.purpose
    if payload.description is not None:
        target.description = payload.description
    if payload.auth_contact is not None:
        target.auth_contact = payload.auth_contact
    if payload.auth_reference is not None:
        target.auth_reference = payload.auth_reference
    if payload.valid_from is not None:
        target.valid_from = payload.valid_from
    if payload.valid_to is not None:
        target.valid_to = payload.valid_to
    if payload.restrictions is not None:
        target.restrictions = payload.restrictions
    if payload.scope_notes is not None:
        target.scope_notes = payload.scope_notes

    # Ports & Exclusions
    if payload.permitted_ports is not None:
        ports = parse_ports_input(payload.permitted_ports)
        target.permitted_ports = json.dumps(ports) if ports else None
    if payload.excluded_ports is not None:
        ex_ports = parse_ports_input(payload.excluded_ports)
        target.excluded_ports = json.dumps(ex_ports) if ex_ports else None
    if payload.excluded_paths is not None:
        ex_paths = parse_paths_input(payload.excluded_paths)
        target.excluded_paths = json.dumps(ex_paths) if ex_paths else None

    if payload.status is not None:
        target.status = payload.status.upper()

    _update_expiration_status(target)

    # Audit log
    db.add(
        AuditLog(
            actor=payload.authorized_by or "operator",
            action="target.updated",
            resource_type="authorized_target",
            resource_id=target.id,
            detail=json.dumps({
                "host": target.host,
                "status": target.status,
                "auth_reference": target.auth_reference,
            }),
        )
    )

    return target


@router.post("/{target_id}/revoke", response_model=AuthorizedTargetResponse)
async def revoke_target(
    target_id: str,
    payload: AuthorizedTargetRevoke,
    db: AsyncSession = Depends(get_db),
):
    """
    Explicitly revoke authorization for a target.
    Instantly blocks any current or future assessments against this target.
    """
    target = await db.get(AuthorizedTarget, target_id)
    if not target or target.is_deleted:
        raise HTTPException(status_code=404, detail="Authorized target not found.")

    target.status = TargetStatus.REVOKED.value
    target.revoked_by = payload.revoked_by
    target.revoked_at = datetime.now(timezone.utc)
    target.revocation_reason = payload.revocation_reason

    db.add(
        AuditLog(
            actor=payload.revoked_by,
            action="target.revoked",
            resource_type="authorized_target",
            resource_id=target.id,
            detail=json.dumps({
                "host": target.host,
                "revocation_reason": payload.revocation_reason,
                "revoked_by": payload.revoked_by,
            }),
        )
    )

    return target


@router.patch("/{target_id}/authorize", response_model=AuthorizedTargetResponse)
async def authorize_target(
    target_id: str,
    authorized_by: str = "operator",
    db: AsyncSession = Depends(get_db),
):
    """Explicitly activate/authorize target (backwards compatibility)."""
    target = await db.get(AuthorizedTarget, target_id)
    if not target or target.is_deleted:
        raise HTTPException(status_code=404, detail="Authorized target not found.")

    target.status = TargetStatus.ACTIVE.value
    target.authorized_by = authorized_by
    target.authorized_at = datetime.now(timezone.utc)

    db.add(
        AuditLog(
            actor=authorized_by,
            action="target.authorized",
            resource_type="authorized_target",
            resource_id=target.id,
            detail=f"Authorized target: {target.host}",
        )
    )
    return target


@router.delete("/{target_id}", response_model=MessageResponse)
async def delete_target(
    target_id: str,
    hard_delete: bool = False,
    db: AsyncSession = Depends(get_db),
):
    """
    Soft-delete or revoke a target to preserve immutable audit trail.
    If hard_delete=True and no assessments exist, permanently removes.
    """
    target = await db.get(AuthorizedTarget, target_id)
    if not target or target.is_deleted:
        raise HTTPException(status_code=404, detail="Target not found.")

    if hard_delete:
        assessment_count = await db.scalar(
            select(func.count(Assessment.id)).where(Assessment.target_id == target_id)
        )
        if (assessment_count or 0) == 0:
            await db.delete(target)
            action = "target.deleted_permanently"
        else:
            target.is_deleted = True
            target.status = TargetStatus.REVOKED.value
            target.revoked_at = datetime.now(timezone.utc)
            target.revocation_reason = "Target decommissioned / soft-deleted (associated assessments exist)"
            action = "target.soft_deleted"
    else:
        target.is_deleted = True
        target.status = TargetStatus.REVOKED.value
        target.revoked_at = datetime.now(timezone.utc)
        target.revocation_reason = "Target decommissioned / soft-deleted by operator"
        action = "target.soft_deleted"

    db.add(
        AuditLog(
            actor="operator",
            action=action,
            resource_type="authorized_target",
            resource_id=target_id,
            detail=f"Decommissioned target: {target.host}",
        )
    )

    return MessageResponse(message=f"Target '{target.host}' removed from active scope.")
