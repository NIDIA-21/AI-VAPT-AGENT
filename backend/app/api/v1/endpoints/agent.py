"""
AI Agent & Intelligent Assessment Planner API Endpoints.
Provides chat interactions, session management, scope-validated assessment planning,
and queryable decision traces.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.assistant import AssistantService
from app.agents.llm_provider import llm_service
from app.agents.planner import AssessmentPlanner, ScopeViolationError
from app.database.session import get_db
from app.models.models import (
    AgentChatMessage,
    AgentChatSession,
    AgentDecision,
    AuditLog,
    AuthorizedTarget,
)
from app.schemas.schemas import (
    AgentChatMessageItem,
    AgentChatRequest,
    AgentChatResponse,
    AgentChatSessionDetail,
    AgentChatSessionItem,
    AgentDecisionItem,
    AgentPlanRequest,
    MessageResponse,
)

router = APIRouter(prefix="/agent", tags=["agent"])


@router.post("/chat", response_model=AgentChatResponse)
async def chat_with_agent(
    payload: AgentChatRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Interact with the conversational AI security assistant.
    Resolves targets, validates scope, and generates multi-stage plans when applicable.
    """
    try:
        result = await AssistantService.process_message(
            message=payload.message,
            db=db,
            session_id=payload.session_id,
            explicit_target_id=payload.target_id,
            user_name=payload.user_name or "security_analyst",
        )
        return AgentChatResponse(**result.model_dump())
    except ScopeViolationError as sve:
        raise HTTPException(status_code=403, detail=str(sve))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Agent interaction error: {str(exc)}",
        )


@router.get("/sessions", response_model=List[AgentChatSessionItem])
async def list_chat_sessions(
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """List recent AI chat sessions with target metadata and message counts."""
    # Query sessions
    sessions_stmt = (
        select(AgentChatSession)
        .order_by(desc(AgentChatSession.updated_at))
        .limit(limit)
    )
    sessions = (await db.scalars(sessions_stmt)).all()

    items: List[AgentChatSessionItem] = []
    for s in sessions:
        # Message count
        count_stmt = select(func.count(AgentChatMessage.id)).where(
            AgentChatMessage.session_id == s.id
        )
        msg_count = (await db.scalar(count_stmt)) or 0

        # Host name if target linked
        target_host = None
        if s.target_id:
            target = await db.get(AuthorizedTarget, s.target_id)
            if target:
                target_host = target.host

        items.append(
            AgentChatSessionItem(
                id=s.id,
                title=s.title,
                target_id=s.target_id,
                target_host=target_host,
                message_count=msg_count,
                created_by=s.created_by,
                created_at=s.created_at,
                updated_at=s.updated_at,
            )
        )
    return items


@router.get("/sessions/{session_id}", response_model=AgentChatSessionDetail)
async def get_chat_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Retrieve full message history for a chat session."""
    session = await db.get(AgentChatSession, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Chat session not found.")

    messages_stmt = (
        select(AgentChatMessage)
        .where(AgentChatMessage.session_id == session_id)
        .order_by(AgentChatMessage.created_at.asc())
    )
    messages = (await db.scalars(messages_stmt)).all()

    return AgentChatSessionDetail(
        id=session.id,
        title=session.title,
        target_id=session.target_id,
        created_by=session.created_by,
        created_at=session.created_at,
        updated_at=session.updated_at,
        messages=[AgentChatMessageItem.model_validate(m) for m in messages],
    )


@router.delete("/sessions/{session_id}", response_model=MessageResponse)
async def delete_chat_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Delete a chat session and its associated messages."""
    session = await db.get(AgentChatSession, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Chat session not found.")

    await db.delete(session)
    return MessageResponse(message=f"Chat session '{session_id}' deleted.")


@router.post("/plan")
async def generate_assessment_plan(
    payload: AgentPlanRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Direct endpoint for generating an authorized assessment plan and decision trace.
    Validates target scope, evaluates tool options, and persists decisions.
    """
    try:
        plan_result = await AssessmentPlanner.plan_assessment(
            target_id=payload.target_id,
            requirements=payload.requirements,
            db=db,
            assessment_type=payload.assessment_type or "full_vapt",
            selected_categories=payload.selected_categories,
            operator=payload.operator or "security_analyst",
        )
        return plan_result.model_dump()
    except ScopeViolationError as sve:
        raise HTTPException(status_code=403, detail=str(sve))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Plan generation failed: {str(exc)}",
        )


@router.get("/decisions", response_model=List[AgentDecisionItem])
async def list_agent_decisions(
    target_id: Optional[str] = None,
    assessment_id: Optional[str] = None,
    session_id: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieve agent decision traces with concrete observations vs AI inferences.
    Filterable by target, assessment, or chat session.
    """
    stmt = select(AgentDecision).order_by(desc(AgentDecision.created_at)).limit(limit)

    if target_id:
        stmt = stmt.where(AgentDecision.target_id == target_id)
    if assessment_id:
        stmt = stmt.where(AgentDecision.assessment_id == assessment_id)
    if session_id:
        stmt = stmt.where(AgentDecision.session_id == session_id)

    decisions = (await db.scalars(stmt)).all()
    return [AgentDecisionItem.model_validate(d) for d in decisions]


@router.get("/engine-info")
async def get_engine_status():
    """Returns status of the active AI model / deterministic fallback engine safely."""
    return llm_service.get_engine_status()
