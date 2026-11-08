"""
Conversational AI Security Assistant Service.
Processes natural language cybersecurity dialogue, resolves authorized targets,
coordinates assessment planning with strict scope validation, and manages chat sessions.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.llm_provider import llm_service
from app.agents.planner import AssessmentPlanner, ScopeViolationError
from app.models.models import AgentChatMessage, AgentChatSession, AuditLog, AuthorizedTarget, TargetStatus
from app.services.scope_validator import ScopeValidationService, normalize_and_validate_host


class ChatResponseDTO(BaseModel):
    session_id: str
    message_id: str
    role: str
    content: str
    engine_info: Dict[str, Any]
    plan: Optional[Dict[str, Any]] = None
    decisions: Optional[List[Dict[str, Any]]] = None
    created_at: str


class AssistantService:
    """Manages chat conversation workflow and intent routing."""

    @classmethod
    async def process_message(
        cls,
        message: str,
        db: AsyncSession,
        session_id: Optional[str] = None,
        explicit_target_id: Optional[str] = None,
        user_name: str = "security_analyst",
    ) -> ChatResponseDTO:
        # 1. Resolve or create chat session
        session = None
        if session_id:
            session = await db.get(AgentChatSession, session_id)

        if not session:
            session = AgentChatSession(
                title=message[:50] + ("..." if len(message) > 50 else ""),
                target_id=explicit_target_id,
                created_by=user_name,
            )
            db.add(session)
            await db.flush()

        # 2. Persist User Message
        user_msg = AgentChatMessage(
            session_id=session.id,
            role="user",
            content=message,
        )
        db.add(user_msg)
        await db.flush()

        # 3. Target Discovery in Query
        target: Optional[AuthorizedTarget] = None
        if explicit_target_id:
            target = await db.get(AuthorizedTarget, explicit_target_id)
            if target and target.is_deleted:
                target = None

        all_targets = (await db.scalars(
            select(AuthorizedTarget).where(AuthorizedTarget.is_deleted == False)
        )).all()

        if not target:
            # Check if user mentioned any existing target host or name
            msg_lower = message.lower()
            for t in all_targets:
                if t.host.lower() in msg_lower or t.name.lower() in msg_lower:
                    target = t
                    break

        # Check if user mentioned an IP or domain pattern that is NOT in registered targets
        unregistered_host_found = None
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", message)
        domain_match = re.search(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", message)

        candidate_host = None
        if ip_match:
            candidate_host = ip_match.group(0)
        elif domain_match and not any(ext in domain_match.group(0).lower() for ext in ["api", "ai", "vapt", "example"]):
            candidate_host = domain_match.group(0)

        if candidate_host and not target:
            # Check if this candidate host is in registered targets
            matched = False
            for t in all_targets:
                if t.host.lower() == candidate_host.lower():
                    target = t
                    matched = True
                    break
            if not matched:
                unregistered_host_found = candidate_host

        # 4. Generate AI Agent Response
        meta_info: Dict[str, Any] = {}
        plan_dict: Optional[Dict[str, Any]] = None
        decisions_list: Optional[List[Dict[str, Any]]] = None

        engine_info = llm_service.get_engine_status()

        # CASE A: User requested assessment or asked about a host that is NOT registered
        if unregistered_host_found:
            reply_text = (
                f"### ⚠️ Scope Security Alert: Unregistered Target Detected\n\n"
                f"You referenced target **`{unregistered_host_found}`**, but it is **not registered** in the authorized target allowlist.\n\n"
                f"> **Strict Scope Policy Enforced**: The AI Agent is strictly prohibited from planning or initiating assessments on unregistered infrastructure.\n\n"
                f"**Required Next Steps:**\n"
                f"1. Navigate to the **Target Scope** registry.\n"
                f"2. Add `{unregistered_host_found}` along with valid authorization reference, validity dates, and port permissions.\n"
                f"3. Return here to generate your customized assessment plan."
            )
            meta_info["scope_violation"] = True
            meta_info["unregistered_host"] = unregistered_host_found

        # CASE B: Target is provided or resolved
        elif target:
            # Update session target association
            if not session.target_id:
                session.target_id = target.id

            # Check target status
            if target.status == TargetStatus.REVOKED.value:
                reply_text = (
                    f"### 🛑 Target Authorization Revoked\n\n"
                    f"Target **`{target.host}`** (`{target.name}`) is currently in **REVOKED** status.\n\n"
                    f"- **Revocation Reason:** *{target.revocation_reason or 'Explicitly revoked by operator.'}*\n"
                    f"- **Revoked At:** `{target.revoked_at or 'Previously'}`\n\n"
                    f"Under platform security rules, all automated planning and tool execution against revoked targets is blocked with HTTP 403."
                )
                meta_info["scope_status"] = "REVOKED"
            elif target.status == TargetStatus.EXPIRED.value:
                reply_text = (
                    f"### ⏳ Target Authorization Expired\n\n"
                    f"Target **`{target.host}`** (`{target.name}`) authorization validity window has **expired** (Expired on: `{target.valid_to}`).\n\n"
                    f"Please renew the target's authorization validity window in the **Target Scope** page before proceeding."
                )
                meta_info["scope_status"] = "EXPIRED"
            else:
                # Target is ACTIVE — Generate Full Intelligent Plan
                try:
                    plan_result = await AssessmentPlanner.plan_assessment(
                        target_id=target.id,
                        requirements=message,
                        db=db,
                        assessment_type="full_vapt",
                        session_id=session.id,
                        operator=user_name,
                    )
                    plan_dict = plan_result.model_dump()
                    decisions_list = [d.model_dump() for d in plan_result.decisions]

                    stages_md = "\n".join([
                        f"| {s.stage_number} | **{s.name}** | `{', '.join(s.recommended_tools)}` | {'🔒 Human Approval' if s.requires_human_approval else '✅ Automated'} |"
                        for s in plan_result.stages
                    ])

                    tools_md = "\n".join([
                        f"- **{t['tool']}** ({t['category']}): {t['rationale']}"
                        for t in plan_result.tool_recommendations
                    ])

                    reply_text = (
                        f"### 🛡️ Authorized Assessment Plan Generated\n\n"
                        f"I have verified active authorization for **`{target.host}`** (Ref: `{target.auth_reference or 'Active Authorization'}`).\n\n"
                        f"#### 📋 Planned Assessment Stages\n\n"
                        f"| # | Stage | Recommended Scanners | Mode |\n"
                        f"|:---|:---|:---|:---|\n"
                        f"{stages_md}\n\n"
                        f"#### 🛠️ Scanner Recommendations & Rationale\n\n"
                        f"{tools_md}\n\n"
                        f"#### 🔍 Scope Boundaries Enforced\n"
                        f"- **Permitted Ports:** `{target.permitted_ports or 'All non-excluded'}`\n"
                        f"- **Excluded Ports:** `{target.excluded_ports or 'None'}`\n"
                        f"- **Excluded URL Paths:** `{target.excluded_paths or 'None'}`\n"
                        f"- **Decision Trace:** `{len(plan_result.decisions)} decisions recorded with observations vs inferences.`\n\n"
                        f"> [!TIP]\n"
                        f"> Click **\"Initialize Assessment with This Plan\"** below to bind this plan directly to an engagement."
                    )

                    meta_info["plan"] = plan_dict
                    meta_info["decisions"] = decisions_list
                    meta_info["target_id"] = target.id
                    meta_info["target_host"] = target.host
                except ScopeViolationError as sve:
                    reply_text = f"### ⚠️ Scope Enforcement Denied Planning\n\n{str(sve)}"
                    meta_info["scope_violation"] = True

        # CASE C: General Cybersecurity & Agent Dialogue
        else:
            # Call LLM service (or deterministic fallback)
            context = {
                "active_targets_count": len([t for t in all_targets if t.status == TargetStatus.ACTIVE.value]),
                "registered_targets": [{"host": t.host, "name": t.name} for t in all_targets[:5]],
            }
            llm_res = await llm_service.generate_response(
                prompt=message,
                system_prompt="You are an expert AI Cybersecurity Assistant and VAPT Planner. Provide structured, actionable cybersecurity guidance.",
                context=context,
            )
            reply_text = llm_res.content
            meta_info["provider"] = llm_res.provider
            meta_info["model"] = llm_res.model
            meta_info["is_fallback"] = llm_res.is_fallback

        meta_info["engine_info"] = engine_info

        # 5. Persist Assistant Response
        assistant_msg = AgentChatMessage(
            session_id=session.id,
            role="assistant",
            content=reply_text,
            meta_info=json.dumps(meta_info),
        )
        db.add(assistant_msg)

        # 6. Audit Log
        db.add(AuditLog(
            actor=user_name,
            action="agent.chat_interaction",
            resource_type="agent_chat_session",
            resource_id=session.id,
            detail=f"Prompt: {message[:100]} | Plan generated: {bool(plan_dict)}",
        ))

        await db.commit()
        await db.refresh(assistant_msg)

        return ChatResponseDTO(
            session_id=session.id,
            message_id=assistant_msg.id,
            role="assistant",
            content=reply_text,
            engine_info=engine_info,
            plan=plan_dict,
            decisions=decisions_list,
            created_at=assistant_msg.created_at.isoformat(),
        )
