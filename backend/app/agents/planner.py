"""
Intelligent Assessment Planner Engine.
Accepts natural language assessment requests, binds them to authorized target scope,
evaluates tool applicability, generates ordered assessment stages, and emits
granular decision traces distinguishing concrete observations from AI inferences.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.llm_provider import llm_service
from app.models.models import AgentDecision, AuthorizedTarget, Finding, ScanJob, TargetStatus
from app.services.scope_validator import ScopeValidationService


class PlanDecision(BaseModel):
    id: str
    stage: str
    selected_tool: str
    rationale: str
    evidence_and_observations: str
    ai_inferences: str
    execution_status: str
    parameters: Optional[Dict[str, Any]] = None
    created_at: str


class PlanStage(BaseModel):
    stage_number: int
    name: str
    category: str
    description: str
    recommended_tools: List[str]
    rationale: str
    requires_human_approval: bool = False


class AssessmentPlanResult(BaseModel):
    plan_id: str
    target_id: str
    target_host: str
    target_name: str
    auth_reference: Optional[str]
    assessment_name: str
    assessment_type: str
    scope_status: str
    summary: str
    stages: List[PlanStage]
    tool_recommendations: List[Dict[str, Any]]
    decisions: List[PlanDecision]
    engine_info: Dict[str, Any]
    created_at: str


class ScopeViolationError(Exception):
    """Raised when an assessment request targets an unauthorized, expired or revoked resource."""
    pass


class AssessmentPlanner:
    """Core Planner that analyzes requirements and builds authorized assessment workflows."""

    @classmethod
    async def plan_assessment(
        cls,
        target_id: str,
        requirements: str,
        db: AsyncSession,
        assessment_type: str = "full_vapt",
        selected_categories: Optional[List[str]] = None,
        session_id: Optional[str] = None,
        operator: str = "security_analyst",
    ) -> AssessmentPlanResult:
        # 1. Fetch target
        target = await db.get(AuthorizedTarget, target_id)
        if not target or target.is_deleted:
            raise ScopeViolationError(f"Target with ID '{target_id}' is not registered in the allowlist.")

        # 2. Scope Validation
        val_res = await ScopeValidationService.validate_scope(
            session=db,
            requested_target=target.host,
            requested_action="assessment_planning",
            actor=operator,
        )

        if not val_res.allowed:
            raise ScopeViolationError(
                f"Scope Enforcer Rejected Planning on '{target.host}': {val_res.reason}"
            )

        if target.status != TargetStatus.ACTIVE.value:
            raise ScopeViolationError(
                f"Cannot plan assessment on target '{target.host}' with status '{target.status}'. Target must be ACTIVE."
            )

        # 3. Analyze Parameters & Scope
        permitted_ports = target.permitted_ports or "80, 443"
        excluded_ports = target.excluded_ports or "None"
        excluded_paths = target.excluded_paths or "None"
        restrictions = target.restrictions or "Safe vulnerability assessment only; no destructive actions."

        # Fetch actual previous findings and scan history for target (context-aware reasoning)
        prev_findings = (await db.scalars(
            select(Finding).where(Finding.host == target.host, Finding.is_false_positive == False)
        )).all()
        prev_scans = (await db.scalars(
            select(ScanJob).where(ScanJob.target_host == target.host)
        )).all()

        history_summary = (
            f"{len(prev_findings)} previous finding(s) on record for {target.host}"
            if prev_findings
            else f"Zero previous findings on record for {target.host} (awaiting scanner report ingestion)"
        )

        # Parse categories
        req_lower = requirements.lower()
        categories = selected_categories or []
        if not categories:
            categories = ["network_discovery", "web_vapt", "server_config", "tls_audit"]

        plan_id = str(uuid.uuid4())
        now_iso = datetime.now(timezone.utc).isoformat()
        decisions: List[PlanDecision] = []
        stages: List[PlanStage] = []
        tool_recommendations: List[Dict[str, Any]] = []

        # ── Stage 1: Reconnaissance & Port Discovery ──────────────────────────
        # TOOL CAPABILITY REALITY: Nmap CLI binary is NOT INSTALLED on host.
        # Parser ingestion is AVAILABLE in IMPORT ONLY mode.
        s1_obs = (
            f"Target host '{target.host}' verified in active scope. Permitted ports: [{permitted_ports}]; Excluded ports: [{excluded_ports}]. "
            f"History: {history_summary}. Tool status: Nmap executable is NOT INSTALLED; XML parser is IMPORT ONLY."
        )
        s1_inf = (
            f"Initial non-destructive TCP SYN service discovery is required to identify open listening ports without triggering firewall blocks. "
            f"Because Nmap executable is not installed locally, automated live scanning cannot execute directly. "
            f"Recommendation: Run Nmap externally ('nmap -sS -sV -p {permitted_ports} -oX nmap_results.xml {target.host}') and ingest via Tool Integrations > Ingest Scanner Reports."
        )
        s1_dec_id = str(uuid.uuid4())

        s1_tool = {
            "tool": "Nmap",
            "display_name": "Nmap XML Parser",
            "category": "Network Discovery",
            "recommended": True,
            "mode": "IMPORT_ONLY",
            "executable_status": "NOT_INSTALLED",
            "flags": f"-sS -sV -p {permitted_ports} --open -oX <report.xml> (Import Only)",
            "rationale": f"Ingests external Nmap XML scan results for {target.host} enforcing permitted ports [{permitted_ports}]. Local CLI binary is not installed.",
        }
        tool_recommendations.append(s1_tool)

        decisions.append(PlanDecision(
            id=s1_dec_id,
            stage="RECONNAISSANCE",
            selected_tool="Nmap XML Parser",
            rationale="Establish accurate inventory of open ports and running service banners. Can execute live: NO (CLI not installed). Next step: Ingest external Nmap XML report.",
            evidence_and_observations=s1_obs,
            ai_inferences=s1_inf,
            execution_status="PLANNED",
            parameters={"ports": permitted_ports, "flags": "-sS -sV", "scan_type": "SYN_PORT_DISCOVERY", "mode": "IMPORT_ONLY"},
            created_at=now_iso,
        ))

        stages.append(PlanStage(
            stage_number=1,
            name="Passive Reconnaissance & Port Discovery (Nmap XML Ingestion)",
            category="Network Discovery",
            description=f"Map reachable network services on {target.host} via Nmap XML report ingestion (Local executable: NOT INSTALLED).",
            recommended_tools=["Nmap XML Parser (Import Only)"],
            rationale="Confirm open services before launching web-layer audits. Uses report ingestion to preserve evidence without live subprocess requirement.",
            requires_human_approval=False,
        ))

        # ── Stage 2: Web Server Configuration Inspection ──────────────────────
        has_web = any(term in permitted_ports for term in ["80", "443", "8080", "8443"]) or target.target_url is not None
        if has_web or "server_config" in categories or "web" in req_lower:
            s2_obs = (
                f"HTTP/HTTPS service detected in target specification ({target.target_url or target.host}). Excluded paths: [{excluded_paths}]. "
                f"Tool capability: Nikto integration mode is IMPORT ONLY."
            )
            s2_inf = (
                "Web server misconfigurations (dangerous HTTP methods, outdated software tokens, missing security headers) expose high risk. "
                "Because Nikto runs in report import mode, the operator should execute Nikto externally (-Format json or xml) and upload the report to the platform."
            )
            s2_dec_id = str(uuid.uuid4())

            s2_tool = {
                "tool": "Nikto",
                "display_name": "Nikto Parser",
                "category": "Web Server Security",
                "recommended": True,
                "mode": "IMPORT_ONLY",
                "executable_status": "IMPORT_ONLY",
                "flags": f"-host {target.host} -Format json -output nikto.json (Import Only)",
                "rationale": "Ingests official Nikto JSON or XML reports to identify dangerous files, HTTP headers, and server CVEs.",
            }
            tool_recommendations.append(s2_tool)

            decisions.append(PlanDecision(
                id=s2_dec_id,
                stage="CONFIG_AUDIT",
                selected_tool="Nikto Parser",
                rationale="Audit server headers, cookie security flags, and known software vulnerabilities. Can execute live: NO (Import-only mode). Next step: Ingest Nikto report.",
                evidence_and_observations=s2_obs,
                ai_inferences=s2_inf,
                execution_status="PLANNED",
                parameters={"target": target.host, "mode": "IMPORT_ONLY", "excluded_paths": excluded_paths},
                created_at=now_iso,
            ))

            stages.append(PlanStage(
                stage_number=2,
                name="Web Server Configuration & Header Audit (Nikto Ingestion)",
                category="Server Configuration",
                description="Evaluate HTTP security headers, server components, and known web server CVEs via Nikto JSON/XML ingestion.",
                recommended_tools=["Nikto Parser (Import Only)"],
                rationale="Detect baseline security flaws in web server configuration before dynamic spidering.",
                requires_human_approval=False,
            ))

        # ── Stage 3: Dynamic Application Vulnerability Scanning (DAST) ────────
        if has_web or "web_vapt" in categories or "web" in req_lower:
            s3_obs = (
                f"Active web application endpoints present. Strict path exclusions: [{excluded_paths}] take precedence over spidering. "
                f"Tool capability: OWASP ZAP is configured in IMPORT ONLY mode."
            )
            s3_inf = (
                "Dynamic application testing uncovers OWASP Top 10 vulnerabilities (XSS, Injection, SSRF). "
                "Because ZAP runs in report import mode, export alerts from OWASP ZAP (JSON or XML) and upload via the Ingestion Hub."
            )
            s3_dec_id = str(uuid.uuid4())

            s3_tool = {
                "tool": "OWASP ZAP",
                "display_name": "OWASP ZAP Parser",
                "category": "DAST & Web Vulnerability",
                "recommended": True,
                "mode": "IMPORT_ONLY",
                "executable_status": "IMPORT_ONLY",
                "flags": f"Export Alerts -> JSON/XML (respecting exclusions {excluded_paths})",
                "rationale": "Normalizes dynamic application security testing alerts and maps to CWE/WASC categories via report ingestion.",
            }
            tool_recommendations.append(s3_tool)

            decisions.append(PlanDecision(
                id=s3_dec_id,
                stage="WEB_APPLICATION_TESTING",
                selected_tool="OWASP ZAP Parser",
                rationale="Detect injection vulnerabilities, cross-site scripting, and broken authentication. Can execute live: NO (Import-only mode). Next step: Ingest ZAP report.",
                evidence_and_observations=s3_obs,
                ai_inferences=s3_inf,
                execution_status="PLANNED",
                parameters={"excluded_paths": excluded_paths, "policy": "OWASP_TOP_10", "mode": "IMPORT_ONLY"},
                created_at=now_iso,
            ))

            stages.append(PlanStage(
                stage_number=3,
                name="Dynamic Application Vulnerability Testing (OWASP ZAP Ingestion)",
                category="Web Application VAPT",
                description="Spider web application endpoints and ingest normalized findings without traversing excluded paths.",
                recommended_tools=["OWASP ZAP Parser (Import Only)"],
                rationale="Identifies runtime vulnerabilities in web forms, query parameters, and API endpoints via verified report evidence.",
                requires_human_approval=False,
            ))

        # ── Stage 4: Cryptographic & TLS Security Verification ────────────────
        if "443" in permitted_ports or "8443" in permitted_ports or (target.target_url and "https" in target.target_url):
            s4_obs = "TLS/HTTPS protocol active in scope profile."
            s4_inf = "Weak ciphers, deprecated TLS 1.0/1.1 protocols, or expiring certificates can compromise data in transit."
            s4_dec_id = str(uuid.uuid4())

            decisions.append(PlanDecision(
                id=s4_dec_id,
                stage="CRYPTO_AUDIT",
                selected_tool="SSL/TLS Analyzer",
                rationale="Audit TLS protocol versions, cipher suite grades, and X.509 certificate trust chains.",
                evidence_and_observations=s4_obs,
                ai_inferences=s4_inf,
                execution_status="PLANNED",
                parameters={"port": 443, "check_protocols": ["TLSv1.2", "TLSv1.3"]},
                created_at=now_iso,
            ))

            stages.append(PlanStage(
                stage_number=4,
                name="Cryptographic & TLS Protocol Audit",
                category="Cryptographic Audit",
                description="Analyze TLS/SSL implementation, cipher suite strength, and certificate validity.",
                recommended_tools=["SSL/TLS Analyzer"],
                rationale="Verifies data-in-transit security against POODLE, Heartbleed, and weak cipher downgrade attacks.",
                requires_human_approval=False,
            ))

        # ── Stage 5: Active Verification & Exploitation Gate ──────────────────
        s5_obs = "Active exploitation or intrusive verification modules could cause denial of service or state alteration."
        s5_inf = "Autonomous exploitation is forbidden. Any intrusive validation step must require explicit Human Approval from the operator."
        s5_dec_id = str(uuid.uuid4())

        s5_tool = {
            "tool": "Metasploit",
            "category": "Exploitation Validation",
            "recommended": False,
            "flags": "Requires Human Approval in Approval Center",
            "rationale": "Held in PENDING_APPROVAL status. Cannot be executed autonomously."
        }
        tool_recommendations.append(s5_tool)

        decisions.append(PlanDecision(
            id=s5_dec_id,
            stage="EXPLOITATION_VALIDATION",
            selected_tool="Metasploit",
            rationale="Gated behind mandatory human authorization before any proof-of-concept payload can be dispatched.",
            evidence_and_observations=s5_obs,
            ai_inferences=s5_inf,
            execution_status="PENDING_APPROVAL",
            parameters={"policy": "HUMAN_APPROVAL_MANDATORY", "auto_run": False},
            created_at=now_iso,
        ))

        stages.append(PlanStage(
            stage_number=len(stages) + 1,
            name="Intrusive Verification Gate (Human-In-The-Loop)",
            category="Active Verification",
            description="Holds any active proof-of-concept validation in Approval Center awaiting analyst sign-off.",
            recommended_tools=["Metasploit (Held)"],
            rationale="Ensures zero unexpected operational downtime and enforces strict authorization protocol.",
            requires_human_approval=True,
        ))

        # ── Stage 6: Cross-Tool Correlation & Risk Prioritization ─────────────
        s6_obs = "Raw outputs from Nmap, Nikto, and ZAP generate disparate finding schemas."
        s6_inf = "Vulnerability normalization and CVSS cross-tool deduplication prevents alert fatigue and highlights actionable criticals."
        s6_dec_id = str(uuid.uuid4())

        decisions.append(PlanDecision(
            id=s6_dec_id,
            stage="CORRELATION_AND_REPORTING",
            selected_tool="Correlation Engine",
            rationale="Deduplicate multi-scanner findings, correlate CVE identifiers, and calculate composite risk score.",
            evidence_and_observations=s6_obs,
            ai_inferences=s6_inf,
            execution_status="PLANNED",
            parameters={"deduplicate_cve": True, "cvss_v3_scoring": True},
            created_at=now_iso,
        ))

        stages.append(PlanStage(
            stage_number=len(stages) + 1,
            name="Cross-Tool Finding Normalization & Risk Prioritization",
            category="Reporting & Analytics",
            description="Normalize scanner evidence, deduplicate overlapping findings, and generate remediation guidance.",
            recommended_tools=["Correlation Engine"],
            rationale="Transforms raw multi-scanner outputs into a prioritized, executive-ready security report.",
            requires_human_approval=False,
        ))

        # 4. Persist Decisions to DB
        for d in decisions:
            db_decision = AgentDecision(
                id=d.id,
                target_id=target.id,
                session_id=session_id,
                stage=d.stage,
                selected_tool=d.selected_tool,
                rationale=d.rationale,
                evidence_and_observations=d.evidence_and_observations,
                ai_inferences=d.ai_inferences,
                execution_status=d.execution_status,
                parameters=json.dumps(d.parameters) if d.parameters else None,
            )
            db.add(db_decision)

        # 5. Engine Status
        engine_status = llm_service.get_engine_status()

        summary_text = (
            f"Tailored {len(stages)}-stage vulnerability assessment plan generated for authorized target '{target.host}'. "
            f"Enforces permitted ports [{permitted_ports}], excludes [{excluded_ports}], and respects path exclusions [{excluded_paths}]. "
            f"Recommended primary scanners: {', '.join([t['tool'] for t in tool_recommendations if t['recommended']])}. "
            f"All active exploitation validation is gated in PENDING_APPROVAL status."
        )

        return AssessmentPlanResult(
            plan_id=plan_id,
            target_id=target.id,
            target_host=target.host,
            target_name=target.name,
            auth_reference=target.auth_reference,
            assessment_name=f"{target.name} — Scoped VAPT Assessment",
            assessment_type=assessment_type,
            scope_status=target.status,
            summary=summary_text,
            stages=stages,
            tool_recommendations=tool_recommendations,
            decisions=decisions,
            engine_info=engine_status,
            created_at=now_iso,
        )
