"""
AI Vulnerability Correlator & Attack Chain Mapper.
Correlates findings across Nmap, Nikto, and OWASP ZAP, maps potential attack chains,
flags suspicious false positives by comparing scanner claims against verified banners,
and produces actionable, prioritized remediation guidance.
Distinguishes verified observations from AI inferences.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional
from pydantic import BaseModel

from app.agents.llm_provider import llm_service
from app.models.models import Finding

logger = logging.getLogger(__name__)


class CorrelationResult(BaseModel):
    assessment_id: str
    target_host: str
    engine: str  # "gemini_llm" or "deterministic_rule_engine"
    total_findings: int
    attack_chains: List[Dict[str, Any]]
    suspicious_false_positives: List[Dict[str, Any]]
    remediation_roadmap: List[Dict[str, Any]]
    analyst_summary: str


class VulnerabilityCorrelator:
    """
    Correlates multi-scanner findings to provide holistic threat intelligence.
    """

    @classmethod
    async def correlate_assessment(
        cls,
        assessment_id: str,
        target_host: str,
        findings: List[Finding],
    ) -> CorrelationResult:
        if not findings:
            return CorrelationResult(
                assessment_id=assessment_id,
                target_host=target_host,
                engine="deterministic_rule_engine",
                total_findings=0,
                attack_chains=[],
                suspicious_false_positives=[],
                remediation_roadmap=[],
                analyst_summary="No vulnerabilities or scanner observations recorded for this assessment yet.",
            )

        # 1. Inspect verified services from Nmap/probes
        verified_services: Dict[int, str] = {}
        for f in findings:
            if "nmap" in (f.source_tool or "").lower() and f.port:
                verified_services[f.port] = (f.service or "").lower()
                if f.evidence and "banner:" in f.evidence.lower():
                    verified_services[f.port] += " " + f.evidence.lower()

        # 2. Detect Suspicious False Positives (Contradictions between scanner alerts and verified banners)
        suspicious_fps: List[Dict[str, Any]] = []
        for f in findings:
            f_tool = (f.source_tool or "").lower()
            if "nmap" not in f_tool and f.port and f.port in verified_services:
                banner_info = verified_services[f.port]
                title_lower = (f.title or "").lower()
                desc_lower = (f.description or "").lower()

                # Contradiction: Alert specifies Apache, but banner is Nginx or IIS
                if "apache" in title_lower and "nginx" in banner_info:
                    suspicious_fps.append({
                        "finding_id": f.id,
                        "finding_title": f.title,
                        "source_tool": f.source_tool,
                        "port": f.port,
                        "observed_evidence": f"Port {f.port} verified service banner is: {banner_info}",
                        "ai_inference": "Tool triggered generic Apache signature, but network port runs Nginx. High likelihood of false positive.",
                        "recommended_action": "Flag as potential false positive pending analyst manual verification.",
                    })
                elif "iis" in title_lower and ("linux" in banner_info or "apache" in banner_info):
                    suspicious_fps.append({
                        "finding_id": f.id,
                        "finding_title": f.title,
                        "source_tool": f.source_tool,
                        "port": f.port,
                        "observed_evidence": f"Port {f.port} verified banner indicates non-Windows system: {banner_info}",
                        "ai_inference": "Microsoft IIS signature matched against non-Windows banner. Likely false positive.",
                        "recommended_action": "Verify server OS before remediation.",
                    })

        # 3. Construct Attack Chains across Recon -> Web -> Exploitation
        recon_findings = [f for f in findings if (f.severity or "").lower() in ["info", "informational", "low"]]
        web_findings = [f for f in findings if any(t in (f.title or "").lower() for t in ["header", "cookie", "directory", "traversal", "method", "nikto"])]
        exploit_findings = [f for f in findings if (f.severity or "").lower() in ["high", "critical"] or f.cve_id]

        attack_chains: List[Dict[str, Any]] = []

        if exploit_findings and (web_findings or recon_findings):
            top_exploit = exploit_findings[0]
            chain_steps = [
                {
                    "stage": "1. Reconnaissance & Discovery",
                    "observation": f"Port {top_exploit.port or 80} exposed on {target_host} running {top_exploit.service or 'HTTP'} service.",
                    "source": "Nmap Network Scanner",
                },
                {
                    "stage": "2. Enumeration & Surface Mapping",
                    "observation": f"Web scanner discovered misconfigurations / sensitive endpoints: {web_findings[0].title if web_findings else 'Standard HTTP endpoints exposed'}",
                    "source": "Nikto / OWASP ZAP",
                },
                {
                    "stage": "3. Potential Exploitation Vector",
                    "observation": f"High-risk condition: {top_exploit.title} (Severity: {top_exploit.severity.upper()}, Evidence: {top_exploit.evidence or 'N/A'})",
                    "inference": "An adversary could leverage reconnaissance findings to locate vulnerable endpoints and deploy targeted payloads.",
                    "source": top_exploit.source_tool,
                },
            ]
            attack_chains.append({
                "chain_id": f"chain-{target_host.replace('.', '-')}",
                "title": f"Attack Vector: {top_exploit.title} via Port {top_exploit.port or 80}",
                "severity": top_exploit.severity.capitalize(),
                "steps": chain_steps,
            })

        # 4. Actionable Remediation Roadmap
        sorted_findings = sorted(findings, key=lambda x: x.risk_score or 0.0, reverse=True)
        remediation_roadmap: List[Dict[str, Any]] = []
        for idx, f in enumerate(sorted_findings[:5], start=1):
            sev = (f.severity or "informational").capitalize()
            remediation_roadmap.append({
                "priority_rank": idx,
                "finding_id": f.id,
                "title": f.title,
                "severity": sev,
                "risk_score": f.risk_score,
                "target": f"{target_host}:{f.port or 80}{f.url_path or ''}",
                "remediation_action": (
                    f"Patch or upgrade software component ({f.service or 'service'}). "
                    f"Enforce strict input validation, restrict network access to port {f.port or 80}, "
                    f"and disable unnecessary debug/management interfaces."
                ),
            })

        # 5. Check if LLM is available for enhanced narrative
        engine_name = "deterministic_rule_engine"
        summary_text = (
            f"Cross-tool correlation analyzed {len(findings)} findings for target {target_host}. "
            f"Detected {len(attack_chains)} composite attack vector(s) and flagged "
            f"{len(suspicious_fps)} potential false positive contradiction(s). "
            f"Primary remediation urgency should focus on {len(exploit_findings)} high/critical items."
        )

        engine_info = llm_service.get_engine_status()
        if not engine_info.get("is_fallback"):
            prompt = (
                f"You are a Senior Penetration Tester analyzing consolidated vulnerability findings for target {target_host}.\n"
                f"Findings count: {len(findings)}\n"
                f"Top findings: {[f.title + ' (' + f.severity + ')' for f in sorted_findings[:5]]}\n"
                f"Suspicious contradictions: {len(suspicious_fps)}\n"
                "Provide a concise, 2-3 sentence executive analyst summary highlighting the primary attack chain and immediate defensive priorities. "
                "Distinguish observed scanner facts from inferences. Do not hallucinate CVEs."
            )
            try:
                gen_result = await llm_service.generate_response(prompt)
                if gen_result and gen_result.content.strip():
                    summary_text = gen_result.content.strip()
                    engine_name = "gemini_llm" if "gemini" in gen_result.provider.lower() else f"{gen_result.provider}_llm"
            except Exception as e:
                logger.warning(f"LLM correlation failed, using deterministic summary: {e}")

        return CorrelationResult(
            assessment_id=assessment_id,
            target_host=target_host,
            engine=engine_name,
            total_findings=len(findings),
            attack_chains=attack_chains,
            suspicious_false_positives=suspicious_fps,
            remediation_roadmap=remediation_roadmap,
            analyst_summary=summary_text,
        )
