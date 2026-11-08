"""
Risk Prioritization Engine.
Calculates multi-factor risk scores (0.0 to 100.0) with transparent,
evidence-based mathematical explanations. No fabricated CVSS scores.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple


class RiskPrioritizer:
    """
    Transparent multi-factor risk scoring engine.
    
    Formula:
      Score = min(100.0, max(0.0, (Base + Exposure + Exploitability) * ConfidenceMultiplier))
    """

    SEVERITY_BASE = {
        "critical": 90.0,
        "high": 70.0,
        "medium": 45.0,
        "low": 20.0,
        "informational": 5.0,
        "info": 5.0,
    }

    WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000}
    INSECURE_PORTS = {21, 23, 69, 110, 143}  # Plaintext FTP, Telnet, TFTP, POP3, IMAP

    @classmethod
    def calculate_risk(
        cls,
        severity: str,
        cvss_score: Optional[float] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        cve_id: Optional[str] = None,
        cwe_id: Optional[str] = None,
        evidence: Optional[str] = None,
        confidence: Optional[str] = "Medium",
        is_false_positive: bool = False,
    ) -> Tuple[float, str]:
        """
        Returns (risk_score, risk_explanation).
        """
        if is_false_positive:
            return 0.0, "Risk Score: 0.0/100 (Flagged as False Positive by analyst/correlator)"

        sev_key = (severity or "informational").lower()
        explanation_parts = []

        # 1. Base Score from CVSS (if genuine) or Severity level
        if cvss_score is not None and 0.0 <= cvss_score <= 10.0:
            base_score = round(cvss_score * 10.0, 1)
            explanation_parts.append(f"Base Score: {base_score} (from genuine scanner CVSS {cvss_score})")
        else:
            base_score = cls.SEVERITY_BASE.get(sev_key, 10.0)
            explanation_parts.append(f"Base Score: {base_score} ({severity.capitalize()} severity baseline)")

        # 2. Exposure Modifier (Port & Service Exposure)
        exposure_adj = 0.0
        if port is not None:
            if port in cls.WEB_PORTS:
                exposure_adj += 5.0
                explanation_parts.append(f"Exposure: +5.0 (Standard web-facing service on port {port})")
            elif port in cls.INSECURE_PORTS:
                exposure_adj += 10.0
                explanation_parts.append(f"Exposure: +10.0 (Legacy unencrypted management service on port {port})")
            else:
                exposure_adj += 2.0
                explanation_parts.append(f"Exposure: +2.0 (Active service listening on port {port})")

        # 3. Exploitability & Real Evidence Modifier
        exploit_adj = 0.0
        evidence_text = (evidence or "").lower()
        if cve_id:
            exploit_adj += 10.0
            explanation_parts.append(f"Exploitability: +10.0 (Documented public CVE identifier: {cve_id})")
        
        if any(term in evidence_text for term in ["remote code", "command injection", "sql injection", "sqli", "rce"]):
            exploit_adj += 10.0
            explanation_parts.append("Exploitability: +10.0 (High-impact vulnerability signature confirmed in evidence)")
        elif any(term in evidence_text for term in ["traversal", "xss", "cross-site scripting", "bypass", "unauthenticated"]):
            exploit_adj += 5.0
            explanation_parts.append("Exploitability: +5.0 (Direct authorization or data access impact)")

        # 4. Confidence Multiplier
        conf_str = (confidence or "Medium").lower()
        if "confirm" in conf_str or "high" in conf_str:
            conf_mult = 1.0
            explanation_parts.append("Confidence: 1.0x (High / Multi-tool confirmed)")
        elif "low" in conf_str:
            conf_mult = 0.7
            explanation_parts.append("Confidence: 0.7x (Low confidence scanner heuristic)")
        else:
            conf_mult = 0.85
            explanation_parts.append("Confidence: 0.85x (Medium confidence scanner observation)")

        # Final Score Calculation
        unscaled = (base_score + exposure_adj + exploit_adj) * conf_mult
        final_score = round(min(100.0, max(0.0, unscaled)), 1)

        explanation = " | ".join(explanation_parts) + f" => Final Risk Score: {final_score}/100"
        return final_score, explanation
