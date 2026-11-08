"""
Vulnerability Deduplication & Evidence Management Service.
Fingerprints findings via SHA-256 and merges cross-tool evidence without
overwriting original scanner artifacts or merging across different hosts/assets.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Finding
from app.scanners.parsers import ParsedFinding
from app.services.risk_prioritizer import RiskPrioritizer

logger = logging.getLogger(__name__)


def compute_finding_fingerprint(
    host: str,
    port: Optional[int] = None,
    url_path: Optional[str] = None,
    cve_id: Optional[str] = None,
    cwe_id: Optional[str] = None,
    title: Optional[str] = None,
) -> str:
    """
    Computes a deterministic SHA-256 fingerprint for a finding.
    
    Guarantees:
      - Different hosts will NEVER produce identical fingerprints.
      - Different ports on the same host will produce distinct fingerprints.
      - Same vulnerability discovered by different scanners on the same host/port/path will match.
    """
    clean_host = (host or "unknown_host").strip().lower()
    clean_port = str(port) if port is not None else ""
    clean_path = (url_path or "").strip().lower()
    if clean_path.endswith("/") and len(clean_path) > 1:
        clean_path = clean_path.rstrip("/")

    # Vulnerability canonical key
    if cve_id and cve_id.strip():
        # CVE uniquely identifies vulnerability on this host and port across scanners
        canon = f"CVE:{cve_id.strip().upper()}"
        raw_signature = f"{clean_host}|{clean_port}|{canon}"
    elif cwe_id and cwe_id.strip():
        canon = f"CWE:{cwe_id.strip().upper()}"
        raw_signature = f"{clean_host}|{clean_port}|{clean_path}|{canon}"
    else:
        # Normalize title: remove punctuation and whitespace, lowercase, truncate
        raw_title = title or "unspecified_vulnerability"
        simplified = re.sub(r"[^a-z0-9]", "", raw_title.lower())[:60]
        canon = f"TITLE:{simplified}"
        raw_signature = f"{clean_host}|{clean_port}|{clean_path}|{canon}"

    return hashlib.sha256(raw_signature.encode("utf-8")).hexdigest()


SEVERITY_ORDER = {
    "informational": 0,
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


async def deduplicate_and_persist_findings(
    parsed_findings: List[ParsedFinding],
    assessment_id: str,
    scan_job_id: Optional[str],
    session: AsyncSession,
) -> List[Finding]:
    """
    Persists parsed findings into the database, performing cross-tool deduplication.
    Merges evidence artifacts when matching fingerprints are detected.
    """
    persisted: List[Finding] = []
    now_iso = datetime.now(timezone.utc).isoformat()

    for p in parsed_findings:
        fp = compute_finding_fingerprint(
            host=p.host,
            port=p.port,
            url_path=p.url_path,
            cve_id=p.cve_id,
            cwe_id=p.cwe_id,
            title=p.title,
        )

        # Check if finding already exists in this assessment
        query = select(Finding).where(
            Finding.assessment_id == assessment_id,
            Finding.fingerprint == fp,
        )
        result = await session.execute(query)
        existing_finding = result.scalars().first()

        new_artifact_entry = {
            "source_tool": p.source_tool,
            "recorded_at": now_iso,
            "evidence": p.evidence,
            "scanner_reference": p.scanner_reference,
            "raw": p.raw_artifact,
        }

        if existing_finding:
            # Duplicate / Cross-tool observation detected!
            # 1. Update source_tool if new
            current_tools = [t.strip() for t in (existing_finding.source_tool or "").split(",") if t.strip()]
            if p.source_tool not in current_tools:
                current_tools.append(p.source_tool)
                existing_finding.source_tool = ", ".join(current_tools)

            # 2. Append to raw_evidence_artifacts without overwriting original scanner traces
            artifacts_list: List[Dict[str, Any]] = []
            if existing_finding.raw_evidence_artifacts:
                try:
                    artifacts_list = json.loads(existing_finding.raw_evidence_artifacts)
                except Exception:
                    artifacts_list = [{"legacy_evidence": existing_finding.raw_evidence_artifacts}]
            artifacts_list.append(new_artifact_entry)
            existing_finding.raw_evidence_artifacts = json.dumps(artifacts_list)

            # 3. Upgrade severity if higher
            existing_rank = SEVERITY_ORDER.get((existing_finding.severity or "informational").lower(), 0)
            new_rank = SEVERITY_ORDER.get((p.severity or "informational").lower(), 0)
            if new_rank > existing_rank:
                existing_finding.severity = p.severity.lower()

            # 4. Enrich CVE/CWE and URL path if newly supplied
            if not existing_finding.cve_id and p.cve_id:
                existing_finding.cve_id = p.cve_id
            if not existing_finding.cwe_id and p.cwe_id:
                existing_finding.cwe_id = p.cwe_id
            if not existing_finding.url_path and p.url_path:
                existing_finding.url_path = p.url_path

            # 5. Multi-tool corroboration increases confidence to Confirmed
            if len(current_tools) > 1:
                existing_finding.confidence = "Confirmed"

            # 6. Recalculate risk score
            score, explanation = RiskPrioritizer.calculate_risk(
                severity=existing_finding.severity,
                cvss_score=existing_finding.cvss_score or p.cvss_score,
                host=existing_finding.host,
                port=existing_finding.port,
                cve_id=existing_finding.cve_id,
                cwe_id=existing_finding.cwe_id,
                evidence=f"{existing_finding.evidence or ''} {p.evidence or ''}",
                confidence=existing_finding.confidence,
                is_false_positive=existing_finding.is_false_positive,
            )
            existing_finding.risk_score = score
            existing_finding.risk_explanation = explanation

            persisted.append(existing_finding)
        else:
            # New unique finding
            score, explanation = RiskPrioritizer.calculate_risk(
                severity=p.severity,
                cvss_score=p.cvss_score,
                host=p.host,
                port=p.port,
                cve_id=p.cve_id,
                cwe_id=p.cwe_id,
                evidence=p.evidence,
                confidence=p.confidence,
                is_false_positive=False,
            )

            artifacts_json = json.dumps([new_artifact_entry])

            new_finding = Finding(
                assessment_id=assessment_id,
                scan_job_id=scan_job_id,
                source_tool=p.source_tool,
                title=p.title,
                description=p.description,
                severity=p.severity.lower(),
                cve_id=p.cve_id,
                cwe_id=p.cwe_id,
                cvss_score=p.cvss_score,
                host=p.host,
                port=p.port,
                url_path=p.url_path,
                service=p.service,
                evidence=p.evidence,
                scanner_reference=p.scanner_reference,
                confidence=p.confidence,
                validation_status="UNVALIDATED",
                fingerprint=fp,
                risk_score=score,
                risk_explanation=explanation,
                raw_evidence_artifacts=artifacts_json,
                is_false_positive=False,
            )
            session.add(new_finding)
            persisted.append(new_finding)

    await session.commit()
    return persisted
