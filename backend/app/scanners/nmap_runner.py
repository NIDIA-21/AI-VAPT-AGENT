"""
Safe Nmap Subprocess Runner.
Strictly enforces scope validation before execution, uses argument-list execution
without shell interpreters, enforces timeouts, and parses XML output directly into normalized findings.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Assessment, AuthorizedTarget, ScanJob
from app.scanners.parsers import NmapParser, ParsedFinding
from app.services.deduplicator import deduplicate_and_persist_findings
from app.services.scope_validator import ScopeValidationService

logger = logging.getLogger(__name__)


def get_nmap_executable() -> Optional[str]:
    """Finds the nmap executable on PATH, returning None if missing."""
    return shutil.which("nmap")


async def get_nmap_status() -> Dict[str, Any]:
    """Inspects Nmap installation and version."""
    nmap_path = get_nmap_executable()
    if not nmap_path:
        return {
            "installed": False,
            "version": "Not Installed",
            "path": None,
            "status": "NOT INSTALLED",
            "mode": "IMPORT ONLY",
            "note": "Nmap binary not found in system PATH. Use XML report import to ingest scans.",
        }

    # Attempt version detection
    version_str = "Unknown"
    try:
        proc = await asyncio.create_subprocess_exec(
            nmap_path,
            "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5.0)
        first_line = stdout.decode("utf-8", errors="replace").splitlines()[0]
        version_str = first_line.strip()
    except Exception as e:
        logger.warning(f"Error querying Nmap version: {e}")
        version_str = "Detected (Version probe timed out)"

    return {
        "installed": True,
        "version": version_str,
        "path": nmap_path,
        "status": "LIVE",
        "mode": "LIVE SCANNING & IMPORT",
        "note": "Nmap binary ready for safe scoped network execution.",
    }


async def run_scoped_nmap_scan(
    target: AuthorizedTarget,
    assessment_id: str,
    session: AsyncSession,
    ports_override: Optional[List[int]] = None,
    timeout_seconds: float = 60.0,
    actor: str = "security_analyst",
) -> ScanJob:
    """
    Executes a live Nmap scan against an authorized target with strict scope checks.
    """
    # 1. Scope Validation Check
    ports_to_check = ports_override[0] if ports_override and len(ports_override) == 1 else None
    scope_result = await ScopeValidationService.validate_scope(
        session=session,
        requested_target=target.host,
        target_id=target.id,
        requested_port=ports_to_check,
        requested_action="nmap_scan",
        actor=actor,
    )

    if not scope_result.allowed:
        # Create FAILED scan job recording scope denial
        job = ScanJob(
            assessment_id=assessment_id,
            scanner="Nmap",
            status="FAILED",
            target_host=target.host,
            parameters=json.dumps({"ports": ports_override}),
            scope_snapshot=json.dumps(scope_result.to_dict()),
            error_message=f"Scope Validation Denied: {scope_result.reason}",
            started_at=datetime.now(timezone.utc),
            finished_at=datetime.now(timezone.utc),
        )
        session.add(job)
        await session.commit()
        await session.refresh(job)
        raise PermissionError(f"Scope violation: {scope_result.reason}")

    # Determine permitted ports
    target_ports: List[str] = []
    if ports_override:
        target_ports = [str(p) for p in ports_override]
    elif target.permitted_ports:
        target_ports = [str(p) for p in target.permitted_ports]

    # Build safe argument list (NO SHELL EXECUTION)
    # Default to fast safe service probe on permitted ports or top safe web/common ports
    port_arg = ",".join(target_ports) if target_ports else "21,22,25,80,443,3000,5000,8000,8080,8443"
    
    nmap_path = get_nmap_executable()
    cmd_args = ["-sV", "-T4", "-Pn", "--open", "-p", port_arg, "-oX", "-", target.host]

    # Initialize ScanJob
    job = ScanJob(
        assessment_id=assessment_id,
        scanner="Nmap",
        status="RUNNING",
        target_host=target.host,
        parameters=json.dumps({"args": cmd_args, "ports": port_arg}),
        scope_snapshot=json.dumps(scope_result.to_dict()),
        started_at=datetime.now(timezone.utc),
    )
    session.add(job)
    await session.commit()
    await session.refresh(job)

    if not nmap_path:
        job.status = "FAILED"
        job.finished_at = datetime.now(timezone.utc)
        job.error_message = (
            "Nmap binary not found in system PATH. Install Nmap on this host or "
            "upload an Nmap XML report using the Report Import endpoint."
        )
        await session.commit()
        return job

    try:
        # Execute safely with argument list, stdout pipe, timeout
        proc = await asyncio.create_subprocess_exec(
            nmap_path,
            *cmd_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(),
            timeout=timeout_seconds,
        )

        stdout_text = stdout_bytes.decode("utf-8", errors="replace")
        stderr_text = stderr_bytes.decode("utf-8", errors="replace")

        job.raw_output = stdout_text
        job.finished_at = datetime.now(timezone.utc)

        if proc.returncode != 0 and not stdout_text:
            job.status = "FAILED"
            job.error_message = f"Nmap exited with code {proc.returncode}: {stderr_text.strip()}"
            await session.commit()
            return job

        # Parse findings from XML output
        parsed_findings = NmapParser.parse_xml(stdout_text, default_host=target.host)
        
        # Deduplicate and persist findings
        await deduplicate_and_persist_findings(
            parsed_findings=parsed_findings,
            assessment_id=assessment_id,
            scan_job_id=job.id,
            session=session,
        )

        job.status = "COMPLETED"
        await session.commit()
        return job

    except asyncio.TimeoutError:
        job.status = "FAILED"
        job.finished_at = datetime.now(timezone.utc)
        job.error_message = f"Nmap execution timed out after {timeout_seconds} seconds."
        try:
            proc.kill()
        except Exception:
            pass
        await session.commit()
        return job

    except Exception as exc:
        job.status = "FAILED"
        job.finished_at = datetime.now(timezone.utc)
        job.error_message = f"Execution error: {str(exc)}"
        await session.commit()
        return job


async def import_nmap_xml_report(
    xml_content: str,
    assessment_id: str,
    target_host: str,
    session: AsyncSession,
) -> Tuple[ScanJob, List[ParsedFinding]]:
    """
    Ingests and validates an uploaded Nmap XML report.
    """
    parsed_findings = NmapParser.parse_xml(xml_content, default_host=target_host)

    job = ScanJob(
        assessment_id=assessment_id,
        scanner="Nmap (Imported XML)",
        status="COMPLETED",
        target_host=target_host,
        parameters=json.dumps({"source": "manual_import", "format": "xml"}),
        raw_output=xml_content,
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
    )
    session.add(job)
    await session.commit()
    await session.refresh(job)

    await deduplicate_and_persist_findings(
        parsed_findings=parsed_findings,
        assessment_id=assessment_id,
        scan_job_id=job.id,
        session=session,
    )

    return job, parsed_findings
