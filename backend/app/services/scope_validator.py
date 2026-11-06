"""
Centralized Scope Validation Service.
Every scanner adapter and assessment engine MUST use this service
prior to executing any scanner command.

Default behavior MUST BE DENY.
Excluded resources always take precedence over allowed resources.
Exact normalized hostname/IP matching — no wildcard, no CIDR in this phase.
"""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import AuditLog, AuthorizedTarget, TargetStatus


# ── Host & Domain Validation Regex ──────────────────────────────────────────
# RFC 1123 compliant domain regex (no wildcards allowed)
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
DANGEROUS_SHELL_CHARS = re.compile(r"[;&|`$<>\r\n\'\"\s]")


def normalize_and_validate_host(host_input: str) -> str:
    """
    Validates that the input is a valid IPv4, IPv6, or domain name.
    Strictly rejects:
      - Wildcards (e.g. *.example.com)
      - CIDR blocks (e.g. 192.168.1.0/24)
      - Shell injection characters (; & | ` $ < > etc.)
      - Protocol prefixes if embedded in host field
    Returns canonical lowercase string.
    """
    if not host_input or not isinstance(host_input, str):
        raise ValueError("Target host or IP address is required.")

    host = host_input.strip()

    # Reject shell injection characters
    if DANGEROUS_SHELL_CHARS.search(host):
        raise ValueError("Invalid target host: contains illegal or dangerous shell characters.")

    # Reject wildcards
    if "*" in host:
        raise ValueError("Wildcard domains (*.example.com) are strictly prohibited in this phase.")

    # Reject CIDR ranges
    if "/" in host:
        raise ValueError("CIDR notation (e.g. /24) is not supported in this phase. Register exact hosts or IPs.")

    # Reject protocol prefixes in host field
    if "://" in host:
        raise ValueError("Protocol prefixes (http://, https://) should not be included in the host field. Use the Target URL field instead.")

    # Remove port if accidentally supplied in host field (e.g. example.com:8080)
    if ":" in host and not host.startswith("[") and host.count(":") == 1:
        parts = host.split(":")
        host = parts[0]

    host_lower = host.lower()

    # 1. Test IPv4
    try:
        ip = ipaddress.IPv4Address(host_lower)
        return str(ip)
    except ipaddress.AddressValueError:
        pass

    # 2. Test IPv6
    try:
        ip6 = ipaddress.IPv6Address(host_lower)
        return str(ip6)
    except ipaddress.AddressValueError:
        pass

    # 3. Test Localhost
    if host_lower == "localhost":
        return "localhost"

    # 4. Test Domain name (RFC 1123)
    if DOMAIN_REGEX.match(host_lower) and len(host_lower) <= 253:
        return host_lower

    raise ValueError(f"Invalid target host '{host}'. Must be a valid IPv4, IPv6, or fully qualified domain name.")


def parse_ports_input(ports_val: Any) -> List[int]:
    """
    Parses a comma-separated string, list, or JSON string of port numbers / ranges.
    Example: '80, 443, 8000-8005' -> [80, 443, 8000, 8001, 8002, 8003, 8004, 8005]
    Validates 1 <= port <= 65535.
    Returns sorted list of unique integers.
    """
    if not ports_val:
        return []

    raw_items: List[str] = []

    if isinstance(ports_val, list):
        for item in ports_val:
            raw_items.append(str(item).strip())
    elif isinstance(ports_val, str):
        # Try JSON decode first
        val_str = ports_val.strip()
        if val_str.startswith("[") and val_str.endswith("]"):
            try:
                decoded = json.loads(val_str)
                if isinstance(decoded, list):
                    raw_items = [str(x).strip() for x in decoded]
            except Exception:
                raw_items = val_str.split(",")
        else:
            raw_items = val_str.split(",")
    else:
        raw_items = [str(ports_val).strip()]

    result_ports: Set[int] = set()

    for item in raw_items:
        item = item.strip()
        if not item:
            continue

        if "-" in item:
            # Port range
            parts = item.split("-")
            if len(parts) != 2:
                raise ValueError(f"Invalid port range specification: '{item}'")
            try:
                start_p = int(parts[0].strip())
                end_p = int(parts[1].strip())
            except ValueError:
                raise ValueError(f"Port range contains non-numeric values: '{item}'")

            if start_p > end_p:
                raise ValueError(f"Port range start ({start_p}) cannot exceed end ({end_p})")
            if start_p < 1 or end_p > 65535:
                raise ValueError(f"Port range must be within 1-65535: '{item}'")
            if (end_p - start_p) > 2000:
                raise ValueError(f"Port range '{item}' is too broad (max 2000 ports per range rule).")

            for p in range(start_p, end_p + 1):
                result_ports.add(p)
        else:
            try:
                p = int(item)
            except ValueError:
                raise ValueError(f"Invalid port value: '{item}' (must be an integer)")
            if p < 1 or p > 65535:
                raise ValueError(f"Port {p} out of range (must be 1-65535)")
            result_ports.add(p)

    return sorted(list(result_ports))


def parse_paths_input(paths_val: Any) -> List[str]:
    """
    Parses and normalizes excluded URL paths.
    Ensures every path begins with '/' and trims trailing slashes.
    """
    if not paths_val:
        return []

    raw_items: List[str] = []
    if isinstance(paths_val, list):
        raw_items = [str(p) for p in paths_val]
    elif isinstance(paths_val, str):
        val_str = paths_val.strip()
        if val_str.startswith("[") and val_str.endswith("]"):
            try:
                decoded = json.loads(val_str)
                if isinstance(decoded, list):
                    raw_items = [str(x) for x in decoded]
            except Exception:
                raw_items = [p.strip() for p in val_str.splitlines() if p.strip()]
        else:
            raw_items = [p.strip() for p in val_str.replace(",", "\n").splitlines() if p.strip()]

    normalized: List[str] = []
    for p in raw_items:
        p = p.strip()
        if not p:
            continue
        if not p.startswith("/"):
            p = "/" + p
        if len(p) > 1 and p.endswith("/"):
            p = p.rstrip("/")
        if p not in normalized:
            normalized.append(p)

    return normalized


class ScopeValidationResult:
    def __init__(
        self,
        allowed: bool,
        reason: str,
        target_id: Optional[str] = None,
        target_name: Optional[str] = None,
        requested_target: Optional[str] = None,
        requested_port: Optional[int] = None,
        requested_path: Optional[str] = None,
        requested_protocol: Optional[str] = None,
        audit_event_id: Optional[str] = None,
    ):
        self.allowed = allowed
        self.reason = reason
        self.target_id = target_id
        self.target_name = target_name
        self.requested_target = requested_target
        self.requested_port = requested_port
        self.requested_path = requested_path
        self.requested_protocol = requested_protocol
        self.audit_event_id = audit_event_id
        self.validation_timestamp = datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "target_id": self.target_id,
            "target_name": self.target_name,
            "requested_target": self.requested_target,
            "requested_port": self.requested_port,
            "requested_path": self.requested_path,
            "requested_protocol": self.requested_protocol,
            "reason": self.reason,
            "validation_timestamp": self.validation_timestamp.isoformat(),
            "audit_event_id": self.audit_event_id,
        }


class ScopeValidationService:
    """
    Central validation engine for authorized targets and execution parameters.
    """

    @staticmethod
    async def validate_scope(
        session: AsyncSession,
        requested_target: str,
        target_id: Optional[str] = None,
        requested_port: Optional[int] = None,
        requested_path: Optional[str] = None,
        requested_protocol: Optional[str] = None,
        requested_action: Optional[str] = "assessment",
        actor: str = "security_agent",
        ip_address: Optional[str] = None,
    ) -> ScopeValidationResult:
        """
        Executes strict scope validation.
        Default is DENY.
        Excluded resources take precedence over permitted resources.
        """
        # Normalize requested host
        try:
            norm_target = normalize_and_validate_host(requested_target)
        except ValueError as err:
            reason = f"Rejected invalid host syntax: {err}"
            audit_id = await ScopeValidationService._log_audit(
                session, actor, "scope.validation.rejected", None, norm_target if 'norm_target' in locals() else requested_target, False, reason, ip_address
            )
            return ScopeValidationResult(
                allowed=False,
                reason=reason,
                requested_target=requested_target,
                requested_port=requested_port,
                requested_path=requested_path,
                audit_event_id=audit_id,
            )

        # 1. Lookup Registered Target
        query = select(AuthorizedTarget).where(
            AuthorizedTarget.host == norm_target,
            AuthorizedTarget.is_deleted == False,
        )
        if target_id:
            query = query.where(AuthorizedTarget.id == target_id)

        target = await session.scalar(query)

        # Fallback: if target_id provided but host was different or not found
        if not target and target_id:
            target = await session.get(AuthorizedTarget, target_id)
            if target and target.is_deleted:
                target = None

        if not target:
            reason = f"Target '{norm_target}' is not registered in the authorized scope allowlist. Default-Deny active."
            audit_id = await ScopeValidationService._log_audit(
                session, actor, "scope.validation.rejected", None, norm_target, False, reason, ip_address
            )
            return ScopeValidationResult(
                allowed=False,
                reason=reason,
                requested_target=norm_target,
                requested_port=requested_port,
                requested_path=requested_path,
                audit_event_id=audit_id,
            )

        # 2. Check Revocation
        status_upper = (target.status or "").upper()
        if status_upper == TargetStatus.REVOKED.value:
            reason = f"Target authorization was REVOKED for '{target.host}'. Reason: {target.revocation_reason or 'No reason specified'}."
            audit_id = await ScopeValidationService._log_audit(
                session, actor, "scope.validation.rejected", target.id, norm_target, False, reason, ip_address
            )
            return ScopeValidationResult(
                allowed=False,
                reason=reason,
                target_id=target.id,
                target_name=target.name,
                requested_target=norm_target,
                requested_port=requested_port,
                requested_path=requested_path,
                audit_event_id=audit_id,
            )

        # 3. Check Active Status
        if status_upper not in (TargetStatus.ACTIVE.value, "AUTHORIZED"):
            reason = f"Target '{target.host}' is in '{target.status}' status (must be ACTIVE to assess)."
            audit_id = await ScopeValidationService._log_audit(
                session, actor, "scope.validation.rejected", target.id, norm_target, False, reason, ip_address
            )
            return ScopeValidationResult(
                allowed=False,
                reason=reason,
                target_id=target.id,
                target_name=target.name,
                requested_target=norm_target,
                requested_port=requested_port,
                requested_path=requested_path,
                audit_event_id=audit_id,
            )

        # 4. Check Authorization Validity Period (Expiration)
        now_utc = datetime.now(timezone.utc)
        if target.valid_from and target.valid_from.tzinfo is None:
            valid_from = target.valid_from.replace(tzinfo=timezone.utc)
        else:
            valid_from = target.valid_from

        if target.valid_to and target.valid_to.tzinfo is None:
            valid_to = target.valid_to.replace(tzinfo=timezone.utc)
        else:
            valid_to = target.valid_to

        if valid_from and now_utc < valid_from:
            reason = f"Target authorization for '{target.host}' has not yet begun (valid from {valid_from.isoformat()})."
            audit_id = await ScopeValidationService._log_audit(
                session, actor, "scope.validation.rejected", target.id, norm_target, False, reason, ip_address
            )
            return ScopeValidationResult(
                allowed=False,
                reason=reason,
                target_id=target.id,
                target_name=target.name,
                requested_target=norm_target,
                requested_port=requested_port,
                requested_path=requested_path,
                audit_event_id=audit_id,
            )

        if valid_to and now_utc > valid_to:
            reason = f"Target authorization for '{target.host}' EXPIRED on {valid_to.isoformat()}."
            # Automatically update status to EXPIRED in database if not already
            if target.status != TargetStatus.EXPIRED.value:
                target.status = TargetStatus.EXPIRED.value
                await session.flush()
            audit_id = await ScopeValidationService._log_audit(
                session, actor, "scope.expired.rejected", target.id, norm_target, False, reason, ip_address
            )
            return ScopeValidationResult(
                allowed=False,
                reason=reason,
                target_id=target.id,
                target_name=target.name,
                requested_target=norm_target,
                requested_port=requested_port,
                requested_path=requested_path,
                audit_event_id=audit_id,
            )

        # 5. Port Validation (Excluded always takes precedence over Allowed)
        if requested_port is not None:
            if not isinstance(requested_port, int) or requested_port < 1 or requested_port > 65535:
                reason = f"Invalid requested port value: {requested_port} (must be 1-65535)."
                audit_id = await ScopeValidationService._log_audit(
                    session, actor, "scope.validation.rejected", target.id, norm_target, False, reason, ip_address
                )
                return ScopeValidationResult(
                    allowed=False,
                    reason=reason,
                    target_id=target.id,
                    target_name=target.name,
                    requested_target=norm_target,
                    requested_port=requested_port,
                    requested_path=requested_path,
                    audit_event_id=audit_id,
                )

            # Check excluded ports first
            excluded_ports = parse_ports_input(target.excluded_ports)
            if requested_port in excluded_ports:
                reason = f"Requested port {requested_port} is EXCLUDED from assessment scope on '{target.host}'."
                audit_id = await ScopeValidationService._log_audit(
                    session, actor, "scope.validation.rejected", target.id, norm_target, False, reason, ip_address
                )
                return ScopeValidationResult(
                    allowed=False,
                    reason=reason,
                    target_id=target.id,
                    target_name=target.name,
                    requested_target=norm_target,
                    requested_port=requested_port,
                    requested_path=requested_path,
                    audit_event_id=audit_id,
                )

            # Check permitted ports
            permitted_ports = parse_ports_input(target.permitted_ports)
            if permitted_ports and requested_port not in permitted_ports:
                reason = f"Requested port {requested_port} is not in the permitted ports list for '{target.host}' (Allowed: {permitted_ports[:10]}...)."
                audit_id = await ScopeValidationService._log_audit(
                    session, actor, "scope.validation.rejected", target.id, norm_target, False, reason, ip_address
                )
                return ScopeValidationResult(
                    allowed=False,
                    reason=reason,
                    target_id=target.id,
                    target_name=target.name,
                    requested_target=norm_target,
                    requested_port=requested_port,
                    requested_path=requested_path,
                    audit_event_id=audit_id,
                )

        # 6. URL Path Exclusion Check
        if requested_path:
            norm_path = requested_path.strip()
            if not norm_path.startswith("/"):
                norm_path = "/" + norm_path

            excluded_paths = parse_paths_input(target.excluded_paths)
            for exc in excluded_paths:
                # Prefix matching or exact match:
                # e.g. exc='/admin' matches '/admin', '/admin/', '/admin/users'
                if (
                    norm_path == exc
                    or norm_path.startswith(exc + "/")
                    or exc == "/*"
                ):
                    reason = f"Requested path '{norm_path}' is EXCLUDED from assessment scope by rule '{exc}'."
                    audit_id = await ScopeValidationService._log_audit(
                        session, actor, "scope.validation.rejected", target.id, norm_target, False, reason, ip_address
                    )
                    return ScopeValidationResult(
                        allowed=False,
                        reason=reason,
                        target_id=target.id,
                        target_name=target.name,
                        requested_target=norm_target,
                        requested_port=requested_port,
                        requested_path=norm_path,
                        audit_event_id=audit_id,
                    )

        # 7. All Scope Checks Passed -> ALLOW
        reason = (
            f"Target '{target.host}' is actively authorized (Ref: {target.auth_reference or 'Active'}) "
            "and all requested parameters fall strictly within permitted scope."
        )
        audit_id = await ScopeValidationService._log_audit(
            session, actor, "scope.validation.approved", target.id, norm_target, True, reason, ip_address
        )

        return ScopeValidationResult(
            allowed=True,
            reason=reason,
            target_id=target.id,
            target_name=target.name,
            requested_target=norm_target,
            requested_port=requested_port,
            requested_path=requested_path,
            requested_protocol=requested_protocol,
            audit_event_id=audit_id,
        )

    @staticmethod
    async def _log_audit(
        session: AsyncSession,
        actor: str,
        action: str,
        target_id: Optional[str],
        requested_target: str,
        allowed: bool,
        reason: str,
        ip_address: Optional[str] = None,
    ) -> str:
        """Persists audit log entry."""
        log = AuditLog(
            actor=actor or "security_agent",
            action=action,
            resource_type="authorized_target",
            resource_id=target_id,
            detail=json.dumps({
                "requested_target": requested_target,
                "allowed": allowed,
                "reason": reason,
            }),
            ip_address=ip_address,
        )
        session.add(log)
        await session.flush()
        return log.id
