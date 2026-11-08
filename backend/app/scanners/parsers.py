"""
Unified Scanner Parsers for Nmap, OWASP ZAP, and Nikto.
Extracts normalized findings from live scanner outputs or imported JSON/XML reports,
preserving full raw scanner evidence and avoiding fabricated CVEs.
"""
from __future__ import annotations

import json
import logging
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class ParsedFinding(BaseModel):
    source_tool: str
    title: str
    description: str
    severity: str  # Critical, High, Medium, Low, Informational
    host: str
    port: Optional[int] = None
    url_path: Optional[str] = None
    service: Optional[str] = None
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    evidence: Optional[str] = None
    scanner_reference: Optional[str] = None
    confidence: str = "Medium"
    raw_artifact: Optional[Dict[str, Any]] = None


class NmapParser:
    """Parses Nmap XML output (-oX -)."""

    @classmethod
    def parse_xml(cls, xml_content: str, default_host: str = "127.0.0.1") -> List[ParsedFinding]:
        findings: List[ParsedFinding] = []
        if not xml_content or not xml_content.strip():
            return findings

        try:
            root = ET.fromstring(xml_content.strip())
        except ET.ParseError as err:
            logger.warning(f"Failed to parse Nmap XML: {err}")
            raise ValueError(f"Malformed Nmap XML output: {err}")

        for host_elem in root.findall("host"):
            # Extract host IP or hostname, prioritizing default_host if matched
            host_ip = default_host
            addr_str = None
            addr_elem = host_elem.find("address")
            if addr_elem is not None and "addr" in addr_elem.attrib:
                addr_str = addr_elem.attrib["addr"]

            hostname_str = None
            hostnames_elem = host_elem.find("hostnames")
            if hostnames_elem is not None:
                h_name = hostnames_elem.find("hostname")
                if h_name is not None and "name" in h_name.attrib:
                    hostname_str = h_name.attrib["name"]

            # If default_host matches either address or hostname, preserve default_host
            if default_host and (default_host in [addr_str, hostname_str]):
                host_ip = default_host
            elif addr_str:
                host_ip = addr_str
            elif hostname_str:
                host_ip = hostname_str

            ports_elem = host_elem.find("ports")
            if ports_elem is None:
                continue

            for port_elem in ports_elem.findall("port"):
                state_elem = port_elem.find("state")
                if state_elem is None or state_elem.attrib.get("state") != "open":
                    continue

                port_id = int(port_elem.attrib.get("portid", 0))
                protocol = port_elem.attrib.get("protocol", "tcp")

                service_elem = port_elem.find("service")
                service_name = service_elem.attrib.get("name", "unknown") if service_elem is not None else "unknown"
                product = service_elem.attrib.get("product", "") if service_elem is not None else ""
                version = service_elem.attrib.get("version", "") if service_elem is not None else ""
                extrainfo = service_elem.attrib.get("extrainfo", "") if service_elem is not None else ""

                version_str = f"{product} {version} {extrainfo}".strip() or "Version not disclosed"

                # Check scripts for vulnerability or SSL details
                script_evidence = []
                cve_found = None
                severity = "informational"

                for script in port_elem.findall("script"):
                    s_id = script.attrib.get("id", "")
                    s_out = script.attrib.get("output", "")
                    script_evidence.append(f"[{s_id}] {s_out}")

                    # Check for CVE identifiers in output
                    if "CVE-" in s_out:
                        import re
                        m = re.search(r"CVE-\d{4}-\d+", s_out)
                        if m:
                            cve_found = m.group(0)
                            severity = "high"

                # Flag plaintext or unencrypted management ports as low/medium risk
                if port_id in [21, 23]:
                    severity = "medium"
                    desc = f"Insecure plaintext service ({service_name}) discovered on port {port_id}. Credentials and data are transmitted unencrypted."
                    title = f"Insecure Plaintext Protocol Exposed ({service_name.upper()} on Port {port_id})"
                elif severity == "high":
                    desc = f"Nmap script identified vulnerability on port {port_id} ({service_name}): {'; '.join(script_evidence[:2])}"
                    title = f"Vulnerability Detected on {service_name} ({port_id}/{protocol})"
                else:
                    severity = "informational"
                    desc = f"Open {protocol.upper()} network port {port_id} running {service_name} ({version_str})."
                    title = f"Open Network Port & Service ({port_id}/{protocol} - {service_name})"

                evidence_str = f"Service: {service_name} | Banner: {version_str}"
                if script_evidence:
                    evidence_str += " | Scripts: " + " ; ".join(script_evidence[:3])

                findings.append(
                    ParsedFinding(
                        source_tool="Nmap",
                        title=title,
                        description=desc,
                        severity=severity,
                        host=host_ip,
                        port=port_id,
                        service=service_name,
                        cve_id=cve_found,
                        evidence=evidence_str,
                        scanner_reference=f"nmap-port-{port_id}-{protocol}",
                        confidence="Confirmed",
                        raw_artifact={
                            "port": port_id,
                            "protocol": protocol,
                            "service": service_name,
                            "version": version_str,
                            "scripts": script_evidence,
                        },
                    )
                )

        return findings


class ZapParser:
    """Parses OWASP ZAP official JSON and XML reports."""

    @classmethod
    def parse_json(cls, json_str: str, default_host: str = "127.0.0.1") -> List[ParsedFinding]:
        findings: List[ParsedFinding] = []
        if not json_str or not json_str.strip():
            return findings

        try:
            data = json.loads(json_str)
        except Exception as err:
            raise ValueError(f"Malformed OWASP ZAP JSON report: {err}")

        # ZAP JSON report may have top-level 'site' array or dictionary
        sites = data.get("site", [])
        if isinstance(sites, dict):
            sites = [sites]

        # Alternative ZAP structure: direct list of alerts or alertsByRisk
        if not sites and "alerts" in data:
            sites = [{"@name": default_host, "alerts": data["alerts"]}]

        for site in sites:
            site_host = site.get("@host") or default_host
            alerts = site.get("alerts", [])
            if isinstance(alerts, dict):
                alerts = [alerts]

            for alert in alerts:
                title = alert.get("alert") or alert.get("name") or "OWASP ZAP Finding"
                desc = alert.get("desc") or alert.get("description") or "No description provided."
                solution = alert.get("solution", "")
                if solution:
                    desc += f"\n\nRemediation Solution:\n{solution}"

                # Severity mapping
                risk = (alert.get("riskdesc") or alert.get("risk") or "informational").lower()
                if "high" in risk:
                    severity = "high"
                elif "medium" in risk:
                    severity = "medium"
                elif "low" in risk:
                    severity = "low"
                else:
                    severity = "informational"

                # Confidence mapping
                confidence_raw = (alert.get("confidence") or "Medium").capitalize()
                confidence = "High" if "High" in confidence_raw else ("Low" if "Low" in confidence_raw else "Medium")

                # CWE ID
                cwe_raw = str(alert.get("cweid") or alert.get("cwe_id") or "")
                cwe_id = f"CWE-{cwe_raw}" if cwe_raw and cwe_raw != "0" and not cwe_raw.startswith("CWE-") else None

                # Instances (URLs & Evidence)
                instances = alert.get("instances", [])
                if isinstance(instances, dict):
                    instances = [instances]

                first_instance = instances[0] if instances else {}
                url = first_instance.get("uri") or alert.get("url") or ""
                evidence = first_instance.get("evidence") or alert.get("evidence") or first_instance.get("param") or "Reported by OWASP ZAP DAST engine"

                # Extract port & path from URL
                port = None
                path = url
                if "://" in url:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    site_host = parsed.hostname or site_host
                    port = parsed.port or (443 if parsed.scheme == "https" else 80)
                    path = parsed.path or "/"

                findings.append(
                    ParsedFinding(
                        source_tool="OWASP ZAP",
                        title=title,
                        description=desc,
                        severity=severity,
                        host=site_host,
                        port=port,
                        url_path=path,
                        service="http",
                        cwe_id=cwe_id,
                        evidence=evidence,
                        scanner_reference=str(alert.get("pluginId") or alert.get("alertid") or "zap-alert"),
                        confidence=confidence,
                        raw_artifact=alert,
                    )
                )

        return findings

    @classmethod
    def parse_xml(cls, xml_str: str, default_host: str = "127.0.0.1") -> List[ParsedFinding]:
        findings: List[ParsedFinding] = []
        if not xml_str or not xml_str.strip():
            return findings

        try:
            root = ET.fromstring(xml_str.strip())
        except ET.ParseError as err:
            raise ValueError(f"Malformed OWASP ZAP XML report: {err}")

        for site_elem in root.findall(".//site"):
            site_host = site_elem.attrib.get("host", default_host)

            for alert_elem in site_elem.findall(".//alertitem"):
                title = alert_elem.findtext("alert") or "OWASP ZAP Finding"
                desc = alert_elem.findtext("desc") or "No description provided."
                solution = alert_elem.findtext("solution")
                if solution:
                    desc += f"\n\nRemediation Solution:\n{solution}"

                risk = (alert_elem.findtext("riskdesc") or "informational").lower()
                if "high" in risk:
                    severity = "high"
                elif "medium" in risk:
                    severity = "medium"
                elif "low" in risk:
                    severity = "low"
                else:
                    severity = "informational"

                confidence = alert_elem.findtext("confidence") or "Medium"
                cwe_raw = alert_elem.findtext("cweid") or ""
                cwe_id = f"CWE-{cwe_raw}" if cwe_raw and cwe_raw != "0" else None

                url = alert_elem.findtext("uri") or ""
                evidence = alert_elem.findtext("evidence") or alert_elem.findtext("param") or "Reported by OWASP ZAP DAST engine"

                port = None
                path = url
                if "://" in url:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    site_host = parsed.hostname or site_host
                    port = parsed.port or (443 if parsed.scheme == "https" else 80)
                    path = parsed.path or "/"

                findings.append(
                    ParsedFinding(
                        source_tool="OWASP ZAP",
                        title=title,
                        description=desc,
                        severity=severity,
                        host=site_host,
                        port=port,
                        url_path=path,
                        service="http",
                        cwe_id=cwe_id,
                        evidence=evidence,
                        scanner_reference=alert_elem.findtext("pluginid") or "zap-xml-alert",
                        confidence=confidence,
                        raw_artifact={"raw_xml": ET.tostring(alert_elem, encoding="unicode")},
                    )
                )

        return findings


class NiktoParser:
    """Parses Nikto JSON and XML reports."""

    @classmethod
    def parse_json(cls, json_str: str, default_host: str = "127.0.0.1") -> List[ParsedFinding]:
        findings: List[ParsedFinding] = []
        if not json_str or not json_str.strip():
            return findings

        try:
            data = json.loads(json_str)
        except Exception as err:
            raise ValueError(f"Malformed Nikto JSON report: {err}")

        # Nikto JSON may be array or dict
        records = data if isinstance(data, list) else [data]

        for scan in records:
            host = scan.get("host") or scan.get("ip") or default_host
            port_val = scan.get("port")
            port = int(port_val) if port_val else 80

            items = scan.get("vulnerabilities") or scan.get("items") or []
            for item in items:
                msg = item.get("msg") or item.get("description") or "Nikto Advisory"
                uri = item.get("url") or item.get("uri") or "/"
                item_id = item.get("id") or item.get("OSVDB") or "nikto-item"

                # Determine severity heuristically based on message content
                msg_lower = msg.lower()
                if any(t in msg_lower for t in ["remote code", "traversal", "vulnerable", "exploit", "unauthenticated"]):
                    severity = "high"
                elif any(t in msg_lower for t in ["cookie", "x-frame-options", "header", "directory indexing", "apache", "nginx"]):
                    severity = "medium"
                elif any(t in msg_lower for t in ["found", "retrieved", "interesting", "outdated"]):
                    severity = "low"
                else:
                    severity = "informational"

                # Check for CVE mentions in message
                cve_found = None
                if "CVE-" in msg:
                    import re
                    m = re.search(r"CVE-\d{4}-\d+", msg)
                    if m:
                        cve_found = m.group(0)

                findings.append(
                    ParsedFinding(
                        source_tool="Nikto",
                        title=f"Nikto Finding: {msg[:80]}",
                        description=msg,
                        severity=severity,
                        host=host,
                        port=port,
                        url_path=uri,
                        service="http",
                        cve_id=cve_found,
                        evidence=f"URI: {uri} | OSVDB: {item.get('OSVDB', 'N/A')} | Method: {item.get('method', 'GET')}",
                        scanner_reference=f"nikto-{item_id}",
                        confidence="Medium",
                        raw_artifact=item,
                    )
                )

        return findings

    @classmethod
    def parse_xml(cls, xml_str: str, default_host: str = "127.0.0.1") -> List[ParsedFinding]:
        findings: List[ParsedFinding] = []
        if not xml_str or not xml_str.strip():
            return findings

        try:
            root = ET.fromstring(xml_str.strip())
        except ET.ParseError as err:
            raise ValueError(f"Malformed Nikto XML report: {err}")

        for details in root.findall(".//scandetails"):
            host = details.attrib.get("targetip") or details.attrib.get("host") or default_host
            port_str = details.attrib.get("port")
            port = int(port_str) if port_str and port_str.isdigit() else 80

            for item in details.findall(".//item"):
                desc = item.findtext("description") or "Nikto finding"
                uri = item.findtext("uri") or "/"
                osvdb = item.attrib.get("osvdbid") or "N/A"

                desc_lower = desc.lower()
                if any(t in desc_lower for t in ["remote code", "traversal", "vulnerable", "exploit"]):
                    severity = "high"
                elif any(t in desc_lower for t in ["cookie", "x-frame-options", "header", "directory indexing"]):
                    severity = "medium"
                else:
                    severity = "low"

                findings.append(
                    ParsedFinding(
                        source_tool="Nikto",
                        title=f"Nikto Advisory: {desc[:80]}",
                        description=desc,
                        severity=severity,
                        host=host,
                        port=port,
                        url_path=uri,
                        service="http",
                        evidence=f"URI: {uri} | OSVDB: {osvdb}",
                        scanner_reference=f"nikto-item-{osvdb}",
                        confidence="Medium",
                        raw_artifact={"raw_xml": ET.tostring(item, encoding="unicode")},
                    )
                )

        return findings
