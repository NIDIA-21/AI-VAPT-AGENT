"""
Scanner availability probe — checks if CLI tools are on the system PATH.
Never executes actual scans; never constructs shell commands unsafely.
All checks strictly use shutil.which for safe executable path lookup.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ScannerInfo:
    name: str
    display_name: str
    binaries: List[str]
    category: str
    description: str
    default_state_when_missing: str = "Not Installed"
    capabilities: List[str] = field(default_factory=list)
    version_flag: str = "--version"
    
    # Probed fields
    status: str = field(default="Not Installed", init=False)
    available: bool = field(default=False, init=False)
    version: Optional[str] = field(default=None, init=False)
    path: Optional[str] = field(default=None, init=False)


KNOWN_SCANNERS: list[ScannerInfo] = [
    ScannerInfo(
        name="nmap",
        display_name="Nmap",
        binaries=["nmap", "nmap.exe"],
        category="Network Exploration",
        description="Network port scanner, OS detection, and service fingerprinting",
        default_state_when_missing="Not Installed",
        capabilities=["Port Scanning", "Service Detection", "OS Fingerprinting", "NSE Scripts"],
        version_flag="--version",
    ),
    ScannerInfo(
        name="zap",
        display_name="OWASP ZAP",
        binaries=["zap.sh", "zap.bat", "zaproxy", "zaproxy.exe"],
        category="Web Application DAST",
        description="Open-source DAST scanner; official JSON & XML report ingestion active",
        default_state_when_missing="Import Only",
        capabilities=["Passive Scanning", "Report Ingestion", "CWE Mapping", "Evidence Extraction"],
        version_flag="-version",
    ),
    ScannerInfo(
        name="nikto",
        display_name="Nikto",
        binaries=["nikto", "nikto.pl"],
        category="Web Server Scanner",
        description="Web server vulnerability scanner; official JSON & XML report ingestion active",
        default_state_when_missing="Import Only",
        capabilities=["Server Misconfig", "OSVDB Tracking", "URI Context", "Report Ingestion"],
        version_flag="-Version",
    ),
    ScannerInfo(
        name="nessus",
        display_name="Nessus",
        binaries=["nessusd", "nessuscli", "nessus"],
        category="Enterprise Vulnerability",
        description="Comprehensive network and system vulnerability assessment engine (Planned)",
        default_state_when_missing="Planned",
        capabilities=["Compliance Audits", "CVE Mapping", "Configuration Audit", "Patch Auditing"],
        version_flag="--version",
    ),
    ScannerInfo(
        name="openvas",
        display_name="OpenVAS / Greenbone",
        binaries=["openvas", "gvm-cli", "gvmd"],
        category="Vulnerability Management",
        description="Open-source vulnerability management and full NVT testing feed (Planned)",
        default_state_when_missing="Planned",
        capabilities=["Full NVT Feed", "Network Vulnerabilities", "Vulnerability Scoring"],
        version_flag="--version",
    ),
    ScannerInfo(
        name="burpsuite",
        display_name="Burp Suite",
        binaries=["burpsuite", "burpsuitepro", "BurpSuiteCommunity", "burp"],
        category="Web Proxy & Scanner",
        description="Web penetration testing toolkit; supports direct report ingestion (Planned)",
        default_state_when_missing="Planned",
        capabilities=["XML/JSON Import", "Issue Parsing", "Request Interception", "Custom Payloads"],
        version_flag="--version",
    ),
    ScannerInfo(
        name="metasploit",
        display_name="Metasploit",
        binaries=["msfconsole", "msfconsole.bat"],
        category="Exploitation Framework",
        description="Exploitation framework. Autonomous exploitation strictly prohibited; human approval gate enforced.",
        default_state_when_missing="Unsupported",
        capabilities=["Payload Verification", "Proof-of-Concept", "Human Approval Gate"],
        version_flag="--version",
    ),
]


def _probe_scanner(info: ScannerInfo) -> ScannerInfo:
    """Probe a single scanner — safe, no network activity, no arbitrary commands."""
    found_path = None
    for binary in info.binaries:
        path = shutil.which(binary)
        if path:
            found_path = path
            break

    if found_path:
        info.available = True
        info.status = "Available"
        info.path = found_path
        try:
            result = subprocess.run(
                [found_path, info.version_flag],
                capture_output=True,
                text=True,
                timeout=4,
            )
            output = (result.stdout or result.stderr or "").strip()
            for line in output.splitlines():
                line = line.strip()
                if line:
                    info.version = line[:100]
                    break
        except Exception:
            info.version = "Version detected"
    else:
        info.available = False
        info.status = info.default_state_when_missing
        info.path = None
        info.version = None

    return info


def probe_all_scanners() -> list[ScannerInfo]:
    """Return availability info for all 7 known scanners."""
    return [_probe_scanner(s) for s in KNOWN_SCANNERS]
