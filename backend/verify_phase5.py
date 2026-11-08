"""
Phase 5 Comprehensive Verification Test Suite:
Validates 10 core cybersecurity tool integration & vulnerability analysis criteria:
1. Tool detection & version reporting (honest status)
2. Strict scope validation before scan execution
3. Rejection of unauthorized scan targets
4. Safe argument construction (no shell=True)
5. XML parsing for Nmap
6. JSON & XML parsing for OWASP ZAP
7. JSON & XML parsing for Nikto
8. Malformed report error handling
9. Duplicate finding detection and multi-tool evidence merging (no cross-asset merges)
10. Evidence traceability, transparent risk prioritization, and AI cross-tool correlation
"""
from __future__ import annotations

import asyncio
import os
import sys

# Ensure backend directory is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from datetime import datetime, timezone
import json
import xml.etree.ElementTree as ET

from app.database.session import AsyncSessionLocal, init_db
from app.models.models import AuthorizedTarget, Assessment, Finding, ScanJob
from app.scanners.nmap_runner import get_nmap_status, run_scoped_nmap_scan, import_nmap_xml_report
from app.scanners.parsers import NmapParser, ZapParser, NiktoParser
from app.services.deduplicator import compute_finding_fingerprint, deduplicate_and_persist_findings
from app.services.risk_prioritizer import RiskPrioritizer
from app.agents.correlator import VulnerabilityCorrelator
from app.services.scope_validator import ScopeValidationService
from sqlalchemy import select, delete


TEST_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -p 80,443 -oX - 192.168.1.100" version="7.94">
<host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.100" addrtype="ipv4"/>
    <hostnames>
        <hostname name="lab-target.local" type="user"/>
    </hostnames>
    <ports>
        <port protocol="tcp" portid="80">
            <state state="open" reason="syn-ack"/>
            <service name="http" product="Apache httpd" version="2.4.49" method="probed" conf="10">
                <cpe>cpe:/a:apache:http_server:2.4.49</cpe>
            </service>
            <script id="http-vuln-cve2021-41773" output="VULNERABLE: Apache 2.4.49 Path Traversal and RCE (CVE-2021-41773)"/>
        </port>
        <port protocol="tcp" portid="443">
            <state state="open" reason="syn-ack"/>
            <service name="ssl/https" product="Apache httpd" version="2.4.49" method="probed" conf="10"/>
        </port>
        <port protocol="tcp" portid="21">
            <state state="open" reason="syn-ack"/>
            <service name="ftp" product="vsftpd" version="2.3.4" method="probed" conf="10"/>
        </port>
    </ports>
</host>
</nmaprun>
"""

TEST_ZAP_JSON = """{
  "@version": "2.14.0",
  "site": [
    {
      "@name": "http://192.168.1.100",
      "@host": "192.168.1.100",
      "@port": "80",
      "alerts": [
        {
          "pluginId": "40012",
          "alert": "Path Traversal in HTTP Server",
          "risk": "High",
          "riskdesc": "High (High)",
          "confidence": "High",
          "desc": "The web server allows unauthorized directory traversal exposing sensitive local system files.",
          "solution": "Upgrade Apache HTTP Server to version 2.4.51 or later.",
          "cweid": "22",
          "instances": [
            {
              "uri": "http://192.168.1.100/icons/.%%32%65/.%%32%65/bin/sh",
              "param": "",
              "evidence": "root:x:0:0:root:/root:/bin/bash"
            }
          ]
        },
        {
          "pluginId": "10038",
          "alert": "Content Security Policy (CSP) Header Not Set",
          "risk": "Low",
          "riskdesc": "Low (Medium)",
          "confidence": "Medium",
          "desc": "Content Security Policy is an effective mechanism against Cross Site Scripting.",
          "solution": "Ensure CSP headers are configured on all HTTP responses.",
          "cweid": "693",
          "instances": [
            {
              "uri": "http://192.168.1.100/index.html",
              "evidence": "Missing Content-Security-Policy header"
            }
          ]
        }
      ]
    }
  ]
}
"""

TEST_ZAP_XML = """<?xml version="1.0"?>
<OWASPZAPReport version="2.14.0">
  <site name="http://192.168.1.100" host="192.168.1.100" port="80" ssl="false">
    <alerts>
      <alertitem>
        <pluginid>10020</pluginid>
        <alert>X-Frame-Options Header Missing</alert>
        <riskdesc>Medium (Medium)</riskdesc>
        <desc>The page does not include X-Frame-Options header.</desc>
        <uri>http://192.168.1.100/login.php</uri>
        <evidence>Missing X-Frame-Options</evidence>
        <cweid>1021</cweid>
      </alertitem>
    </alerts>
  </site>
</OWASPZAPReport>
"""

TEST_NIKTO_JSON = """[
  {
    "host": "192.168.1.100",
    "ip": "192.168.1.100",
    "port": "80",
    "banner": "Apache/2.4.49",
    "vulnerabilities": [
      {
        "id": "000001",
        "OSVDB": "0",
        "method": "GET",
        "url": "/icons/.%%32%65/.%%32%65/etc/passwd",
        "msg": "Apache 2.4.49 is vulnerable to remote code execution and path traversal (CVE-2021-41773)."
      },
      {
        "id": "000002",
        "OSVDB": "3092",
        "method": "GET",
        "url": "/test/",
        "msg": "Retrieved /test/ directory indexing is enabled."
      }
    ]
  }
]
"""

TEST_NIKTO_XML = """<?xml version="1.0" ?>
<niktoscan>
  <scandetails targetip="192.168.1.100" port="80" host="192.168.1.100">
    <item osvdbid="3268">
      <description>/manual/: Directory indexing found.</description>
      <uri>/manual/</uri>
    </item>
  </scandetails>
</niktoscan>
"""


async def run_verification():
    print("=" * 80)
    print("AI-VAPT AGENT: PHASE 5 CYBERSECURITY TOOLS & EVIDENCE VERIFICATION")
    print("=" * 80)

    await init_db()
    passed_tests = 0
    total_tests = 10

    async with AsyncSessionLocal() as session:
        # ── Test 1: Tool detection and honest status reporting ────────────────
        print("\n[TEST 1] Tool Detection and Honest Status Reporting...")
        status_info = await get_nmap_status()
        assert "status" in status_info, "Missing status in nmap status info"
        assert "mode" in status_info, "Missing mode in nmap status info"
        print(f"  [+] Nmap Status: {status_info['status']} | Mode: {status_info['mode']} | Version: {status_info.get('version')}")
        assert status_info["status"] in ["LIVE", "NOT INSTALLED"], f"Unexpected status {status_info['status']}"
        passed_tests += 1
        print("  [+] PASS: Honest tool status reported accurately.")

        # ── Setup Authorized Target & Assessment for Testing ──────────────────
        # Clean any prior test target
        await session.execute(delete(AuthorizedTarget).where(AuthorizedTarget.host.in_(["192.168.1.100", "unauthorized.badactor.com"])))
        await session.commit()

        target = AuthorizedTarget(
            name="Lab Internal Server",
            host="192.168.1.100",
            target_url="http://192.168.1.100",
            status="ACTIVE",
            auth_reference="AUTH-LAB-2026-PHASE5",
            permitted_ports=json.dumps([80, 443, 21]),
            excluded_ports=json.dumps([22, 3389]),
        )
        session.add(target)
        await session.commit()
        await session.refresh(target)

        assessment = Assessment(
            name="Phase 5 Lab Assessment",
            target_id=target.id,
            status="ACTIVE",
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        # ── Test 2: Scope validation before scan execution ────────────────────
        print("\n[TEST 2] Scope Validation Enforcement Before Scan Execution...")
        scope_res = await ScopeValidationService.validate_scope(
            session=session,
            requested_target="192.168.1.100",
            target_id=target.id,
            requested_port=80,
            requested_action="nmap_scan",
        )
        assert scope_res.allowed is True, f"Authorized port 80 should be allowed, got: {scope_res.reason}"
        print(f"  [+] Port 80 validation passed: {scope_res.reason}")
        passed_tests += 1
        print("  [+] PASS: Strict scope validation approved authorized target.")

        # ── Test 3: Rejection of unauthorized scan targets ────────────────────
        print("\n[TEST 3] Rejection of Unauthorized Scan Targets and Excluded Ports...")
        unauth_scope = await ScopeValidationService.validate_scope(
            session=session,
            requested_target="unauthorized.badactor.com",
            requested_action="nmap_scan",
        )
        assert unauth_scope.allowed is False, "Unauthorized domain must be rejected by default-deny!"
        print(f"  [+] Unauthorized host correctly rejected: {unauth_scope.reason}")

        excluded_port_scope = await ScopeValidationService.validate_scope(
            session=session,
            requested_target="192.168.1.100",
            target_id=target.id,
            requested_port=22,
            requested_action="nmap_scan",
        )
        assert excluded_port_scope.allowed is False, "Excluded port 22 must be denied!"
        print(f"  [+] Excluded port 22 correctly denied: {excluded_port_scope.reason}")
        passed_tests += 1
        print("  [+] PASS: Default-deny and excluded ports strictly enforced.")

        # ── Test 4: Safe argument construction (no shell=True) ───────────────
        print("\n[TEST 4] Safe Argument Construction and Subprocess Guarantees...")
        import inspect
        from app.scanners import nmap_runner
        runner_source = inspect.getsource(nmap_runner)
        assert "shell=True" not in runner_source, "CRITICAL SECURITY VIOLATION: shell=True found in nmap_runner!"
        assert "create_subprocess_exec" in runner_source, "Safe create_subprocess_exec must be used!"
        print("  [+] Code inspection verified: zero shell=True invocations; safe exec argument lists used exclusively.")
        passed_tests += 1
        print("  [+] PASS: Subprocess execution is safe from shell injection.")

        # ── Test 5: Nmap XML Parsing & Feature Extraction ─────────────────────
        print("\n[TEST 5] Nmap XML Report Parsing...")
        nmap_findings = NmapParser.parse_xml(TEST_NMAP_XML, default_host="192.168.1.100")
        assert len(nmap_findings) >= 2, f"Expected at least 2 findings, got {len(nmap_findings)}"
        
        # Check port 80 finding
        p80_find = next(f for f in nmap_findings if f.port == 80)
        assert "Apache" in p80_find.service or "http" in p80_find.service
        assert p80_find.cve_id == "CVE-2021-41773", f"Expected CVE-2021-41773, got {p80_find.cve_id}"
        assert p80_find.severity.lower() == "high"

        # Check port 21 finding (plaintext protocol)
        p21_find = next(f for f in nmap_findings if f.port == 21)
        assert p21_find.severity.lower() == "medium"
        assert "vsftpd" in p21_find.evidence

        print(f"  [+] Nmap findings extracted: {len(nmap_findings)}")
        print(f"    - Finding: {p80_find.title} | CVE: {p80_find.cve_id} | Sev: {p80_find.severity}")
        print(f"    - Finding: {p21_find.title} | Sev: {p21_find.severity}")
        passed_tests += 1
        print("  [+] PASS: Nmap XML successfully parsed with services, banners, and CVEs.")

        # ── Test 6: OWASP ZAP JSON & XML Parsing ──────────────────────────────
        print("\n[TEST 6] OWASP ZAP JSON and XML Report Ingestion...")
        zap_json_findings = ZapParser.parse_json(TEST_ZAP_JSON, default_host="192.168.1.100")
        assert len(zap_json_findings) == 2, f"Expected 2 ZAP JSON findings, got {len(zap_json_findings)}"
        zap_traversal = next(f for f in zap_json_findings if "Path Traversal" in f.title)
        assert zap_traversal.cwe_id == "CWE-22"
        assert zap_traversal.severity.lower() == "high"
        assert zap_traversal.confidence.lower() == "high"
        assert "root:x:0:0" in zap_traversal.evidence

        zap_xml_findings = ZapParser.parse_xml(TEST_ZAP_XML, default_host="192.168.1.100")
        assert len(zap_xml_findings) == 1, f"Expected 1 ZAP XML finding, got {len(zap_xml_findings)}"
        assert zap_xml_findings[0].cwe_id == "CWE-1021"
        assert zap_xml_findings[0].severity.lower() == "medium"

        print(f"  [+] ZAP JSON parsed: {len(zap_json_findings)} findings (CWE-22 extracted with raw proof).")
        print(f"  [+] ZAP XML parsed: {len(zap_xml_findings)} finding (CWE-1021 extracted).")
        passed_tests += 1
        print("  [+] PASS: OWASP ZAP JSON and XML reports parsed accurately.")

        # ── Test 7: Nikto JSON & XML Parsing ──────────────────────────────────
        print("\n[TEST 7] Nikto JSON and XML Report Ingestion...")
        nikto_json_findings = NiktoParser.parse_json(TEST_NIKTO_JSON, default_host="192.168.1.100")
        assert len(nikto_json_findings) == 2, f"Expected 2 Nikto findings, got {len(nikto_json_findings)}"
        nikto_cve = next(f for f in nikto_json_findings if f.cve_id == "CVE-2021-41773")
        assert nikto_cve.severity.lower() == "high"
        assert "/icons/" in nikto_cve.url_path

        nikto_xml_findings = NiktoParser.parse_xml(TEST_NIKTO_XML, default_host="192.168.1.100")
        assert len(nikto_xml_findings) == 1, f"Expected 1 Nikto XML finding, got {len(nikto_xml_findings)}"
        assert "/manual/" in nikto_xml_findings[0].url_path

        print(f"  [+] Nikto JSON parsed: {len(nikto_json_findings)} findings (CVE-2021-41773 detected).")
        print(f"  [+] Nikto XML parsed: {len(nikto_xml_findings)} finding.")
        passed_tests += 1
        print("  [+] PASS: Nikto JSON and XML parsed with full OSVDB & URI context.")

        # ── Test 8: Malformed Report Error Handling ───────────────────────────
        print("\n[TEST 8] Malformed Report Error Handling...")
        try:
            NmapParser.parse_xml("<broken xml<nmap>")
            assert False, "Should have raised ValueError on malformed Nmap XML"
        except ValueError as e:
            print(f"  [+] Malformed Nmap XML caught: {e}")

        try:
            ZapParser.parse_json("{invalid_json: true, broken")
            assert False, "Should have raised ValueError on malformed ZAP JSON"
        except ValueError as e:
            print(f"  [+] Malformed ZAP JSON caught: {e}")

        try:
            NiktoParser.parse_json("NOT_JSON")
            assert False, "Should have raised ValueError on malformed Nikto JSON"
        except ValueError as e:
            print(f"  [+] Malformed Nikto JSON caught: {e}")

        passed_tests += 1
        print("  [+] PASS: All malformed report formats cleanly rejected with informative errors.")

        # ── Test 9: Duplicate Detection and Multi-Tool Evidence Merging ───────
        print("\n[TEST 9] Duplicate Detection & Multi-Tool Evidence Merging...")
        # Verify fingerprint uniqueness across assets
        fp_host_a = compute_finding_fingerprint("192.168.1.100", 80, None, "CVE-2021-41773", None, "Path Traversal")
        fp_host_b = compute_finding_fingerprint("10.0.0.50", 80, None, "CVE-2021-41773", None, "Path Traversal")
        assert fp_host_a != fp_host_b, "CRITICAL: Fingerprints across different hosts MUST NEVER be identical!"
        print("  [+] Host isolation verified: Different hosts produce different fingerprints.")

        # Persist Nmap findings into DB
        persisted_nmap = await deduplicate_and_persist_findings(
            parsed_findings=nmap_findings,
            assessment_id=assessment.id,
            scan_job_id=None,
            session=session,
        )
        initial_count = len(persisted_nmap)
        print(f"  [+] Persisted {initial_count} initial Nmap findings.")

        # Ingest Nikto findings (which includes the same CVE-2021-41773 on port 80!)
        persisted_nikto = await deduplicate_and_persist_findings(
            parsed_findings=nikto_json_findings,
            assessment_id=assessment.id,
            scan_job_id=None,
            session=session,
        )

        # Query finding for CVE-2021-41773 in DB
        q_cve = select(Finding).where(Finding.assessment_id == assessment.id, Finding.cve_id == "CVE-2021-41773")
        res_cve = await session.execute(q_cve)
        merged_cve_finding = res_cve.scalars().all()
        assert len(merged_cve_finding) == 1, f"Expected exactly 1 merged finding, got {len(merged_cve_finding)}"
        
        target_f = merged_cve_finding[0]
        assert "Nmap" in target_f.source_tool and "Nikto" in target_f.source_tool, f"Expected combined source tools, got: {target_f.source_tool}"
        assert target_f.confidence == "Confirmed", f"Multi-tool finding must be Confirmed, got: {target_f.confidence}"
        
        # Verify raw evidence artifacts preserved both traces
        artifacts = json.loads(target_f.raw_evidence_artifacts)
        assert len(artifacts) >= 2, f"Expected at least 2 raw evidence artifacts, got {len(artifacts)}"
        tools_in_artifacts = [a["source_tool"] for a in artifacts]
        assert "Nmap" in tools_in_artifacts and "Nikto" in tools_in_artifacts
        print(f"  [+] Multi-tool finding successfully merged! Source: {target_f.source_tool} | Confidence: {target_f.confidence}")
        print(f"  [+] Raw artifacts preserved: {len(artifacts)} traces from {tools_in_artifacts}")
        passed_tests += 1
        print("  [+] PASS: Duplicate detected, evidence merged without data loss, cross-asset merge strictly prevented.")

        # ── Test 10: Evidence Traceability, Risk Prioritizer & AI Correlation ───
        print("\n[TEST 10] Risk Prioritization, Traceability & AI Correlation Engine...")
        score, explanation = RiskPrioritizer.calculate_risk(
            severity="high",
            cvss_score=None,
            host="192.168.1.100",
            port=80,
            cve_id="CVE-2021-41773",
            evidence="Path traversal and remote code execution payload verified",
            confidence="Confirmed",
        )
        assert score >= 80.0, f"High severity with RCE and CVE should score >= 80.0, got {score}"
        assert "Base Score" in explanation and "Exposure" in explanation and "Final Risk Score" in explanation
        print(f"  [+] Multi-factor Risk Score: {score}/100")
        print(f"  [+] Transparent Explanation: {explanation}")

        # Also ingest ZAP findings
        await deduplicate_and_persist_findings(
            parsed_findings=zap_json_findings,
            assessment_id=assessment.id,
            scan_job_id=None,
            session=session,
        )

        # Run AI Correlation across all findings
        all_findings_res = await session.execute(select(Finding).where(Finding.assessment_id == assessment.id))
        all_findings = all_findings_res.scalars().all()
        
        correlation = await VulnerabilityCorrelator.correlate_assessment(
            assessment_id=assessment.id,
            target_host="192.168.1.100",
            findings=all_findings,
        )

        assert correlation.total_findings > 0, "Correlation should process findings"
        assert len(correlation.remediation_roadmap) > 0, "Roadmap should have prioritized items"
        print(f"  [+] AI Correlation completed (Engine: {correlation.engine})")
        print(f"  [+] Attack chains discovered: {len(correlation.attack_chains)}")
        print(f"  [+] Remediation roadmap items: {len(correlation.remediation_roadmap)}")
        print(f"  [+] Analyst summary: {correlation.analyst_summary}")
        passed_tests += 1
        print("  [+] PASS: Evidence traceability, multi-factor risk scoring, and cross-tool correlation verified.")

    print("\n" + "=" * 80)
    print(f"PHASE 5 VERIFICATION RESULT: {passed_tests}/{total_tests} TESTS PASSED (100% SUCCESS)")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(run_verification())
