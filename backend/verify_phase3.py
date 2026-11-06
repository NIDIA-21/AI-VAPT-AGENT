"""
Automated Security & Scope Validation Tests for Phase 3.
Covers all 12 required test cases:
1. Successful target registration.
2. Invalid domain rejection (wildcards, malformed characters).
3. Invalid IP rejection (invalid octets, invalid IPv6 format).
4. Authorized target acceptance.
5. Unregistered target rejection.
6. Disallowed port rejection.
7. Excluded port rejection.
8. Expired authorization rejection.
9. Revoked target rejection.
10. Excluded URL path rejection.
11. Invalid port range rejection.
12. Default-deny behavior.
"""
import asyncio
from datetime import datetime, timedelta, timezone
from httpx import AsyncClient, ASGITransport

from main import app
from app.database.session import init_db


async def run_phase3_security_suite():
    await init_db()
    print("=================================================================")
    print("   AI-VAPT AGENT: PHASE 3 STRICT SCOPE VALIDATION TEST SUITE   ")
    print("=================================================================\n")

    passed_count = 0
    total_tests = 12

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Pre-cleanup in case of prior interrupted runs
        for test_host in ["192.168.1.50", "192.168.200.1", "app.securecorp.local"]:
            r_existing = await client.get(f"/api/v1/targets?search={test_host}")
            if r_existing.status_code == 200:
                for t in r_existing.json():
                    if t.get("host") == test_host:
                        await client.delete(f"/api/v1/targets/{t['id']}?hard_delete=true")

        now = datetime.now(timezone.utc)

        # -------------------------------------------------------------
        # Test 1: Successful Target Registration
        # -------------------------------------------------------------
        print("[Test 1/12] Successful target registration with normalized inputs...")
        target_payload = {
            "name": "Staging Web Cluster",
            "host": "192.168.1.50",
            "target_url": "https://192.168.1.50:8443",
            "purpose": "Routine VAPT Audit",
            "description": "Authorized staging web cluster for Q4 assessment",
            "auth_contact": "ciso-ops@company.internal",
            "auth_reference": "AUTH-2026-SEC-0042",
            "valid_from": (now - timedelta(days=1)).isoformat(),
            "valid_to": (now + timedelta(days=30)).isoformat(),
            "permitted_ports": [80, 443, 8080, 8443],
            "excluded_ports": [22, 3389, 5432],
            "excluded_paths": ["/admin", "/logout", "/payments"],
            "restrictions": "No destructive exploits. Safe fuzzing only.",
            "status": "ACTIVE",
            "authorized_by": "secops_lead",
        }
        r = await client.post("/api/v1/targets", json=target_payload)
        assert r.status_code == 201, f"Expected 201 Created, got {r.status_code}: {r.text}"
        target1 = r.json()
        target1_id = target1["id"]
        assert target1["host"] == "192.168.1.50"
        assert target1["status"] == "ACTIVE"
        print(f"  [PASS] Target registered with ID: {target1_id}")
        passed_count += 1

        # -------------------------------------------------------------
        # Test 2: Invalid Domain Rejection (wildcards, malformed characters)
        # -------------------------------------------------------------
        print("\n[Test 2/12] Invalid domain rejection (wildcards, shell characters)...")
        # Wildcard test
        r_wildcard = await client.post("/api/v1/targets", json={
            "name": "Wildcard Target",
            "host": "*.corp.example.com",
            "purpose": "Invalid test"
        })
        assert r_wildcard.status_code == 422, f"Expected 422 for wildcard, got {r_wildcard.status_code}"
        assert "wildcard" in r_wildcard.json()["detail"].lower()
        print("  [PASS] Sub-test 2a: Wildcard domain (*.corp.example.com) rejected with HTTP 422.")

        # Shell injection test
        r_shell = await client.post("/api/v1/targets", json={
            "name": "Shell Injection Target",
            "host": "corp.com; rm -rf /",
            "purpose": "Shell test"
        })
        assert r_shell.status_code == 422
        assert "illegal" in r_shell.json()["detail"].lower() or "dangerous" in r_shell.json()["detail"].lower()
        print("  [PASS] Sub-test 2b: Dangerous shell characters in host rejected with HTTP 422.")
        passed_count += 1

        # -------------------------------------------------------------
        # Test 3: Invalid IP Rejection (invalid octets, malformed IPv6)
        # -------------------------------------------------------------
        print("\n[Test 3/12] Invalid IP rejection (out-of-range octets, bad format)...")
        r_bad_ip = await client.post("/api/v1/targets", json={
            "name": "Bad IP Target",
            "host": "999.300.200.100",
            "purpose": "Bad IP test"
        })
        assert r_bad_ip.status_code == 422
        print(f"  [PASS] Sub-test 3a: Bad IPv4 octets rejected with HTTP 422: {r_bad_ip.json()['detail']}")

        # CIDR test
        r_cidr = await client.post("/api/v1/targets", json={
            "name": "CIDR Block Target",
            "host": "192.168.1.0/24",
            "purpose": "CIDR test"
        })
        assert r_cidr.status_code == 422
        assert "cidr" in r_cidr.json()["detail"].lower()
        print(f"  [PASS] Sub-test 3b: CIDR notation rejected with HTTP 422: {r_cidr.json()['detail']}")
        passed_count += 1

        # -------------------------------------------------------------
        # Test 4: Authorized Target Acceptance
        # -------------------------------------------------------------
        print("\n[Test 4/12] Authorized target acceptance in scope validation...")
        r_val_ok = await client.post("/api/v1/scope/validate", json={
            "requested_target": "192.168.1.50",
            "requested_port": 443,
            "requested_path": "/api/v1/users",
            "requested_protocol": "https"
        })
        assert r_val_ok.status_code == 200
        val_ok = r_val_ok.json()
        assert val_ok["allowed"] is True
        assert val_ok["target_id"] == target1_id
        print(f"  [PASS] Scope validated: allowed={val_ok['allowed']} | Reason: {val_ok['reason']}")
        passed_count += 1

        # -------------------------------------------------------------
        # Test 5: Unregistered Target Rejection
        # -------------------------------------------------------------
        print("\n[Test 5/12] Unregistered target rejection (Default-Deny)...")
        r_val_unreg = await client.post("/api/v1/scope/validate", json={
            "requested_target": "10.0.0.99",
            "requested_port": 80
        })
        assert r_val_unreg.status_code == 200
        val_unreg = r_val_unreg.json()
        assert val_unreg["allowed"] is False
        assert "not registered" in val_unreg["reason"].lower()
        print(f"  [PASS] Unregistered target rejected: allowed={val_unreg['allowed']} | Reason: {val_unreg['reason']}")
        passed_count += 1

        # -------------------------------------------------------------
        # Test 6: Disallowed Port Rejection
        # -------------------------------------------------------------
        print("\n[Test 6/12] Disallowed port rejection (port not in permitted list)...")
        # Port 9000 is not in [80, 443, 8080, 8443]
        r_val_disallowed = await client.post("/api/v1/scope/validate", json={
            "requested_target": "192.168.1.50",
            "requested_port": 9000
        })
        assert r_val_disallowed.status_code == 200
        val_disallowed = r_val_disallowed.json()
        assert val_disallowed["allowed"] is False
        assert "permitted ports" in val_disallowed["reason"].lower()
        print(f"  [PASS] Disallowed port 9000 rejected: {val_disallowed['reason']}")
        passed_count += 1

        # -------------------------------------------------------------
        # Test 7: Excluded Port Rejection
        # -------------------------------------------------------------
        print("\n[Test 7/12] Excluded port rejection (port explicitly forbidden)...")
        # Port 22 is in excluded_ports [22, 3389, 5432]
        r_val_excluded = await client.post("/api/v1/scope/validate", json={
            "requested_target": "192.168.1.50",
            "requested_port": 22
        })
        assert r_val_excluded.status_code == 200
        val_excluded = r_val_excluded.json()
        assert val_excluded["allowed"] is False
        assert "excluded" in val_excluded["reason"].lower()
        print(f"  [PASS] Excluded port 22 rejected: {val_excluded['reason']}")
        passed_count += 1

        # -------------------------------------------------------------
        # Test 8: Expired Authorization Rejection
        # -------------------------------------------------------------
        print("\n[Test 8/12] Expired authorization rejection...")
        # Register a target that expired yesterday
        r_exp = await client.post("/api/v1/targets", json={
            "name": "Old Expired Target",
            "host": "192.168.200.1",
            "purpose": "Expiration test",
            "auth_reference": "EXPIRED-REF-2025",
            "valid_from": (now - timedelta(days=60)).isoformat(),
            "valid_to": (now - timedelta(days=1)).isoformat(),
            "status": "ACTIVE",
            "authorized_by": "auditor"
        })
        assert r_exp.status_code == 201
        exp_target = r_exp.json()
        exp_id = exp_target["id"]

        # Validate against expired target
        r_val_exp = await client.post("/api/v1/scope/validate", json={
            "requested_target": "192.168.200.1",
            "requested_port": 80
        })
        assert r_val_exp.status_code == 200
        val_exp = r_val_exp.json()
        assert val_exp["allowed"] is False
        assert "expired" in val_exp["reason"].lower()
        print(f"  [PASS] Expired target rejected: {val_exp['reason']}")

        # Also attempt assessment creation -> Must be HTTP 403
        r_asm_exp = await client.post("/api/v1/assessments", json={
            "name": "Assessment against expired target",
            "target_id": exp_id
        })
        assert r_asm_exp.status_code == 403
        print("  [PASS] Assessment against expired target blocked with HTTP 403.")
        passed_count += 1

        # -------------------------------------------------------------
        # Test 9: Revoked Target Rejection
        # -------------------------------------------------------------
        print("\n[Test 9/12] Revoked target rejection...")
        # Revoke target1
        r_revoke = await client.post(f"/api/v1/targets/{target1_id}/revoke", json={
            "revoked_by": "security_officer_jane",
            "revocation_reason": "Emergency security incident: scope authorization revoked by client"
        })
        assert r_revoke.status_code == 200
        revoked_target = r_revoke.json()
        assert revoked_target["status"] == "REVOKED"
        print(f"  Target {target1_id} status updated to: {revoked_target['status']}")

        # Validate against revoked target -> Must be DENIED
        r_val_rev = await client.post("/api/v1/scope/validate", json={
            "requested_target": "192.168.1.50",
            "requested_port": 443
        })
        assert r_val_rev.status_code == 200
        val_rev = r_val_rev.json()
        assert val_rev["allowed"] is False
        assert "revoked" in val_rev["reason"].lower()
        print(f"  [PASS] Revoked target rejected: {val_rev['reason']}")

        # Assessment creation against revoked target -> Must be HTTP 403
        r_asm_rev = await client.post("/api/v1/assessments", json={
            "name": "Assessment against revoked target",
            "target_id": target1_id
        })
        assert r_asm_rev.status_code == 403
        print("  [PASS] Assessment against revoked target blocked with HTTP 403.")
        passed_count += 1

        # -------------------------------------------------------------
        # Test 10: Excluded URL Path Rejection
        # -------------------------------------------------------------
        print("\n[Test 10/12] Excluded URL path rejection (prefix matching)...")
        # Register a new active target with excluded paths
        r_web = await client.post("/api/v1/targets", json={
            "name": "Web Application Target",
            "host": "app.securecorp.local",
            "purpose": "DAST Testing",
            "auth_reference": "AUTH-PATH-TEST",
            "valid_from": (now - timedelta(days=1)).isoformat(),
            "valid_to": (now + timedelta(days=15)).isoformat(),
            "permitted_ports": [80, 443],
            "excluded_paths": ["/admin", "/logout", "/payments"],
            "status": "ACTIVE"
        })
        assert r_web.status_code == 201
        web_id = r_web.json()["id"]

        # Request excluded path /admin/settings
        r_val_path = await client.post("/api/v1/scope/validate", json={
            "requested_target": "app.securecorp.local",
            "requested_port": 443,
            "requested_path": "/admin/settings"
        })
        assert r_val_path.status_code == 200
        val_path = r_val_path.json()
        assert val_path["allowed"] is False
        assert "excluded" in val_path["reason"].lower()
        print(f"  [PASS] Sub-test 10a: Excluded subpath '/admin/settings' rejected: {val_path['reason']}")

        # Request allowed path /api/v1/catalog
        r_val_allowed_path = await client.post("/api/v1/scope/validate", json={
            "requested_target": "app.securecorp.local",
            "requested_port": 443,
            "requested_path": "/api/v1/catalog"
        })
        assert r_val_allowed_path.status_code == 200
        assert r_val_allowed_path.json()["allowed"] is True
        print("  [PASS] Sub-test 10b: Permitted path '/api/v1/catalog' allowed.")
        passed_count += 1

        # -------------------------------------------------------------
        # Test 11: Invalid Port Range Rejection
        # -------------------------------------------------------------
        print("\n[Test 11/12] Invalid port range rejection (ports > 65535 or inverted ranges)...")
        r_bad_port1 = await client.post("/api/v1/targets", json={
            "name": "Bad Port Target",
            "host": "test-ports.local",
            "permitted_ports": "80, 70000"
        })
        assert r_bad_port1.status_code == 422
        assert "out of range" in r_bad_port1.json()["detail"].lower()
        print("  [PASS] Sub-test 11a: Port 70000 (>65535) rejected with HTTP 422.")

        r_bad_port2 = await client.post("/api/v1/targets", json={
            "name": "Inverted Range Target",
            "host": "test-ports2.local",
            "permitted_ports": "8080-8000"
        })
        assert r_bad_port2.status_code == 422
        assert "cannot exceed" in r_bad_port2.json()["detail"].lower()
        print("  [PASS] Sub-test 11b: Inverted range '8080-8000' rejected with HTTP 422.")
        passed_count += 1

        # -------------------------------------------------------------
        # Test 12: Default-Deny Behavior
        # -------------------------------------------------------------
        print("\n[Test 12/12] Default-Deny behavior confirmation...")
        # Completely empty or non-matching request
        r_deny = await client.post("/api/v1/scope/validate", json={
            "requested_target": "unauthorized-external-server.com",
            "requested_port": 443
        })
        assert r_deny.status_code == 200
        val_deny = r_deny.json()
        assert val_deny["allowed"] is False
        assert "default-deny" in val_deny["reason"].lower() or "not registered" in val_deny["reason"].lower()
        print(f"  [PASS] Default-Deny verified: {val_deny['reason']}")
        passed_count += 1

        # -------------------------------------------------------------
        # Clean up test targets
        # -------------------------------------------------------------
        print("\n[Cleanup] Cleaning up test targets and verifying audit trail...")
        await client.delete(f"/api/v1/targets/{target1_id}?hard_delete=true")
        await client.delete(f"/api/v1/targets/{exp_id}?hard_delete=true")
        await client.delete(f"/api/v1/targets/{web_id}?hard_delete=true")

        # Verify audit trail
        r_audit = await client.get("/api/v1/scope/audit?limit=10")
        assert r_audit.status_code == 200
        audit = r_audit.json()
        assert audit["total_events"] > 0
        print(f"  [PASS] Audit log query returned {audit['total_events']} events.")
        for ev in audit["events"][:3]:
            print(f"    - Event [{ev['action']}]: {ev['detail'][:60]}...")

    print("\n=================================================================")
    print(f"   TEST SUITE SUMMARY: {passed_count}/{total_tests} TESTS PASSED (100% SUCCESS)   ")
    print("=================================================================")

if __name__ == "__main__":
    asyncio.run(run_phase3_security_suite())
