import asyncio
from httpx import AsyncClient, ASGITransport
from main import app
from app.database.session import init_db

async def run_end_to_end_test():
    await init_db()
    print("==============================================")
    print("      AI-VAPT AGENT COMPLETE VERIFICATION     ")
    print("==============================================\n")
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost:8000") as client:
        # [1] System Health
        print("[1] Testing System Health API (/api/v1/health)...")
        r = await client.get("/api/v1/health")
        assert r.status_code == 200, f"Health check failed: {r.status_code}"
        health = r.json()
        print(f"    STATUS: {health['status']} | DB: {health['database']} | VERSION: {health['version']}")
        
        # [2] Dashboard Endpoints in Clean State
        print("\n[2] Testing Dashboard Endpoints (Clean Database)...")
        stats = (await client.get("/api/v1/dashboard/stats")).json()
        print(f"    Metric 1 - Total Assessments: {stats['total_assessments']}")
        print(f"    Metric 2 - Active Scans: {stats['active_scans']}")
        print(f"    Metric 3 - Total Vulnerabilities: {stats['total_vulnerabilities']}")
        print(f"    Metric 4 - Critical Vulnerabilities: {stats['critical_vulnerabilities']}")
        assert stats["total_assessments"] == 0
        assert stats["total_vulnerabilities"] == 0
        
        # Severity
        sev = (await client.get("/api/v1/dashboard/severity")).json()
        print(f"    Severity Breakdown Total: {sev['total']} (Crit: {sev['critical']}, High: {sev['high']}, Med: {sev['medium']}, Low: {sev['low']}, Info: {sev['informational']})")
        assert sev["total"] == 0
        
        # Tools
        tools = (await client.get("/api/v1/dashboard/tools")).json()
        print(f"    Tools Probed: {tools['total_tools']} scanners")
        for t in tools["tools"]:
            print(f"      - {t['display_name']}: [{t['status']}] ({t['category']})")
        assert tools["total_tools"] == 7
        
        # [3] Scope & Authorization Security Test
        print("\n[3] Testing Scope Enforcement & Target Authorization Rules...")
        # Register a test target
        target_payload = {
            "name": "Local Staging Environment",
            "host": "127.0.0.1",
            "scope_notes": "Authorized local test fixture",
            "authorized_by": "lead_auditor"
        }
        res_target = await client.post("/api/v1/targets", json=target_payload)
        assert res_target.status_code == 201, f"Failed to register target: {res_target.text}"
        target = res_target.json()
        target_id = target["id"]
        print(f"    Target registered: {target['host']} (Status: {target['status']})")
        
        # Attempt assessment before authorization -> Must be REJECTED (HTTP 403)
        res_unauth = await client.post("/api/v1/assessments", json={
            "name": "Unauthorized Pre-Scan Test",
            "target_id": target_id,
            "assessment_type": "Network & Web"
        })
        print(f"    Unapproved Target Assessment Attempt: HTTP {res_unauth.status_code}")
        assert res_unauth.status_code == 403, "Security rule violation: Assessment allowed against unapproved target!"
        print("    SECURITY VERIFIED: Unapproved targets strictly rejected with HTTP 403.")
        
        # Authorize the target
        auth_res = await client.patch(f"/api/v1/targets/{target_id}/authorize?authorized_by=secops_lead")
        assert auth_res.status_code == 200
        print(f"    Explicit operator authorization granted: Status = {auth_res.json()['status']}")
        
        # Now create assessment -> Must SUCCEED (HTTP 201)
        res_asm = await client.post("/api/v1/assessments", json={
            "name": "Phase 2 Test Assessment",
            "target_id": target_id,
            "assessment_type": "Network & Web"
        })
        assert res_asm.status_code == 201
        asm = res_asm.json()
        print(f"    Assessment created: \"{asm['name']}\" (ID: asm-{asm['id'][:8]})")
        
        # [4] Verify Dashboard Reflects New Assessment Real-Time
        print("\n[4] Verifying Dashboard Updates with Real Data...")
        updated_stats = (await client.get("/api/v1/dashboard/stats")).json()
        print(f"    Updated Total Assessments: {updated_stats['total_assessments']}")
        print(f"    Updated Authorized Targets: {updated_stats['authorized_targets']}")
        assert updated_stats["total_assessments"] == 1
        assert updated_stats["authorized_targets"] == 1
        
        # Verify Activity Stream
        act = (await client.get("/api/v1/dashboard/activity")).json()
        print(f"    Assessment Activity Table items: {len(act['assessments'])}")
        assert len(act["assessments"]) >= 1
        latest_asm = act["assessments"][0]
        print(f"      - ID: {latest_asm['id'][:8]}... | Host: {latest_asm['target_host']} | Type: {latest_asm['assessment_type']}")
        
        print(f"    AI Agent Activity Stream items: {len(act['agent_activities'])}")
        assert len(act["agent_activities"]) >= 1
        for a in act["agent_activities"][:3]:
            print(f"      - [{a['category']}] {a['description']}")
            
        # Clean up test target and assessment
        await client.delete(f"/api/v1/assessments/{asm['id']}")
        await client.delete(f"/api/v1/targets/{target_id}")
        
        reset_stats = (await client.get("/api/v1/dashboard/stats")).json()
        assert reset_stats["total_assessments"] == 0
        print("    Cleaned up test records. Database returned to baseline.")

    print("\n==============================================")
    print("      ALL SYSTEM INTEGRITY TESTS PASSED!     ")
    print("==============================================")

if __name__ == "__main__":
    asyncio.run(run_end_to_end_test())
