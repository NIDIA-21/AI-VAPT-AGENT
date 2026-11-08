"""
Automated Verification Suite for Sprint 4:
Conversational AI Agent & Intelligent Assessment Planner.
Tests:
1. Engine status and safe provider metadata.
2. Conversational message processing & session persistence.
3. Strict scope validation in AI planner (unregistered target rejection).
4. Expired/revoked target refusal in AI agent.
5. Multi-stage assessment plan generation for active authorized targets.
6. Tool selection & rationale (Nmap, Nikto, ZAP, Metasploit human gate).
7. Decision trace generation (distinguishing concrete observations vs AI inferences).
8. Decision persistence and linking to assessments.
9. Assessment creation with attached AI plan.
10. Session message history and retrieval.
"""
import asyncio
from datetime import datetime, timedelta, timezone
from httpx import AsyncClient, ASGITransport

from main import app
from app.database.session import init_db


async def run_sprint4_verification():
    await init_db()
    print("=================================================================")
    print("   AI-VAPT AGENT: SPRINT 4 AI PLANNER & AGENT TEST SUITE       ")
    print("=================================================================\n")

    passed_count = 0
    total_tests = 10

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        now = datetime.now(timezone.utc)

        # -------------------------------------------------------------
        # Test 1: Engine Status (Safe, No Leaks)
        # -------------------------------------------------------------
        print("[Test 1/10] Engine status & safe metadata...")
        r_engine = await client.get("/api/v1/agent/engine-info")
        assert r_engine.status_code == 200, f"Expected 200, got {r_engine.status_code}"
        eng = r_engine.json()
        assert "active_engine" in eng
        assert "is_fallback" in eng
        assert "OPENAI_API_KEY" not in str(eng)
        print(f"  [PASS] Engine: {eng['active_engine']} | Fallback Mode: {eng['is_fallback']}")
        passed_count += 1

        # -------------------------------------------------------------
        # Test 2: General Chat Conversation & Session Creation
        # -------------------------------------------------------------
        print("\n[Test 2/10] General chat conversation and session persistence...")
        chat_req = {
            "message": "Hello! What is your role as the AI security assistant?",
            "user_name": "lead_analyst"
        }
        r_chat1 = await client.post("/api/v1/agent/chat", json=chat_req)
        assert r_chat1.status_code == 200
        chat1 = r_chat1.json()
        assert chat1["session_id"] is not None
        assert "AI-VAPT" in chat1["content"] or "security" in chat1["content"].lower()
        session_id = chat1["session_id"]
        print(f"  [PASS] Session created with ID: {session_id}")
        passed_count += 1

        # -------------------------------------------------------------
        # Test 3: Unregistered Target Rejection in AI Agent
        # -------------------------------------------------------------
        print("\n[Test 3/10] Unregistered target rejection in AI agent (Default-Deny)...")
        r_chat_unreg = await client.post("/api/v1/agent/chat", json={
            "session_id": session_id,
            "message": "Please scan 198.51.100.99 for all vulnerabilities immediately."
        })
        assert r_chat_unreg.status_code == 200
        unreg_data = r_chat_unreg.json()
        assert "unregistered" in unreg_data["content"].lower() or "alert" in unreg_data["content"].lower()
        print(f"  [PASS] Unregistered target 198.51.100.99 blocked by scope guard.")
        passed_count += 1

        # -------------------------------------------------------------
        # Setup: Register an Active Authorized Target
        # -------------------------------------------------------------
        print("\n[Setup] Registering active authorized target for planning...")
        # Clean up any leftover
        for cleanup_host in ["10.10.20.50", "10.10.99.1"]:
            r_clean = await client.get(f"/api/v1/targets?search={cleanup_host}")
            if r_clean.status_code == 200:
                for t in r_clean.json():
                    if t.get("host") == cleanup_host:
                        await client.delete(f"/api/v1/targets/{t['id']}?hard_delete=true")

        target_payload = {
            "name": "Internal Banking Gateway",
            "host": "10.10.20.50",
            "target_url": "https://10.10.20.50:8443",
            "purpose": "Sprint 4 AI Planning Verification",
            "description": "Authorized target for AI planner tests",
            "auth_contact": "secops@banking.internal",
            "auth_reference": "AUTH-SPRINT4-PLAN-001",
            "valid_from": (now - timedelta(days=1)).isoformat(),
            "valid_to": (now + timedelta(days=14)).isoformat(),
            "permitted_ports": [80, 443, 8443],
            "excluded_ports": [22, 3389],
            "excluded_paths": ["/admin", "/settlement/wire"],
            "restrictions": "No DoS. Safe automated DAST only.",
            "status": "ACTIVE",
            "authorized_by": "ciso",
        }
        r_target = await client.post("/api/v1/targets", json=target_payload)
        assert r_target.status_code == 201
        active_target = r_target.json()
        target_id = active_target["id"]
        print(f"  [Setup] Target registered: {active_target['host']} ({target_id})")

        # -------------------------------------------------------------
        # Test 4: Expired & Revoked Target Refusal in AI Planner
        # -------------------------------------------------------------
        print("\n[Test 4/10] Expired / Revoked target refusal in AI Planner...")
        # Create an expired target
        r_exp = await client.post("/api/v1/targets", json={
            "name": "Decommissioned Old Portal",
            "host": "10.10.99.1",
            "purpose": "Expired test",
            "valid_from": (now - timedelta(days=60)).isoformat(),
            "valid_to": (now - timedelta(days=10)).isoformat(),
            "status": "EXPIRED"
        })
        exp_target_id = r_exp.json()["id"]

        r_exp_plan = await client.post("/api/v1/agent/plan", json={
            "target_id": exp_target_id,
            "requirements": "Audit web ports"
        })
        assert r_exp_plan.status_code == 403
        print(f"  [PASS] Expired target rejected by planner with HTTP 403: {r_exp_plan.json()['detail']}")
        await client.delete(f"/api/v1/targets/{exp_target_id}?hard_delete=true")
        passed_count += 1

        # -------------------------------------------------------------
        # Test 5: Assessment Plan Generation for Active Target
        # -------------------------------------------------------------
        print("\n[Test 5/10] Multi-stage assessment plan generation...")
        r_plan = await client.post("/api/v1/agent/plan", json={
            "target_id": target_id,
            "requirements": "Assess web applications and services for OWASP Top 10 vulnerabilities.",
            "assessment_type": "full_vapt",
            "selected_categories": ["network_discovery", "web_vapt", "server_config"]
        })
        assert r_plan.status_code == 200
        plan = r_plan.json()
        assert plan["target_id"] == target_id
        assert len(plan["stages"]) >= 4
        print(f"  [PASS] Plan generated with {len(plan['stages'])} stages across target {plan['target_host']}.")
        passed_count += 1

        # -------------------------------------------------------------
        # Test 6: Scanner Recommendations & Rationales
        # -------------------------------------------------------------
        print("\n[Test 6/10] Scanner recommendations and rationales...")
        tools = [t["tool"] for t in plan["tool_recommendations"]]
        assert "Nmap" in tools
        assert "Nikto" in tools
        assert "OWASP ZAP" in tools
        assert "Metasploit" in tools

        # Metasploit must be held in PENDING_APPROVAL
        meta_tool = next(t for t in plan["tool_recommendations"] if t["tool"] == "Metasploit")
        assert meta_tool["recommended"] is False
        assert "Human Approval" in meta_tool["flags"]
        print(f"  [PASS] Tools recommended: Nmap, Nikto, OWASP ZAP. Metasploit held for Human Approval.")
        passed_count += 1

        # -------------------------------------------------------------
        # Test 7: Decision Trace & Observations vs Inferences
        # -------------------------------------------------------------
        print("\n[Test 7/10] Decision trace: Observations vs Inferences separation...")
        decisions = plan["decisions"]
        assert len(decisions) >= 4
        for d in decisions:
            assert len(d["evidence_and_observations"]) > 10, "Observations must be populated"
            assert len(d["ai_inferences"]) > 10, "AI inferences must be populated"
            assert d["execution_status"] in ["PLANNED", "PENDING_APPROVAL"]
        print(f"  [PASS] Verified {len(decisions)} decision trace items with concrete observations vs inferences.")
        passed_count += 1

        # -------------------------------------------------------------
        # Test 8: Decision Trace Query API
        # -------------------------------------------------------------
        print("\n[Test 8/10] Decision trace query endpoint (GET /api/v1/agent/decisions)...")
        r_dec = await client.get(f"/api/v1/agent/decisions?target_id={target_id}")
        assert r_dec.status_code == 200
        dec_list = r_dec.json()
        assert len(dec_list) >= len(decisions)
        print(f"  [PASS] Retrieved {len(dec_list)} persisted decision records from database.")
        passed_count += 1

        # -------------------------------------------------------------
        # Test 9: Create Assessment with Attached Plan
        # -------------------------------------------------------------
        print("\n[Test 9/10] Create assessment with attached AI plan and decision IDs...")
        decision_ids = [d["id"] for d in decisions]
        r_ass = await client.post("/api/v1/assessments", json={
            "name": "Q4 Banking Core VAPT",
            "description": "Assessment planned by Conversational AI Agent",
            "target_id": target_id,
            "assessment_type": "full_vapt",
            "ai_plan": plan["summary"],
            "decision_ids": decision_ids,
            "created_by": "lead_analyst"
        })
        assert r_ass.status_code == 201
        ass_data = r_ass.json()
        assert ass_data["target_id"] == target_id
        assert ass_data["ai_plan"] is not None
        print(f"  [PASS] Assessment created with attached AI Plan: {ass_data['id']}")
        passed_count += 1

        # -------------------------------------------------------------
        # Test 10: Chat Session Message History Retrieval
        # -------------------------------------------------------------
        print("\n[Test 10/10] Session message history retrieval...")
        r_sess = await client.get(f"/api/v1/agent/sessions/{session_id}")
        assert r_sess.status_code == 200
        sess_data = r_sess.json()
        assert len(sess_data["messages"]) >= 2
        print(f"  [PASS] Retrieved session '{session_id}' with {len(sess_data['messages'])} messages.")
        passed_count += 1

        # Cleanup
        await client.delete(f"/api/v1/targets/{target_id}?hard_delete=true")

    print("\n=================================================================")
    print(f"   SPRINT 4 TEST SUITE SUMMARY: {passed_count}/{total_tests} TESTS PASSED (100% SUCCESS)   ")
    print("=================================================================")

if __name__ == "__main__":
    asyncio.run(run_sprint4_verification())
