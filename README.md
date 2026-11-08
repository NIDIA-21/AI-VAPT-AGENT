# AI-VAPT AGENT

> **AI-Powered Unified Vulnerability Assessment & Penetration Testing Platform**  
> *Defensive AI Security Governance • Strict Scope Enforcement • Human-in-the-Loop Validation*

[![Python](https://img.shields.io/badge/Python-3.14-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115.5-009688.svg)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-19.0-61DAFB.svg)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-3178C6.svg)](https://www.typescriptlang.org)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-3.4-38B2AC.svg)](https://tailwindcss.com)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)]()

---

## 1. Project Introduction

**AI-VAPT AGENT** is an intelligent, unified vulnerability assessment and penetration testing system. It bridges the gap between natural language security requests and rigorous technical execution by combining conversational AI planning, multi-scanner orchestration, SHA-256 finding deduplication, evidence-based vulnerability intelligence, and strict scope governance into a cohesive cybersecurity platform.

---

## 2. Problem Statement

Traditional vulnerability management faces three critical failure modes:
1. **Unbounded Agent Risk**: Autonomous security agents risk executing unauthorized actions, spraying packets across out-of-scope enterprise subnets, or triggering denial-of-service conditions.
2. **AI Hallucination & Fake Findings**: Generic LLM assistants frequently fabricate nonexistent CVE identifiers, hallucinate inaccurate CVSS scores, and claim vulnerabilities without verified evidence.
3. **Fragmented Tool Silos**: Analysts struggle to correlate disjoint outputs across network scanners (Nmap), DAST engines (OWASP ZAP), and web server scanners (Nikto), leading to alert fatigue and duplicate reports.

**AI-VAPT AGENT** solves these issues with:
- A **centralized default-deny scope enforcement engine** that rejects out-of-scope targets before any scanner process spawns.
- An **evidence-backed vulnerability schema** where CVEs and CVSS ratings are strictly attributed to verified scanner output.
- A **human-in-the-loop approval gate** that halts intrusive validation actions until an authorized analyst explicitly reviews and approves them.

---

## 3. Core Features

- **Scope Management Allowlist**: Normalizes IPv4, IPv6, and FQDNs; enforces validity windows and excluded ports/paths; rejects wildcard domains and shell characters.
- **Conversational AI Security Planner**: Conversational chat assistant powered by Google Gemini / OpenAI with an autonomous **Deterministic Rule-Based Security Engine fallback**.
- **Safe Subprocess Scanner Runner**: Scoped Nmap execution using argument lists (strictly zero `shell=True`) with 60-second timeouts.
- **Official Report Ingestion**: Native JSON and XML report parsers for OWASP ZAP and Nikto.
- **Unified Finding Normalization**: Standardized schema tracking title, severity, CVSS, CVE, CWE, affected assets, ports, URLs, and confidence.
- **Duplicate Detection & Multi-Tool Evidence Merging**: SHA-256 fingerprinting guarantees **zero cross-asset merges** while consolidating multi-tool findings on the same host/port.
- **Transparent Multi-Factor Risk Prioritization**: Computes risk scores ($0.0 - 100.0$) using base severity, network exposure, exploit evidence, and confidence multipliers with transparent mathematical explanations.
- **AI Vulnerability Correlation & Attack Chain Mapping**: Synthesizes cross-tool findings into multi-stage attack vectors (Reconnaissance $\rightarrow$ Enumeration $\rightarrow$ Exploitation) and flags scanner discrepancies.
- **Human-in-the-Loop Approval Center**: Mandatory analyst identity, decision timestamps, and rejection rationales for intrusive validation steps.
- **Audit-Grade PDF Report Generator**: ReportLab-based generator producing 20-section reports with running headers, footers, and page numbers.

---

## 4. Technology Stack

| Layer | Technologies |
|:---|:---|
| **Frontend** | React 19, TypeScript, Vite 6, TailwindCSS, Recharts, Lucide React, Axios |
| **Backend** | Python 3.14, FastAPI 0.115.5, Uvicorn, Pydantic v2 |
| **Database** | SQLite 3 via SQLAlchemy 2.0 Async ORM, aiosqlite |
| **Reporting** | ReportLab 5.1 (Two-Pass `NumberedCanvas`, PDF-1.4 standard) |
| **Security Integrations** | Nmap Subprocess Runner, OWASP ZAP Parser, Nikto Parser, 7-Scanner Availability Prober |
| **AI Layer** | Google Gemini (`gemini-1.5-flash`), OpenAI (`gpt-4o-mini`), Deterministic Cybersecurity Expert System |

---

## 5. System Architecture

```
AI-VAPT-AGENT/
├── backend/
│   ├── app/
│   │   ├── agents/          # AI assistant, assessment planner, LLM providers, correlator
│   │   ├── api/v1/          # REST endpoints (health, dashboard, targets, scope, scanners, findings, approvals, reports)
│   │   ├── core/            # Configuration & environment settings
│   │   ├── database/        # Async SQLAlchemy session & dynamic SQLite migrations
│   │   ├── models/          # ORM models (AuthorizedTarget, Assessment, ScanJob, Finding, ApprovalRequest, AuditLog)
│   │   ├── reports/         # ReportLab 20-section PDF generator
│   │   ├── scanners/        # Safe Nmap runner, official ZAP & Nikto JSON/XML parsers, probe diagnostics
│   │   ├── schemas/         # Pydantic v2 schemas for request/response validation
│   │   └── services/        # Centralized ScopeValidationService, RiskPrioritizer, Deduplicator
│   ├── main.py              # FastAPI application entrypoint
│   ├── requirements.txt     # Python dependencies
│   └── verify_final_phase.py# 20-point automated test suite
├── frontend/
│   ├── src/
│   │   ├── components/      # Navigation, layouts, UI components
│   │   ├── pages/           # 10 interactive cybersecurity pages
│   │   ├── services/        # Axios API client services
│   │   └── types/           # Application TypeScript definitions
│   ├── package.json
│   └── vite.config.ts
├── docs/
│   └── ARCHITECTURE.md      # In-depth architectural specification and data flow diagrams
└── sample_vapt_report.pdf   # Generated audit-grade sample VAPT report
```

---

## 6. Installation Instructions

### Prerequisites
- **Python**: 3.11+ (Python 3.14 fully supported)
- **Node.js**: 18.0+
- **npm**: 9.0+
- **Git**: Installed and on system `PATH`

### Repository Setup
```bash
git clone https://github.com/NIDIA-21/AI-VAPT-AGENT.git
cd AI-VAPT-AGENT
```

---

## 7. Environment Configuration

Copy the sample environment file and configure optional keys:
```bash
cp .env.example backend/.env
```

Key environment variables in `backend/.env`:
```ini
APP_NAME="AI-VAPT Agent"
DEBUG=false
DATABASE_URL="sqlite+aiosqlite:///./vapt_agent.db"
API_V1_PREFIX="/api/v1"

# LLM Configuration (Optional: If omitted, the Deterministic Security Engine executes automatically)
LLM_PROVIDER="deterministic"  # Options: deterministic, gemini, openai, ollama
GEMINI_API_KEY=""
OPENAI_API_KEY=""
LLM_MODEL="gemini-1.5-flash"
```

---

## 8. Backend Startup

1. Open a terminal in the project root:
```bash
cd backend
python -m pip install -r requirements.txt
```

2. Launch the backend server:
```bash
python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

The backend starts at `http://127.0.0.1:8000`.

---

## 9. Frontend Startup

1. Open a second terminal:
```bash
cd frontend
npm install
npm run dev
```

2. Open **http://localhost:5173** in your browser.

---

## 10. API Documentation

Interactive OpenAPI / Swagger documentation is available out of the box:
- **Interactive Swagger UI**: `http://127.0.0.1:8000/api/docs`
- **ReDoc Technical Reference**: `http://127.0.0.1:8000/api/redoc`
- **OpenAPI Schema (JSON)**: `http://127.0.0.1:8000/api/openapi.json`

---

## 11. Scanner Integrations

The platform features safe execution and native report ingestion:
1. **Nmap Network Discovery**: Safe subprocess execution (`asyncio.create_subprocess_exec`) with `-sV -T4 -Pn --open -p <ports> -oX - <host>`. Strict scope verification runs before command generation.
2. **OWASP ZAP DAST Ingestion**: Official JSON and XML report parser. Ingests alerts, CWE IDs, risk levels, URLs, parameters, and evidence.
3. **Nikto Web Scanner Ingestion**: Official JSON and XML report parser. Ingests advisories, OSVDB references, HTTP methods, and CVEs.

---

## 12. Integration Status Matrix

| Tool | Integration Type | Mode | Truthful Status | Input / Output Format | Primary Limitations |
|:---|:---|:---:|:---:|:---|:---|
| **Nmap** | Live Subprocess | LIVE / IMPORT | Available / Not Installed | CLI args $\rightarrow$ XML (`-oX -`) | Strict allowlist enforced; no arbitrary IP ranges. |
| **OWASP ZAP** | Report Ingestion | IMPORT ONLY | Import Only | ZAP JSON & XML v2.14+ | Ingestion mode active; target host must match scope. |
| **Nikto** | Report Ingestion | IMPORT ONLY | Import Only | Nikto JSON & XML | Ingestion mode active; target host must match scope. |
| **Nessus** | Enterprise Scanner | PLANNED | Planned | Nessus XML (`.nessus`) | Adapter planned for future release. |
| **OpenVAS** | Vulnerability Feed | PLANNED | Planned | GVM XML format | Adapter planned for future release. |
| **Burp Suite** | Web Proxy & Scanner | PLANNED | Planned | Burp XML / JSON | Adapter planned for future release. |
| **Metasploit** | Exploitation Framework | UNSUPPORTED | Unsupported | Modular Payloads | **Autonomous exploitation strictly prohibited.** Human gate enforced. |

---

## 13. Scope Enforcement

All assessment activity is gated by [`ScopeValidationService`](file:///c:/Users/nixon/AI-VAPT-AGENT/backend/app/services/scope_validator.py).
- **Default-Deny Policy**: Any host, IP, or domain not explicitly registered in `ACTIVE` status is blocked.
- **Port Allowlist**: Only explicitly permitted ports (e.g. `80, 443`) are tested.
- **Port Exclusion Override**: Excluded ports (e.g. `22, 3389`) strictly override permitted entries.
- **Path Exclusion Matching**: Prefix-based path blocking (e.g. `/admin` blocks `/admin/settings`).
- **No Wildcard Domains**: Wildcards (`*.example.com`) and broad CIDR blocks (`/24`) are rejected during registration.

---

## 14. Human-in-the-Loop Approval Mechanism

Located at `/approvals` in the web application:
- Elevated or intrusive validation actions (e.g., active SQLi proof-of-concept probes, deep DAST crawlers) are queued in `PENDING` state.
- **Approval Gate**: An analyst must enter their identity and review target scope, validation purpose, and risk information.
- **Scope Re-Verification**: Approving an action automatically re-validates target authorization. If a target expired or was revoked in the interim, approval is blocked.
- **Rejection Rationale**: Rejections require a mandatory analyst rationale recorded in immutable audit logs.
- **Zero Autonomous Exploitation**: Metasploit and intrusive exploits are held in approval queue and never executed autonomously.

---

## 15. PDF Reporting

Located at `/reports` in the web application:
- Generates publication-quality, audit-grade VAPT reports using ReportLab.
- Contains 20 required sections including Executive Summary, Scope Boundaries, Assets Tested, Tool Execution Audit, Prioritized Findings, Detailed Technical Findings, Scanner Evidence, Limitations, and Human Approvals.
- Uses `NumberedCanvas` for two-pass running page numbering (`Page X of Y`).
- **Non-Fabrication Guarantee**: Generates strictly from database findings. If zero findings exist, the report explicitly states: *"No vulnerability findings were recorded during this assessment."*

---

## 16. Testing Instructions

Run the automated test suites from the project root:

```bash
# 1. Final Phase Verification Suite (All 20 Criteria)
python backend/verify_final_phase.py

# 2. Phase 5 Cybersecurity Tools & Evidence Suite (10 Criteria)
python backend/verify_phase5.py

# 3. Phase 4 AI Planner & Chat Suite (10 Criteria)
python backend/verify_sprint4.py

# 4. Phase 3 Strict Scope Validation Suite (12 Criteria)
python backend/verify_phase3.py

# 5. Frontend Production Build Check
cd frontend && npm run build
```

---

## 17. Known Limitations

- **Live Nmap Availability**: Requires `nmap` installed on the host system to execute live network scans; if missing, the UI gracefully informs the analyst and switches to official XML report import mode.
- **DAST / Web Scanner Execution**: OWASP ZAP and Nikto operate in official report ingestion mode (`IMPORT ONLY`) to avoid uncontrolled network flooding during automated runs.
- **Autonomous Exploitation**: Metasploit modules are restricted by policy; the platform prioritizes vulnerability identification and evidence verification over intrusive exploitation.

---

## 18. Hackathon Demonstration Workflow

Follow these 10 steps for a live presentation to the hackathon judges:

1. **Step 1: Register Authorized Target**  
   Navigate to **Target Management** (`/targets`). Click **Register Target**. Enter host `192.168.1.50`, permitted ports `80, 443`, authorization reference `AUTH-DEMO-2026`. Observe immediate scope normalization and audit logging.
2. **Step 2: Enter Conversational Security Request**  
   Navigate to **AI Agent** (`/agent`). Send: *"Perform a web vulnerability assessment on 192.168.1.50."*
3. **Step 3: Show AI-Generated Assessment Planning**  
   Observe the 6-stage ordered assessment plan with tool recommendations (Nmap, Nikto, ZAP) and human approval gates for Metasploit.
4. **Step 4: Show Scanner Execution or Report Import**  
   Navigate to **Scan Activity** (`/scans`). Launch a scoped Nmap scan or navigate to **Integrations** (`/integrations`) to ingest sample ZAP/Nikto reports.
5. **Step 5: Display Normalized Vulnerability Findings**  
   Navigate to **Findings** (`/findings`). Inspect the normalized findings table with CVE, CWE, risk score pills, and severity badges.
6. **Step 6: Demonstrate Duplicate Detection & Evidence Correlation**  
   Click **Details** on any finding. Observe that Nmap and Nikto observations on the same host/port have merged into multi-tool evidence without overwriting original scanner traces.
7. **Step 7: Show Transparent Risk Prioritization**  
   Review the mathematical risk calculation trace (e.g. `Base Score: 85.0 + Exposure: +5.0 => Final Score: 90.0/100`).
8. **Step 8: Demonstrate Human Approval Mechanism**  
   Navigate to **Approval Center** (`/approvals`). Review the pending validation action. Click **Approve & Authorize** (or **Reject Action** with mandatory rationale). Observe audit recording and scope re-verification.
9. **Step 9: Generate & Download Professional VAPT PDF**  
   Navigate to **Reports** (`/reports`). Select the assessment, click **Download Official PDF**, and open the generated document (`sample_vapt_report.pdf`) to show all 20 audit sections.
10. **Step 10: Show Integration Status Matrix**  
    Navigate to **Integrations** (`/integrations`). Review the truthful diagnostic matrix displaying live availability, input/output formats, and limitations across all 7 cybersecurity tools.
