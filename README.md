# AI-VAPT Agent

> **AI-Powered Unified Vulnerability Assessment and Penetration Testing Agent**

A conversational AI cybersecurity assistant that helps security analysts perform **authorized** vulnerability assessments. The system strictly validates all targets against an explicit allowlist — no assessment can begin without operator authorization.

---

## ⚠️ Ethical & Legal Notice

This tool is designed **exclusively** for authorized penetration testing and vulnerability assessments. You must have **explicit written permission** from the target system owner before running any scans. Unauthorized use against systems you do not own or have permission to test is illegal and unethical.

---

## Architecture

```
AI-VAPT-AGENT/
├── frontend/          # React + TypeScript + Vite + Tailwind
├── backend/           # FastAPI + SQLAlchemy + Python
├── documentation/     # Architecture docs, threat model
├── reports/           # Generated PDF reports (git-ignored)
├── .env.example       # Environment variable template
└── README.md
```

## Phase 1 — Completed ✅

- [x] Complete folder structure
- [x] React + TypeScript + Vite frontend with Tailwind CSS
- [x] FastAPI backend with async SQLite database
- [x] Health-check API endpoint
- [x] Dashboard with stat cards, severity chart, tool status
- [x] Sidebar navigation & header with live backend status indicator
- [x] Authorized target model with strict allowlist
- [x] Assessment model with scope validation (only authorized targets)
- [x] Scanner availability probe (Nmap, ZAP, Nikto, Nessus, OpenVAS)
- [x] Placeholder pages for all 10 modules
- [x] Audit trail model
- [x] `.env.example` and `.gitignore`

## Planned Phases

| Phase | Features |
|-------|----------|
| **2** | New Assessment workflow, AI planning, target registration UI |
| **3** | Nmap integration, scan orchestration, result ingestion |
| **4** | OWASP ZAP + Nikto integration, finding normalization |
| **5** | AI agent chat interface, vulnerability correlation |
| **6** | Approval center (human-in-the-loop), active validation |
| **7** | PDF report generation, evidence explorer |
| **8** | Advanced integrations (Nessus, OpenVAS, Burp Suite) |

---

## Getting Started

### Prerequisites

- **Python** 3.11+  
- **Node.js** 18+  
- **npm** 9+

### 1. Clone & Configure

```bash
git clone <repo-url>
cd AI-VAPT-AGENT

# Copy environment template
cp .env.example backend/.env
# Edit backend/.env with your LLM API key and settings
```

### 2. Start the Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at:
- **http://localhost:8000/api/v1/health** — Health check
- **http://localhost:8000/api/docs** — Interactive Swagger docs
- **http://localhost:8000/api/redoc** — ReDoc docs

### 3. Start the Frontend

```bash
cd frontend
npm install
npm run dev
```

Open **http://localhost:5173** in your browser.

### 4. Build for Production

```bash
cd frontend
npm run build
```

---

## Security Design Principles

1. **Explicit target authorization** — All targets must be registered and authorized before any assessment can begin.
2. **Strict scope validation** — Assessments are rejected if the target is not in the authorized allowlist.
3. **No arbitrary shell execution** — Scanner integrations use safe argument construction with fixed argument lists.
4. **Active exploitation disabled by default** — Requires explicit human approval workflow.
5. **Audit trail** — All security-relevant actions are logged immutably.
6. **Scanner honesty** — If a scanner is unavailable, it shows as NOT FOUND — never faked as successful.
7. **Evidence separation** — Raw scanner output is always distinguished from AI-generated explanations.
8. **No fabrication** — CVEs, scan results, and vulnerabilities are never invented.
9. **API keys server-side only** — LLM credentials never appear in frontend code or browser requests.

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, React Router v6, Recharts, Lucide React |
| Backend | Python, FastAPI, Pydantic v2, SQLAlchemy 2.0 (async) |
| Database | SQLite (dev) → PostgreSQL (prod) |
| AI | Modular LLM — OpenAI / Gemini / Anthropic / Ollama |
| Scanners | Nmap, OWASP ZAP, Nikto (+ Nessus, OpenVAS planned) |

---

## API Endpoints (Phase 1)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/health` | System health check |
| `GET` | `/api/v1/health/scanners` | Scanner availability |
| `GET` | `/api/v1/dashboard/stats` | Dashboard aggregate stats |
| `GET` | `/api/v1/targets` | List authorized targets |
| `POST` | `/api/v1/targets` | Register a new target |
| `PATCH` | `/api/v1/targets/{id}/authorize` | Authorize a target |
| `DELETE` | `/api/v1/targets/{id}` | Remove a target |
| `GET` | `/api/v1/assessments` | List assessments |
| `POST` | `/api/v1/assessments` | Create an assessment |
| `GET` | `/api/v1/assessments/{id}` | Get assessment detail |
| `DELETE` | `/api/v1/assessments/{id}` | Delete an assessment |

---

## Development

```bash
# Backend tests (Phase 2+)
cd backend && pytest

# Frontend type check
cd frontend && npx tsc --noEmit

# Frontend lint
cd frontend && npm run lint
```
