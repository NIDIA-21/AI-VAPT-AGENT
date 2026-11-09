# AI-VAPT AGENT — Demo Video Script
# DataOps Innovation Hackathon 2026 | Hack The Core
# Voice: Young Indian woman, natural Malayalam accent, warm conversational tone
# Total Target Duration: 5–7 minutes
# Recording: OBS Studio screen capture of http://localhost:5173
# ─────────────────────────────────────────────────────────────────────────────

---

## SECTION 1 — INTRO (0:00–0:30)
**[Screen: Slide 1 / Project Title Card]**

> "Hi, I'm demonstrating AI-VAPT AGENT — an AI-powered unified vulnerability assessment
> and penetration testing platform we built for the DataOps Innovation Hackathon 2026.
>
> This isn't just another security tool. It's an intelligent system that combines
> conversational AI, strict scope enforcement, multi-scanner correlation, and
> human-in-the-loop validation — everything a modern security operations center needs,
> in one platform.
>
> Let me walk you through it."

---

## SECTION 2 — DASHBOARD (0:30–1:00)
**[Screen: Navigate to http://localhost:5173 — Dashboard page]**

> "So this is our dashboard — the SOC command center. Right at the top, you can see
> the six-stage workflow progress indicator that shows exactly where we are in the
> assessment lifecycle — from target registration all the way to report generation.
>
> Below that, we have live severity counters, recent activity, and a complete scan
> activity overview. Everything is dark-themed with a professional cybersecurity aesthetic —
> cyan accents on a deep navy background."

---

## SECTION 3 — TARGET REGISTRATION (1:00–1:45)
**[Screen: Navigate to /targets — Target Management]**

> "Before any scan can run, we must register an authorized target. This is the
> foundation of our entire safety model — strict scope enforcement.
>
> I'll click 'Register Target', enter the host IP — say 192.168.1.50, set permitted
> ports to 80 and 443, add an authorization reference number, and register it.
>
> Notice that the system immediately normalizes the IP address, validates the port list,
> and logs an audit event with the exact timestamp. No wildcard domains, no broad CIDR
> blocks — everything is locked down from the start.
>
> Down here in the Scope Audit Log, every access attempt — approved or rejected —
> is immutably recorded."

---

## SECTION 4 — AI AGENT (1:45–2:45)
**[Screen: Navigate to /agent — AI Agent page]**

> "Now here's where the intelligence comes in — our conversational AI security planner.
>
> I'll type: 'Perform a web vulnerability assessment on 192.168.1.50.'
>
> And watch what happens — the AI engine instantly verifies the target is in scope,
> and generates a six-stage assessment plan — Nmap port discovery, Nikto web fingerprinting,
> OWASP ZAP dynamic analysis, evidence correlation, human approval gate, and
> PDF report generation.
>
> Notice the label here — RULE-BASED ENGINE or LLM-GENERATED — we're completely
> transparent about whether Gemini, GPT-4o, or our deterministic expert system
> generated this response."

**[Screen: Type a mismatched target query]**

> "Now let me show you something really important. I'll ask the agent to scan
> a different IP — 10.10.20.50 — which is NOT the active session target.
>
> Immediately — TARGET SCOPE MISMATCH DETECTED. The system shows the requested
> target versus the authorized target, explains why planning was blocked, and
> records this rejection in the audit log. Zero tolerance for out-of-scope actions."

---

## SECTION 5 — SCANNER HUB (2:45–3:30)
**[Screen: Navigate to /integrations — Scanner Hub]**

> "This is the Scanner Integration Hub. We support seven security tools — Nmap,
> OWASP ZAP, Nikto, Nessus, OpenVAS, Burp Suite, and Metasploit.
>
> Each card shows the truthful integration status. Nmap has a live subprocess runner
> when installed, plus an XML report parser that's always available. ZAP and Nikto
> are in import-only mode — we ingest their official reports and normalize the findings.
>
> Nessus, OpenVAS, and Burp Suite are on our roadmap. And Metasploit —
> you'll see it's marked UNSUPPORTED for autonomous use. That's by design.
> No autonomous exploitation. Ever.
>
> Let me paste a sample ZAP report here — select the target, choose XML format,
> paste the content, and import. The system validates scope, parses the alerts,
> normalizes them, and stores them in the database."

---

## SECTION 6 — FINDINGS & RISK SCORING (3:30–4:15)
**[Screen: Navigate to /findings — Findings page]**

> "Here are the normalized vulnerability findings. Every finding has a title,
> severity badge, CVE identifier, CWE category, affected host, port, and
> a computed risk score from zero to a hundred.
>
> The risk formula is completely transparent — base severity, plus network exposure,
> plus exploit evidence confidence — all shown in the finding details.
>
> We also do SHA-256 based deduplication — if Nmap and Nikto both detect the same
> vulnerability on the same host and port, they're merged into one finding with
> combined evidence. No duplicate alerts.
>
> And analysts can mark findings as false positives — which immediately affects
> risk prioritization and report generation."

---

## SECTION 7 — HUMAN APPROVAL (4:15–4:50)
**[Screen: Navigate to /approvals — Approvals page]**

> "Every intrusive action — SQLi probes, deep DAST crawls, any active exploitation —
> must pass through this human approval gate before execution.
>
> I can see the pending action here — target, scope details, risk information.
> I'll enter my analyst ID, review the details, and either approve or reject.
>
> If I reject, I must provide a written rationale — that's mandatory. Both the approval
> and rejection are timestamped and stored in an immutable audit trail.
> The scope is also re-verified at approval time — if the target expired between
> planning and approval, the action is automatically blocked."

---

## SECTION 8 — PDF REPORT (4:50–5:30)
**[Screen: Navigate to /reports — Reports page]**

> "Finally — the PDF report. Click Download Official PDF, and we get a full
> twenty-section audit-grade VAPT report generated by ReportLab.
>
> It includes the executive summary, scope boundaries, assets tested versus
> assets registered, tool execution audit with truthful failure records,
> prioritized findings, CVE traceability, business risk considerations,
> baseline security recommendations, human approval records, and limitations.
>
> And here's something we're really proud of — if no scanner evidence exists,
> the report says exactly that — Assessment Status: INCONCLUSIVE DRAFT.
> No fabricated findings. No invented CVEs. Only what's in the database."

---

## SECTION 9 — CLOSING (5:30–6:00)
**[Screen: Return to Dashboard, then show Slide 18]**

> "AI-VAPT AGENT brings together conversational AI, strict scope governance,
> multi-tool correlation, transparent risk prioritization, human oversight,
> and professional reporting — all in one platform.
>
> We built this to show that intelligent cybersecurity doesn't mean autonomous
> and unchecked. It means smart, safe, transparent, and human-guided.
>
> Thank you so much for watching. The source code is on GitHub at
> github.com/NIDIA-21/AI-VAPT-AGENT — please do check it out."

---

## RECORDING GUIDE

### Tools Needed
- **OBS Studio** (free) — screen capture
- **Audio**: Record voice separately using phone Voice Memos app (sounds more natural)
  - Or use Audacity for PC recording
- **Merge**: Use DaVinci Resolve (free) or Kapwing.com to overlay audio on screen recording
- **Export**: MP4, 1920×1080, 30fps

### Screen Flow Summary
| Timestamp | URL | Action |
|---|---|---|
| 0:00–0:30 | PPT Slide 1 | Show title slide |
| 0:30–1:00 | localhost:5173/ | Dashboard walkthrough |
| 1:00–1:45 | localhost:5173/targets | Register target, show audit log |
| 1:45–2:45 | localhost:5173/agent | AI planning + mismatch demo |
| 2:45–3:30 | localhost:5173/integrations | Scanner hub + ZAP import |
| 3:30–4:15 | localhost:5173/findings | Findings table + risk scoring |
| 4:15–4:50 | localhost:5173/approvals | Human approval workflow |
| 4:50–5:30 | localhost:5173/reports | Generate and open PDF |
| 5:30–6:00 | Dashboard / Slide 18 | Closing statement |

### Voice Tips for Natural Sound
- Record in a quiet room with minimal echo
- Keep a glass of water nearby
- Speak naturally and conversationally — not like reading a script
- Use slight pauses between sections
- Smile while speaking — it comes through in the voice
- Record each section separately and join them — easier to re-record mistakes
