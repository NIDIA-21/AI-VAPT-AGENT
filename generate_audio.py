from gtts import gTTS
import os
import subprocess
import json

segments = [
    {
        "id": "01_intro",
        "text": "Hi, I'm demonstrating AI-VAPT AGENT — an AI-powered unified vulnerability assessment and penetration testing platform we built for the DataOps Innovation Hackathon 2026. This isn't just another security tool. It's an intelligent system that combines conversational AI, strict scope enforcement, multi-scanner correlation, and human-in-the-loop validation — everything a modern security operations center needs, in one platform. Let me walk you through it."
    },
    {
        "id": "02_dashboard",
        "text": "So this is our dashboard — the SOC command center. Right at the top, you can see the six-stage workflow progress indicator that shows exactly where we are in the assessment lifecycle — from target registration all the way to report generation. Below that, we have live severity counters, recent activity, and a complete scan activity overview. Everything is dark-themed with a professional cybersecurity aesthetic — cyan accents on a deep navy background."
    },
    {
        "id": "03_targets",
        "text": "Before any scan can run, we must register an authorized target. This is the foundation of our entire safety model — strict scope enforcement. I'll click Register Target, enter the host IP — say 192.168.1.50, set permitted ports to 80 and 443, add an authorization reference number, and register it. Notice that the system immediately normalizes the IP address, validates the port list, and logs an audit event with the exact timestamp. No wildcard domains, no broad CIDR blocks — everything is locked down from the start. Down here in the Scope Audit Log, every access attempt — approved or rejected — is immutably recorded."
    },
    {
        "id": "04_ai_agent",
        "text": "Now here's where the intelligence comes in — our conversational AI security planner. I'll type: 'Perform a web vulnerability assessment on 192.168.1.50.' And watch what happens — the AI engine instantly verifies the target is in scope, and generates a six-stage assessment plan — Nmap port discovery, Nikto web fingerprinting, OWASP ZAP dynamic analysis, evidence correlation, human approval gate, and PDF report generation. Notice the label here — RULE-BASED ENGINE or LLM-GENERATED — we're completely transparent about whether Gemini, GPT-4o, or our deterministic expert system generated this response. Now let me show you something really important. I'll ask the agent to scan a different IP — 10.10.20.50 — which is NOT the active session target. Immediately — TARGET SCOPE MISMATCH DETECTED. The system shows the requested target versus the authorized target, explains why planning was blocked, and records this rejection in the audit log. Zero tolerance for out-of-scope actions."
    },
    {
        "id": "05_scanners",
        "text": "This is the Scanner Integration Hub. We support seven security tools — Nmap, OWASP ZAP, Nikto, Nessus, OpenVAS, Burp Suite, and Metasploit. Each card shows the truthful integration status. Nmap has a live subprocess runner when installed, plus an XML report parser that's always available. ZAP and Nikto are in import-only mode — we ingest their official reports and normalize the findings. Nessus, OpenVAS, and Burp Suite are on our roadmap. And Metasploit — you'll see it's marked UNSUPPORTED for autonomous use. That's by design. No autonomous exploitation. Ever. Let me paste a sample ZAP report here — select the target, choose XML format, paste the content, and import. The system validates scope, parses the alerts, normalizes them, and stores them in the database."
    },
    {
        "id": "06_findings",
        "text": "Here are the normalized vulnerability findings. Every finding has a title, severity badge, CVE identifier, CWE category, affected host, port, and a computed risk score from zero to a hundred. The risk formula is completely transparent — base severity, plus network exposure, plus exploit evidence confidence — all shown in the finding details. We also do SHA-256 based deduplication — if Nmap and Nikto both detect the same vulnerability on the same host and port, they're merged into one finding with combined evidence. No duplicate alerts. And analysts can mark findings as false positives — which immediately affects risk prioritization and report generation."
    },
    {
        "id": "07_approvals",
        "text": "Every intrusive action — SQLi probes, deep DAST crawls, any active exploitation — must pass through this human approval gate before execution. I can see the pending action here — target, scope details, risk information. I'll enter my analyst ID, review the details, and either approve or reject. If I reject, I must provide a written rationale — that's mandatory. Both the approval and rejection are timestamped and stored in an immutable audit trail. The scope is also re-verified at approval time — if the target expired between planning and approval, the action is automatically blocked."
    },
    {
        "id": "08_reports",
        "text": "Finally — the PDF report. Click Download Official PDF, and we get a full twenty-section audit-grade VAPT report generated by ReportLab. It includes the executive summary, scope boundaries, assets tested versus assets registered, tool execution audit with truthful failure records, prioritized findings, CVE traceability, business risk considerations, baseline security recommendations, human approval records, and limitations. And here's something we're really proud of — if no scanner evidence exists, the report says exactly that — Assessment Status: INCONCLUSIVE DRAFT. No fabricated findings. No invented CVEs. Only what's in the database."
    },
    {
        "id": "09_closing",
        "text": "AI-VAPT AGENT brings together conversational AI, strict scope governance, multi-tool correlation, transparent risk prioritization, human oversight, and professional reporting — all in one platform. We built this to show that intelligent cybersecurity doesn't mean autonomous and unchecked. It means smart, safe, transparent, and human-guided. Thank you so much for watching. The source code is on GitHub at github.com/NIDIA-21/AI-VAPT-AGENT — please do check it out."
    }
]

out_dir = r"C:\Users\nixon\AI-VAPT-AGENT\recordings\audio_segments"
os.makedirs(out_dir, exist_ok=True)

ffmpeg = r"C:\Users\nixon\CloudBill\node_modules\ffmpeg-static\ffmpeg.exe"

durations = {}

for seg in segments:
    mp3_file = os.path.join(out_dir, f"{seg['id']}.mp3")
    wav_file = os.path.join(out_dir, f"{seg['id']}.wav")
    print(f"Generating audio for {seg['id']}...")
    tts = gTTS(text=seg['text'], lang='en', tld='co.in', slow=False)
    tts.save(mp3_file)
    
    # Convert to WAV with standard sample rate
    cmd = f'"{ffmpeg}" -y -i "{mp3_file}" -ar 24000 -ac 1 "{wav_file}"'
    subprocess.run(cmd, shell=True, capture_output=True)
    
    # Measure duration
    dur_cmd = f'"{ffmpeg}" -i "{wav_file}" -f null -'
    res = subprocess.run(dur_cmd, shell=True, capture_output=True, text=True)
    dur = 20.0
    import re
    m = re.search(r"Duration: (\d+):(\d+):(\d+\.\d+)", res.stderr or res.stdout)
    if m:
        dur = float(m.group(1))*3600 + float(m.group(2))*60 + float(m.group(3))
    durations[seg['id']] = dur
    print(f"  -> {seg['id']}: {dur:.2f} seconds")

# Save durations to JSON
with open(os.path.join(out_dir, "durations.json"), "w") as f:
    json.dump(durations, f, indent=2)

print("\nAll audio segments generated successfully!")
print(f"Total voiceover duration: {sum(durations.values()):.2f} seconds ({sum(durations.values())/60:.2f} minutes)")
