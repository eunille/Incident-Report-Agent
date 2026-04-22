# Incident Report Writer

**AI-powered post-incident report generator for cybersecurity teams.**  
Converts raw SIEM alerts, log files, or analyst notes into a structured, NIST-compliant incident report — in seconds.

---

## What It Does

Writing a post-incident report after a security breach typically takes an analyst **2–4 hours**. They have to sift through raw logs, reconstruct the attack timeline, identify IOCs, map techniques to MITRE ATT&CK, estimate response times, and format everything into a readable document.

**Incident Report Writer automates all of that.**

You paste in raw data. The system runs it through a two-pass AI pipeline and outputs a complete, professional report — with MITRE ATT&CK tagging, severity scoring, SLA timing, IOC extraction, remediation tasks, and PDF export.

---

## What Problem It Solves

| Without this tool | With this tool |
|---|---|
| 2–4 hours of manual writing | Report ready in ~30 seconds |
| Inconsistent formatting across analysts | Standardized NIST SP 800-61r2 structure every time |
| Easy to forget MITRE mapping or SLA metrics | Automatically populated |
| Hallucinated or unsupported claims slip through | Grounding verification removes them |
| No audit trail of what was and wasn't evidence-backed | [UNCERTAIN] flags mark low-confidence items |

**Target users:** SOC analysts, incident responders, security managers, MSSP teams.

---

## Features

- **Auto-detects input format** — paste Splunk/Sentinel JSON exports, raw syslog lines, or free-text analyst notes. No manual formatting required.
- **Two-pass LLM pipeline** — Pass 1 reconstructs the attack timeline. Pass 2 verifies every claim against the source data and removes hallucinations.
- **MITRE ATT&CK tagging** — Every event in the timeline is tagged with relevant technique IDs (e.g. `T1078 - Valid Accounts`, `T1486 - Ransomware`). Falls back to keyword matching if the LLM misses any.
- **Severity scoring** — CRITICAL / HIGH / MEDIUM / LOW based on impact analysis.
- **SLA timing** — Detection time and containment time calculated from event timestamps.
- **IOC extraction** — IP addresses, file hashes, domains, and usernames pulled from the data.
- **Remediation task table** — Structured table of recommended actions with owner and priority.
- **Grounding verification** — Claims not supported by evidence are either flagged `[UNCERTAIN]` or removed entirely.
- **PDF + Markdown export** — Download the report in either format.
- **Free LLM providers** — Uses Groq (primary) and Gemini (automatic fallback). No paid API required.
- **Pipeline stepper UI** — Visual progress tracker shows each stage: Parse → Timeline → Grounding → Render.

---

## Report Structure

Every generated report follows **NIST SP 800-61r2** (Computer Security Incident Handling Guide):

```
1. Header         — Incident ID, analyst, classification, severity, date
2. Executive Summary
3. Attack Timeline — Chronological table with MITRE ATT&CK column
4. IOC List        — IPs, hashes, domains, usernames
5. Root Cause Analysis
6. Impact Assessment
7. Response Actions Taken
8. Remediation Tasks — Structured table: task / owner / priority / due date
9. Lessons Learned
10. Recommendations
```

---

## Services Used

| Service | Purpose | Cost |
|---|---|---|
| **Groq API** | Primary LLM — `llama-3.3-70b-versatile` | Free (100k tokens/day) |
| **Google Gemini API** | Fallback LLM — `gemini-2.0-flash` | Free (generous quota) |
| **Streamlit** | Web UI framework | Free / open source |
| **Pydantic v2** | Schema validation at every pipeline stage | Open source |
| **Jinja2** | Report template engine | Open source |
| **WeasyPrint** | PDF generation from HTML | Open source |
| **MITRE ATT&CK** | Threat technique taxonomy | Free / public |

---

## How It Works — Pipeline Flow

```
User Input (paste / upload)
        │
        ▼
┌─────────────────────────────────┐
│  Step 1: Parse & Normalize      │  Auto-detects JSON / logfile / freetext
│  agent/parser.py                │  Extracts events, timestamps, sources
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│  Step 2: Timeline Agent (LLM 1) │  Groq llama-3.3-70b (or Gemini fallback)
│  agent/timeline_agent.py        │  Reconstructs chronological attack timeline
│                                 │  Tags MITRE ATT&CK techniques per event
│                                 │  Calculates severity, SLA, remediation tasks
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│  Step 3: Grounding Verifier     │  LLM 2 — hallucination guard
│  agent/grounding_verifier.py    │  Checks every claim against source evidence
│                                 │  Flags [UNCERTAIN] or removes unsupported claims
│                                 │  Extracts and classifies IOCs
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│  Step 4: Report Generator       │  Jinja2 template → Markdown
│  agent/report_generator.py      │  WeasyPrint → PDF
│  templates/incident_report.j2   │  NIST SP 800-61r2 structure
└────────────────┬────────────────┘
                 │
                 ▼
        Download .md or .pdf
```

---

## Setup

### Requirements

- Python 3.11+
- A free [Groq API key](https://console.groq.com) (takes 1 minute to create)
- Optionally: a [Gemini API key](https://aistudio.google.com/apikey) for fallback

### Installation

```bash
# Clone the project
git clone <repo-url>
cd incident-report-writer

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Configuration

Create a `.env` file in the project root:

```env
LLM_PROVIDER=groq
GROQ_API_KEY=your_groq_api_key_here

# Optional — used as automatic fallback if Groq rate-limits
GEMINI_API_KEY=your_gemini_api_key_here
```

### Run

```bash
streamlit run ui/app.py
```

Open [http://localhost:8501](http://localhost:8501) in your browser.

---

## Demo Walkthrough

### Test Case 1 — Ransomware Attack

Paste this into the **Incident Data** field:

```
2024-01-15T08:30:00 Authentication succeeded for user jsmith from 185.220.101.45
2024-01-15T08:32:14 Scheduled task created: HKLM\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate by jsmith
2024-01-15T08:35:01 File dropped: C:\Windows\Temp\svchost32.exe (SHA256: d41d8cd98f00b204e9800998ecf8427e)
2024-01-15T08:36:45 Volume shadow copy deletion: vssadmin delete shadows /all /quiet by SYSTEM
2024-01-15T08:40:00 Mass file rename: 1,247 files renamed .locked on \\fileserver01\Finance
```

**Expected output:** CRITICAL severity · MITRE T1078, T1053.005, T1490, T1486 · ~10 min SLA

---

### Test Case 2 — Phishing + C2

```
2024-02-10T09:15:00 Email received from attacker@malicious-domain.ru — subject "Invoice Q1-2024" — attachment Invoice.xlsm
2024-02-10T09:22:31 User jdoe opened Invoice.xlsm — macro execution detected by AV
2024-02-10T09:22:45 Outbound connection from WKSTN-042 to 192.168.99.5:4444
2024-02-10T09:30:00 LDAP query executed from WKSTN-042 — enumerating domain users
2024-02-10T09:45:00 RDP connection from WKSTN-042 to DC01 using domain admin credentials
```

**Expected output:** HIGH severity · MITRE T1566, T1059, T1071, T1021.001

---

### Test Case 3 — Insider Threat

```
Security alert triggered at 14:30. Employee Martinez in Finance was observed inserting a USB drive into FINSRV-003 shortly before submitting resignation. DLP logs show 847MB transferred to external device between 14:28 and 14:44. Files involved appear to be Q4 financial reports. Badge access logs show Martinez badged into the server room at 14:25 — unauthorized area.
```

**Expected output:** MEDIUM-HIGH severity · T1052 (USB exfil) · T1078 · access revocation tasks

---

## Project Structure

```
incident-report-writer/
├── agent/
│   ├── llm_client.py          # Provider-agnostic LLM abstraction (Groq / Gemini / Claude)
│   ├── parser.py              # Input parser — auto-detects JSON, logfile, freetext
│   ├── timeline_agent.py      # LLM step 1 — attack timeline reconstruction
│   ├── grounding_verifier.py  # LLM step 2 — hallucination guard
│   └── report_generator.py    # Jinja2 + WeasyPrint report renderer
├── schemas/
│   └── incident_schema.py     # Pydantic v2 data models
├── templates/
│   └── incident_report.md.j2  # Jinja2 report template (NIST structure)
├── tests/
│   └── test_pipeline.py       # 63 unit + integration tests
├── ui/
│   └── app.py                 # Streamlit web UI
├── .env                       # API keys (not committed)
├── requirements.txt
└── README.md
```

---

## Running Tests

```bash
source .venv/bin/activate
pytest tests/ -v
```

63 tests pass. 1 test is skipped (WeasyPrint PDF — requires system fonts, works in the app).

---

## Rate Limits & Fallback

- **Groq free tier:** 100,000 tokens/day. Resets at midnight UTC.
- **Automatic fallback:** If Groq returns a rate-limit error, the system silently retries the same request using Gemini. No manual intervention needed.
- **Gemini free tier:** ~1,500 requests/day, 1M tokens/minute. More than enough for testing.

---

## Security Notes

- API keys are stored in `.env` (never committed — add `.env` to `.gitignore`).
- All LLM outputs are validated against Pydantic schemas before use.
- The grounding verifier acts as a second defense layer against hallucinated IOCs or unsupported claims entering the final report.
- Reports are classified by default as `CONFIDENTIAL`. Adjust in the UI settings.

---

