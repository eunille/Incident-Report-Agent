# agent/timeline_agent.py
"""
Timeline Reconstruction Agent — LLM Step 1.

Sends the normalized IncidentSchema to Claude and receives a chronologically
ordered list of events with narrative descriptions.

GROUNDING CONSTRAINT: The agent is instructed to only assert facts that are
explicitly traceable to the source data. Uncertain items are flagged rather
than stated as facts. This is enforced in the system prompt and validated via
Pydantic before the output leaves this module.
"""

import json
import os
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, field_validator

from agent.llm_client import LLMClient, strip_json_fences
from schemas.incident_schema import IncidentSchema

# ── Output schema ─────────────────────────────────────────────────────────────


class RemediationTask(BaseModel):
    """A single remediation action item."""

    task: str                    # What needs to be done
    owner: str = "[UNASSIGNED]"  # Team or role responsible
    priority: str = "MEDIUM"     # CRITICAL / HIGH / MEDIUM / LOW
    due_date: Optional[str] = None  # ISO date or relative ("7 days")


class TimelineEvent(BaseModel):
    """A single verified event in the reconstructed attack timeline."""

    event_id: str  # e.g. "EVT-001"
    timestamp: Optional[str] = None  # ISO string or "[TIMESTAMP UNKNOWN]"
    description: str  # narrative description of the event
    source_ref: str  # which raw_event(s) this claim comes from
    uncertain: bool = False  # True = flagged for analyst review
    mitre_techniques: list[str] = []  # e.g. ["T1078 - Valid Accounts"]

    @field_validator("timestamp", mode="before")
    @classmethod
    def _normalize_ts(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return "[TIMESTAMP UNKNOWN]"
        return v.strip() or "[TIMESTAMP UNKNOWN]"


class TimelineResult(BaseModel):
    """Full output of the timeline reconstruction agent."""

    events: list[TimelineEvent]
    executive_summary: str  # 3–5 sentence plain-English overview
    affected_assets: list[str]  # hosts, IPs, user accounts, data stores
    ioc_list: list[str]  # IPs, domains, file hashes, file paths
    containment_actions: list[str]  # actions taken, by whom, at what time
    root_cause: str
    lessons_learned: list[str]
    # ── Industry enhancements ───────────────────────────────────────────────
    severity: str = "UNKNOWN"  # CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
    mitre_techniques: list[str] = []  # top-level ATT&CK IDs e.g. "T1486 - Data Encrypted"
    detection_time_minutes: Optional[int] = None  # first event → first detection alert
    containment_time_minutes: Optional[int] = None  # detection → containment complete
    remediation_tasks: list[RemediationTask] = []  # actionable task list


# ── Prompts ───────────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """You are a senior security incident analyst.
Your task is to reconstruct the attack timeline and extract structured intelligence
from the provided incident data.

STRICT RULES — these are non-negotiable:
1. Only include events that are explicitly present in the source data.
2. If a timestamp is missing or ambiguous, use "[TIMESTAMP UNKNOWN]" — do not infer.
3. Do not connect events causally unless the source data explicitly supports it.
4. If you are uncertain about any detail, set "uncertain": true on that event — do NOT state uncertain things as facts.
5. Do not invent IOCs, IPs, hostnames, or usernames that are not in the source data.
6. Your output will be used in a regulatory compliance report. Accuracy is non-negotiable.
7. Every event must include a "source_ref" tracing it back to the original source text.

OUTPUT FORMAT:
Return a single JSON object matching this exact schema (no markdown fences, raw JSON only):
{
  "events": [
    {
      "event_id": "EVT-001",
      "timestamp": "<ISO timestamp or [TIMESTAMP UNKNOWN]>",
      "description": "<concise factual description>",
      "source_ref": "<exact quote or line from source data>",
      "uncertain": false,
      "mitre_techniques": ["T1078 - Valid Accounts"]
    }
  ],
  "executive_summary": "<3-5 sentence plain English overview for CISO>",
  "affected_assets": ["<host/IP/user/datastore>"],
  "ioc_list": ["<IP>", "<domain>", "<SHA256>", "<file path>"],
  "containment_actions": ["<action taken, by whom, timestamp if known>"],
  "root_cause": "<what allowed the incident to occur — only if supported by data>",
  "lessons_learned": ["<specific, actionable recommendation>"],
  "severity": "<CRITICAL|HIGH|MEDIUM|LOW — overall incident severity>",
  "mitre_techniques": ["T1078 - Valid Accounts", "T1486 - Data Encrypted for Impact"],
  "detection_time_minutes": <integer minutes between first event timestamp and last event timestamp, or null if fewer than 2 timestamps>,
  "containment_time_minutes": <integer — estimate based on span of events, or null>,
  "remediation_tasks": [
    {
      "task": "<specific remediation action>",
      "owner": "<team or role e.g. Endpoint Security, IT Ops>",
      "priority": "<CRITICAL|HIGH|MEDIUM|LOW>",
      "due_date": "<relative e.g. 1 day, 7 days, 30 days>"
    }
  ]
}

MITRE ATT&CK RULES (CRITICAL):
- EVERY event in the events array MUST have a "mitre_techniques" field — even if it is an empty list [].
- Tag each event with the most specific applicable ATT&CK technique(s) based on what it describes.
- Common mappings: successful login → T1078; scheduled task → T1053.005; file drop → T1105 or T1204; shadow copy deletion → T1490; mass file rename/encryption → T1486; lateral movement → T1021.
- Also populate the top-level "mitre_techniques" as a deduplicated union of all per-event techniques.

For severity: CRITICAL = data exfiltration/destruction/ransomware, HIGH = confirmed compromise, MEDIUM = suspected compromise, LOW = probe/scan.
For SLA timing: Use the first and last timestamps in the event list to compute detection_time_minutes. Set containment_time_minutes to the same value if no explicit containment timestamp is available.
For remediation tasks: Generate 3-6 specific, actionable tasks with clear owners and relative due dates (e.g., "1 day", "7 days")."""


def _build_user_message(schema: IncidentSchema) -> str:
    """Serialise the IncidentSchema into a prompt-safe string."""
    parts: list[str] = ["# INCIDENT SOURCE DATA\n"]

    parts.append(f"Input source: {schema.input_source}")
    parts.append(f"Total raw events: {len(schema.events)}\n")

    parts.append("## Raw Events\n")
    for i, event in enumerate(schema.events, start=1):
        ts = event.timestamp.isoformat() if event.timestamp else "[TIMESTAMP UNKNOWN]"
        parts.append(f"### Event {i}")
        parts.append(f"Timestamp: {ts}")
        parts.append(f"Source: {event.source}")
        parts.append(f"Description: {event.description}")
        parts.append(f"Raw text:\n{event.raw_text}\n")

    if schema.analyst_notes:
        parts.append("## Analyst Notes\n")
        parts.append(schema.analyst_notes)

    return "\n".join(parts)


# ── Agent ─────────────────────────────────────────────────────────────────────


class TimelineAgent:
    """
    Wraps the LLM call for timeline reconstruction.

    Supports Groq, Gemini, and Claude via LLMClient.
    Provider is selected from environment (see agent/llm_client.py).

    Usage:
        agent = TimelineAgent()
        result = agent.run(incident_schema)
    """

    MAX_TOKENS = 4096

    def __init__(self, client: Optional[LLMClient] = None) -> None:
        self._client = client or LLMClient.from_env()

    def run(self, schema: IncidentSchema) -> TimelineResult:
        """
        Reconstruct the attack timeline from the normalised incident schema.

        Args:
            schema: Normalised IncidentSchema from parser.parse().

        Returns:
            TimelineResult with ordered events and extracted intelligence.

        Raises:
            ValueError: If the LLM returns malformed JSON or fails schema validation.
            anthropic.APIError: On API communication failure.
        """
        user_message = _build_user_message(schema)

        raw_text = self._client.complete(
            _SYSTEM_PROMPT,
            user_message,
            max_tokens=self.MAX_TOKENS,
        )
        raw_text = strip_json_fences(raw_text)

        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Timeline agent returned invalid JSON.\n"
                f"Raw response (first 500 chars): {raw_text[:500]}\n"
                f"JSON error: {exc}"
            ) from exc

        try:
            result = TimelineResult(**data)
        except Exception as exc:
            raise ValueError(
                f"Timeline agent output failed schema validation: {exc}\n"
                f"Data received: {json.dumps(data, indent=2)[:1000]}"
            ) from exc

        result = _enrich_mitre(result)
        return result


# ── MITRE enrichment fallback ──────────────────────────────────────────────────

_MITRE_KEYWORDS: list[tuple[list[str], str]] = [
    (["scheduled task", "schtask", "currentversion\\run", "at.exe"], "T1053.005 - Scheduled Task"),
    (["valid account", "authentication succeeded", "login success", "logon success"], "T1078 - Valid Accounts"),
    (["file drop", "file created", "file written", "dropped file", "download"], "T1105 - Ingress Tool Transfer"),
    (["shadow copy", "vssadmin", "vss delete"], "T1490 - Inhibit System Recovery"),
    (["file rename", ".locked", ".encrypt", "ransomware", "mass rename"], "T1486 - Data Encrypted for Impact"),
    (["powershell", "ps1", "invoke-expression", "iex "], "T1059.001 - PowerShell"),
    (["cmd.exe", "command prompt", "command line"], "T1059.003 - Windows Command Shell"),
    (["mimikatz", "lsass", "credential dump", "sekurlsa"], "T1003.001 - LSASS Memory"),
    (["net user", "net localgroup", "useradd", "new user"], "T1136 - Create Account"),
    (["lateral movement", "psexec", "wmiexec", "remote exec"], "T1021 - Remote Services"),
    (["phishing", "spear-phish", "malicious email", "macro", "attachment"], "T1566 - Phishing"),
    (["c2", "command and control", "beacon", "callback", "outbound connection"], "T1071 - Application Layer Protocol"),
    (["data exfil", "large upload", "outbound transfer", "exfiltrat"], "T1041 - Exfiltration Over C2 Channel"),
    (["registry", "hklm", "hkcu", "reg add", "regedit"], "T1547.001 - Registry Run Keys"),
    (["dll", "inject", "process hollow", "reflective"], "T1055 - Process Injection"),
    (["usb", "removable media", "external drive"], "T1091 - Replication Through Removable Media"),
    (["rdp", "remote desktop", "3389"], "T1021.001 - Remote Desktop Protocol"),
    (["privilege escalat", "uac bypass", "token impersonat"], "T1548 - Abuse Elevation Control Mechanism"),
    (["nmap", "port scan", "discovery", "reconnaissance"], "T1046 - Network Service Discovery"),
    (["web shell", "webshell", "aspx upload", "php upload"], "T1505.003 - Web Shell"),
]


def _enrich_mitre(result: TimelineResult) -> TimelineResult:
    """
    Fallback: tag any event whose mitre_techniques list is empty
    by matching keywords in the event description.
    Also syncs top-level mitre_techniques with per-event tags.
    """
    all_techniques: set[str] = set(result.mitre_techniques)

    enriched_events: list[TimelineEvent] = []
    for event in result.events:
        if not event.mitre_techniques:
            desc_lower = event.description.lower()
            inferred: list[str] = []
            for keywords, technique in _MITRE_KEYWORDS:
                if any(kw in desc_lower for kw in keywords):
                    inferred.append(technique)
            if inferred:
                event = event.model_copy(update={"mitre_techniques": inferred})
                all_techniques.update(inferred)
        else:
            all_techniques.update(event.mitre_techniques)
        enriched_events.append(event)

    return result.model_copy(update={
        "events": enriched_events,
        "mitre_techniques": sorted(all_techniques),
    })
