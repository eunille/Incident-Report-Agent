# agent/grounding_verifier.py
"""
Grounding Verifier — LLM Step 2 (hallucination guard).

Takes the TimelineResult from the timeline agent and checks every claim
against the original source data. Claims marked UNSUPPORTED are removed.
Claims marked UNCERTAIN are kept but flagged for analyst review.

This pass is NOT optional. No agent output reaches the report renderer
without passing through this module.
"""

import json
import os
from enum import Enum
from typing import Optional

from pydantic import BaseModel

from agent.llm_client import LLMClient, strip_json_fences
from agent.timeline_agent import RemediationTask, TimelineEvent, TimelineResult
from schemas.incident_schema import IncidentSchema

# ── Verification status ────────────────────────────────────────────────────────


class VerificationStatus(str, Enum):
    VERIFIED = "VERIFIED"
    UNCERTAIN = "UNCERTAIN"
    UNSUPPORTED = "UNSUPPORTED"


class ClaimVerification(BaseModel):
    """Verification result for a single claim or event."""

    claim_id: str  # matches TimelineEvent.event_id or a field name
    status: VerificationStatus
    evidence: Optional[str] = None  # quote from source data supporting VERIFIED
    reviewer_note: Optional[str] = None  # explanation for UNCERTAIN/UNSUPPORTED


class VerificationReport(BaseModel):
    """Full output of the grounding verifier pass."""

    event_verifications: list[ClaimVerification]
    executive_summary_status: VerificationStatus
    root_cause_status: VerificationStatus
    ioc_verifications: list[ClaimVerification]
    reviewer_note: Optional[str] = None  # overall notes from the verifier


class GroundedResult(BaseModel):
    """
    TimelineResult after the grounding pass.

    UNSUPPORTED claims are removed. UNCERTAIN claims have uncertain=True.
    This is the only object that reaches the report renderer.
    """

    events: list[TimelineEvent]
    executive_summary: str
    affected_assets: list[str]
    ioc_list: list[str]
    containment_actions: list[str]
    root_cause: str
    lessons_learned: list[str]
    unsupported_removed: int  # count of claims stripped by the verifier
    uncertain_count: int  # count of claims flagged for analyst review
    # ── Industry enhancements ──────────────────────────────────────────────
    severity: str = "UNKNOWN"
    mitre_techniques: list[str] = []
    detection_time_minutes: Optional[int] = None
    containment_time_minutes: Optional[int] = None
    remediation_tasks: list[RemediationTask] = []


# ── Prompts ────────────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """You are a forensic fact-checker reviewing a security incident report draft.

Your job is to verify every claim in the DRAFT REPORT against the SOURCE DATA.

For each timeline event, output one of:
- VERIFIED   — the claim is explicitly and directly supported by the source data (include the supporting quote)
- UNCERTAIN  — the claim is partially supported or inferential (explain what is uncertain)
- UNSUPPORTED — the claim is not found in the source data or contradicts it (these will be removed)

RULES:
1. Do not rewrite any claim. Only classify it.
2. A claim is VERIFIED only if the exact detail (timestamp, IP, hostname, action) appears in the source.
3. Inferred causality, assumed context, or plausible-but-unverified details = UNCERTAIN at best.
4. If a timestamp is stated but not in the source = UNSUPPORTED.
5. IOCs (IPs, hashes, domains, paths) must appear verbatim in the source to be VERIFIED.
6. The executive_summary and root_cause are VERIFIED only if every sentence traces to source data.

OUTPUT FORMAT:
Return a single JSON object (no markdown fences, raw JSON only):
{
  "event_verifications": [
    {
      "claim_id": "EVT-001",
      "status": "VERIFIED" | "UNCERTAIN" | "UNSUPPORTED",
      "evidence": "<exact quote from source, or null>",
      "reviewer_note": "<explanation if UNCERTAIN or UNSUPPORTED, or null>"
    }
  ],
  "executive_summary_status": "VERIFIED" | "UNCERTAIN" | "UNSUPPORTED",
  "root_cause_status": "VERIFIED" | "UNCERTAIN" | "UNSUPPORTED",
  "ioc_verifications": [
    {
      "claim_id": "<ioc value>",
      "status": "VERIFIED" | "UNCERTAIN" | "UNSUPPORTED",
      "evidence": "<exact quote from source, or null>",
      "reviewer_note": null
    }
  ],
  "reviewer_note": "<optional overall note>"
}"""


def _build_verifier_message(
    schema: IncidentSchema, timeline: TimelineResult
) -> str:
    """Construct the verifier prompt combining source data and draft report."""
    parts: list[str] = []

    # ── Source data ──
    parts.append("# SOURCE DATA (ground truth)\n")
    for i, event in enumerate(schema.events, start=1):
        ts = event.timestamp.isoformat() if event.timestamp else "[TIMESTAMP UNKNOWN]"
        parts.append(f"[Source {i}] {ts} | {event.source}\n{event.raw_text}\n")

    if schema.analyst_notes:
        parts.append(f"[Analyst Notes]\n{schema.analyst_notes}\n")

    # ── Draft report ──
    parts.append("\n# DRAFT REPORT (to verify)\n")
    parts.append("## Timeline Events")
    for ev in timeline.events:
        parts.append(
            f"- {ev.event_id} | {ev.timestamp or '[TIMESTAMP UNKNOWN]'} | "
            f"{ev.description} [source_ref: {ev.source_ref}]"
        )

    parts.append("\n## Executive Summary")
    parts.append(timeline.executive_summary)

    parts.append("\n## Root Cause")
    parts.append(timeline.root_cause)

    parts.append("\n## IOC List")
    for ioc in timeline.ioc_list:
        parts.append(f"- {ioc}")

    return "\n".join(parts)


# ── Apply verification results ─────────────────────────────────────────────────


def _apply_verification(
    timeline: TimelineResult, report: VerificationReport
) -> GroundedResult:
    """
    Apply the verifier's decisions to the timeline result.

    - UNSUPPORTED events are removed.
    - UNCERTAIN events have uncertain=True.
    - Executive summary and root cause are cleared if UNSUPPORTED.
    """
    status_map: dict[str, VerificationStatus] = {
        v.claim_id: v.status for v in report.event_verifications
    }
    ioc_status_map: dict[str, VerificationStatus] = {
        v.claim_id: v.status for v in report.ioc_verifications
    }

    # Filter and annotate events
    grounded_events: list[TimelineEvent] = []
    removed = 0

    for event in timeline.events:
        verdict = status_map.get(event.event_id, VerificationStatus.UNCERTAIN)
        if verdict == VerificationStatus.UNSUPPORTED:
            removed += 1
            continue  # strip from output
        updated = event.model_copy(
            update={"uncertain": verdict == VerificationStatus.UNCERTAIN}
        )
        grounded_events.append(updated)

    # Filter IOCs
    verified_iocs = [
        ioc
        for ioc in timeline.ioc_list
        if ioc_status_map.get(ioc, VerificationStatus.UNCERTAIN)
        != VerificationStatus.UNSUPPORTED
    ]

    # Guard executive summary and root cause
    exec_summary = (
        timeline.executive_summary
        if report.executive_summary_status != VerificationStatus.UNSUPPORTED
        else "[Executive summary could not be verified — analyst review required]"
    )
    root_cause = (
        timeline.root_cause
        if report.root_cause_status != VerificationStatus.UNSUPPORTED
        else "[Root cause could not be verified — analyst review required]"
    )

    uncertain_count = sum(1 for e in grounded_events if e.uncertain)

    return GroundedResult(
        events=grounded_events,
        executive_summary=exec_summary,
        affected_assets=timeline.affected_assets,
        ioc_list=verified_iocs,
        containment_actions=timeline.containment_actions,
        root_cause=root_cause,
        lessons_learned=timeline.lessons_learned,
        unsupported_removed=removed,
        uncertain_count=uncertain_count,
        severity=timeline.severity,
        mitre_techniques=timeline.mitre_techniques,
        detection_time_minutes=timeline.detection_time_minutes,
        containment_time_minutes=timeline.containment_time_minutes,
        remediation_tasks=timeline.remediation_tasks,
    )


# ── Public class ───────────────────────────────────────────────────────────────


class GroundingVerifier:
    """
    Runs the grounding verification pass (LLM Step 2).

    Supports Groq, Gemini, and Claude via LLMClient.
    Provider is selected from environment (see agent/llm_client.py).

    Usage:
        verifier = GroundingVerifier()
        grounded = verifier.run(incident_schema, timeline_result)
    """

    MAX_TOKENS = 4096

    def __init__(self, client: Optional[LLMClient] = None) -> None:
        self._client = client or LLMClient.from_env()

    def run(self, schema: IncidentSchema, timeline: TimelineResult) -> GroundedResult:
        """
        Verify all timeline claims against the source data.

        Args:
            schema: The original normalised IncidentSchema (source of truth).
            timeline: Output from TimelineAgent.run().

        Returns:
            GroundedResult — verified claims only, uncertain items flagged.

        Raises:
            ValueError: If the LLM returns malformed JSON or fails schema validation.
            anthropic.APIError: On API communication failure.
        """
        message = _build_verifier_message(schema, timeline)

        raw_text = self._client.complete(
            _SYSTEM_PROMPT,
            message,
            max_tokens=self.MAX_TOKENS,
        )
        raw_text = strip_json_fences(raw_text)

        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Grounding verifier returned invalid JSON.\n"
                f"Raw response (first 500 chars): {raw_text[:500]}\n"
                f"JSON error: {exc}"
            ) from exc

        try:
            verification_report = VerificationReport(**data)
        except Exception as exc:
            raise ValueError(
                f"Grounding verifier output failed schema validation: {exc}\n"
                f"Data received: {json.dumps(data, indent=2)[:1000]}"
            ) from exc

        return _apply_verification(timeline, verification_report)
