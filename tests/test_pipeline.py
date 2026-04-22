# tests/test_pipeline.py
"""
Phase 7 — Full test suite for the Incident Report Writer pipeline.

Covers:
  - agent/parser.py          (parse, auto-detection, timestamp extraction)
  - agent/llm_client.py      (provider auto-detection, missing-key error)
  - agent/timeline_agent.py  (prompt building, JSON parsing, Pydantic validation)
  - agent/grounding_verifier (VERIFIED/UNCERTAIN/UNSUPPORTED filtering)
  - agent/report_generator   (Jinja2 rendering, IOC type classification)
  - End-to-end pipeline      (mocked LLM, 3 fixture files)

All LLM calls are replaced with unittest.mock.Mock objects — no API key required.
"""

import json
import os
import sys
import textwrap
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ── Path setup ────────────────────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from agent.grounding_verifier import (
    ClaimVerification,
    GroundedResult,
    GroundingVerifier,
    VerificationReport,
    VerificationStatus,
)
from agent.llm_client import LLMClient, _auto_detect_provider, strip_json_fences
from agent.parser import _extract_timestamp, _parse_timestamp, parse
from agent.report_generator import ReportGenerator, _ioc_type
from agent.timeline_agent import TimelineAgent, TimelineEvent, TimelineResult
from schemas.incident_schema import IncidentSchema, RawEvent

# ── Fixtures & helpers ────────────────────────────────────────────────────────

_FIXTURES = Path(__file__).parent / "sample_inputs"


def _make_timeline_result(**overrides) -> TimelineResult:
    defaults = dict(
        events=[
            TimelineEvent(
                event_id="EVT-001",
                timestamp="2024-01-15T08:30:00",
                description="Attacker logged in via SSH from 10.0.0.5",
                source_ref="event[0]",
                uncertain=False,
            )
        ],
        executive_summary="A single SSH intrusion event was detected.",
        affected_assets=["server01", "10.0.0.5"],
        ioc_list=["10.0.0.5", "malware.exe"],
        containment_actions=["Account disabled at 08:45"],
        root_cause="Weak password policy",
        lessons_learned=["Enforce MFA on all SSH access"],
    )
    defaults.update(overrides)
    return TimelineResult(**defaults)


def _make_grounded_result(**overrides) -> GroundedResult:
    tr = _make_timeline_result()
    defaults = dict(
        events=tr.events,
        executive_summary=tr.executive_summary,
        affected_assets=tr.affected_assets,
        ioc_list=tr.ioc_list,
        containment_actions=tr.containment_actions,
        root_cause=tr.root_cause,
        lessons_learned=tr.lessons_learned,
        unsupported_removed=0,
        uncertain_count=0,
    )
    defaults.update(overrides)
    return GroundedResult(**defaults)


def _make_mock_llm_client(json_response: str) -> MagicMock:
    """Return a mock LLMClient whose .complete() always returns json_response."""
    mock = MagicMock(spec=LLMClient)
    mock.complete.return_value = json_response
    return mock


# ═══════════════════════════════════════════════════════════════════════════════
# 1. PARSER TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestTimestampExtraction:
    def test_iso8601_basic(self):
        dt = _extract_timestamp("2024-01-15T08:30:00")
        assert dt is not None
        assert dt.year == 2024 and dt.month == 1 and dt.day == 15

    def test_iso8601_with_space_separator(self):
        dt = _extract_timestamp("2024-01-15 08:30:00 INFO login succeeded")
        assert dt is not None
        assert dt.hour == 8

    def test_us_date_format(self):
        dt = _extract_timestamp("Alert triggered at 04/22/2026 14:32:01")
        assert dt is not None
        assert dt.month == 4

    def test_syslog_format(self):
        dt = _extract_timestamp("Apr 22 14:32:01 hostname sshd[12345]: Accepted")
        assert dt is not None

    def test_no_timestamp_returns_none(self):
        assert _extract_timestamp("No timestamp here at all") is None

    def test_iso8601_fractional_seconds(self):
        dt = _extract_timestamp("2024-03-10T12:00:00.123456")
        assert dt is not None
        assert dt.second == 0


class TestParseAutoDetection:
    def test_detects_json_dict(self):
        payload = json.dumps({"timestamp": "2024-01-15T08:00:00", "message": "test event"})
        result = parse(payload)
        assert result.input_source == "json"

    def test_detects_json_list(self):
        payload = json.dumps([{"timestamp": "2024-01-15T08:00:00", "message": "ev1"}])
        result = parse(payload)
        assert result.input_source == "json"

    def test_detects_logfile_by_timestamp_prefix(self):
        log = "2024-01-15T08:00:00 INFO login succeeded for user admin from 10.0.0.1"
        result = parse(log)
        assert result.input_source == "logfile"

    def test_detects_paste_for_free_text(self):
        text = "The attacker gained access to the finance server and exfiltrated data."
        result = parse(text)
        assert result.input_source == "paste"

    def test_force_source_overrides_detection(self):
        log = "2024-01-15T08:00:00 INFO something happened"
        result = parse(log, force_source="paste")
        assert result.input_source == "paste"


class TestParseSplunkJson:
    def test_splunk_results_wrapper(self):
        data = {
            "results": [
                {"_time": "2024-01-15T08:00:00", "_raw": "user=admin action=login"},
                {"_time": "2024-01-15T08:05:00", "_raw": "user=admin action=upload"},
            ]
        }
        result = parse(json.dumps(data))
        assert result.input_source == "json"
        assert len(result.events) == 2

    def test_sentinel_value_wrapper(self):
        data = {
            "value": [
                {"properties": {"createdTimeUtc": "2024-01-15T08:00:00Z", "description": "Brute force"}}
            ]
        }
        result = parse(json.dumps(data))
        assert result.input_source == "json"
        assert len(result.events) >= 1

    def test_generic_event_list(self):
        data = [
            {"timestamp": "2024-01-15T08:00:00", "message": "Event A"},
            {"timestamp": "2024-01-15T08:01:00", "message": "Event B"},
        ]
        result = parse(json.dumps(data))
        assert len(result.events) == 2

    def test_single_event_dict_wrapped_in_list(self):
        data = {"timestamp": "2024-01-15T08:00:00", "message": "Single event"}
        result = parse(json.dumps(data))
        assert len(result.events) >= 1


class TestParseAnalystNotes:
    def test_analyst_notes_attached(self):
        result = parse("2024-01-15T08:00:00 login attempt", analyst_notes="Suspicious country")
        assert result.analyst_notes == "Suspicious country"

    def test_no_analyst_notes_is_none(self):
        result = parse("2024-01-15T08:00:00 login attempt")
        assert result.analyst_notes is None

    def test_empty_analyst_notes_treated_as_none(self):
        result = parse("2024-01-15T08:00:00 login attempt", analyst_notes="")
        assert not result.analyst_notes


class TestParseEdgeCases:
    def test_multiline_paste_groups_by_blank_line(self):
        text = textwrap.dedent("""\
            2024-01-15T08:00:00 login succeeded

            2024-01-15T08:05:00 file transfer started
        """)
        result = parse(text)
        assert result.input_source in ("logfile", "paste")
        assert len(result.events) >= 1

    def test_invalid_json_falls_back_to_paste(self):
        # Looks like it starts with { but is invalid JSON
        result = parse("{not valid json")
        # Should not raise; should produce something usable
        assert result.input_source in ("paste", "logfile")
        assert len(result.events) >= 1

    def test_empty_input_returns_schema(self):
        # Very minimal input — parser should not crash
        result = parse("   ")
        assert isinstance(result, IncidentSchema)

    def test_schema_validation_rejects_bad_source(self):
        with pytest.raises(Exception):
            IncidentSchema(events=[], input_source="invalid_source")


# ═══════════════════════════════════════════════════════════════════════════════
# 2. LLM CLIENT TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestStripJsonFences:
    def test_removes_markdown_code_fence(self):
        raw = "```json\n{\"key\": \"value\"}\n```"
        assert strip_json_fences(raw) == '{"key": "value"}'

    def test_removes_plain_code_fence(self):
        raw = "```\n{\"key\": 1}\n```"
        assert strip_json_fences(raw) == '{"key": 1}'

    def test_passthrough_when_no_fence(self):
        raw = '{"key": "value"}'
        assert strip_json_fences(raw) == raw

    def test_strips_surrounding_whitespace(self):
        raw = "  \n  {\"a\": 1}  \n  "
        assert strip_json_fences(raw).strip() == '{"a": 1}'


class TestAutoDetectProvider:
    def test_detects_groq_key(self, monkeypatch):
        monkeypatch.setenv("GROQ_API_KEY", "gsk_test")
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("LLM_PROVIDER", raising=False)
        assert _auto_detect_provider() == "groq"

    def test_detects_gemini_when_no_groq(self, monkeypatch):
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        monkeypatch.setenv("GEMINI_API_KEY", "gemini_test")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("LLM_PROVIDER", raising=False)
        assert _auto_detect_provider() == "gemini"

    def test_detects_claude_as_last_resort(self, monkeypatch):
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "ant_test")
        monkeypatch.delenv("LLM_PROVIDER", raising=False)
        assert _auto_detect_provider() == "claude"

    def test_returns_none_when_no_keys(self, monkeypatch):
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("LLM_PROVIDER", raising=False)
        assert _auto_detect_provider() is None

    def test_from_env_raises_when_no_provider(self, monkeypatch):
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("LLM_PROVIDER", raising=False)
        with pytest.raises(EnvironmentError):
            LLMClient.from_env()


# ═══════════════════════════════════════════════════════════════════════════════
# 3. TIMELINE AGENT TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestTimelineAgent:
    def _valid_response(self, **overrides) -> str:
        data = {
            "events": [
                {
                    "event_id": "EVT-001",
                    "timestamp": "2024-01-15T08:30:00",
                    "description": "SSH login from 10.0.0.5",
                    "source_ref": "event[0]",
                    "uncertain": False,
                    "mitre_techniques": ["T1078 - Valid Accounts"],
                }
            ],
            "executive_summary": "An SSH intrusion was detected.",
            "affected_assets": ["server01"],
            "ioc_list": ["10.0.0.5"],
            "containment_actions": ["Account locked"],
            "root_cause": "Weak credentials",
            "lessons_learned": ["Enable MFA"],
            "severity": "HIGH",
            "mitre_techniques": ["T1078 - Valid Accounts"],
            "detection_time_minutes": 5,
            "containment_time_minutes": 15,
            "remediation_tasks": [
                {"task": "Reset compromised account", "owner": "IT Ops", "priority": "HIGH", "due_date": "1 day"}
            ],
        }
        data.update(overrides)
        return json.dumps(data)

    def test_run_returns_timeline_result(self):
        mock_client = _make_mock_llm_client(self._valid_response())
        agent = TimelineAgent(client=mock_client)
        schema = parse("2024-01-15T08:30:00 ssh login from 10.0.0.5")
        result = agent.run(schema)
        assert isinstance(result, TimelineResult)
        assert len(result.events) == 1
        assert result.events[0].event_id == "EVT-001"

    def test_llm_called_once(self):
        mock_client = _make_mock_llm_client(self._valid_response())
        agent = TimelineAgent(client=mock_client)
        schema = parse("2024-01-15T08:30:00 event")
        agent.run(schema)
        assert mock_client.complete.call_count == 1

    def test_json_fences_in_response_handled(self):
        fenced = f"```json\n{self._valid_response()}\n```"
        mock_client = _make_mock_llm_client(fenced)
        agent = TimelineAgent(client=mock_client)
        schema = parse("2024-01-15T08:30:00 event")
        result = agent.run(schema)
        assert isinstance(result, TimelineResult)

    def test_invalid_json_raises_value_error(self):
        mock_client = _make_mock_llm_client("this is not valid JSON at all")
        agent = TimelineAgent(client=mock_client)
        schema = parse("2024-01-15T08:30:00 event")
        with pytest.raises((ValueError, json.JSONDecodeError, Exception)):
            agent.run(schema)

    def test_missing_required_field_raises(self):
        incomplete = json.dumps({"events": [], "executive_summary": "ok"})
        mock_client = _make_mock_llm_client(incomplete)
        agent = TimelineAgent(client=mock_client)
        schema = parse("2024-01-15T08:30:00 event")
        with pytest.raises(Exception):
            agent.run(schema)

    def test_uncertain_flag_preserved(self):
        response = self._valid_response(
            events=[{
                "event_id": "EVT-001",
                "timestamp": None,
                "description": "Possible lateral movement",
                "source_ref": "analyst note",
                "uncertain": True,
            }]
        )
        mock_client = _make_mock_llm_client(response)
        result = TimelineAgent(client=mock_client).run(
            parse("2024-01-15T08:30:00 suspicious activity")
        )
        assert result.events[0].uncertain is True

    def test_null_timestamp_becomes_placeholder(self):
        response = self._valid_response(
            events=[{
                "event_id": "EVT-001",
                "timestamp": None,
                "description": "Unknown timing event",
                "source_ref": "event[0]",
                "uncertain": False,
            }]
        )
        mock_client = _make_mock_llm_client(response)
        result = TimelineAgent(client=mock_client).run(
            parse("2024-01-15T08:30:00 unknown timing")
        )
        assert result.events[0].timestamp == "[TIMESTAMP UNKNOWN]"


# ═══════════════════════════════════════════════════════════════════════════════
# 4. GROUNDING VERIFIER TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestGroundingVerifier:
    def _schema(self) -> IncidentSchema:
        return parse("2024-01-15T08:30:00 ssh login from 10.0.0.5")

    def _timeline(self, n_events: int = 1) -> TimelineResult:
        events = [
            TimelineEvent(
                event_id=f"EVT-{i:03}",
                timestamp="2024-01-15T08:30:00",
                description=f"Event {i}",
                source_ref=f"event[{i-1}]",
            )
            for i in range(1, n_events + 1)
        ]
        return TimelineResult(
            events=events,
            executive_summary="Test summary.",
            affected_assets=["server01"],
            ioc_list=["10.0.0.5"],
            containment_actions=["Isolated host"],
            root_cause="Test root cause",
            lessons_learned=["Test lesson"],
        )

    def _verification_response(self, statuses: list[str]) -> str:
        verifications = [
            {"claim_id": f"EVT-{i+1:03}", "status": s, "evidence": "raw log line"}
            for i, s in enumerate(statuses)
        ]
        return json.dumps({
            "event_verifications": verifications,
            "executive_summary_status": "VERIFIED",
            "root_cause_status": "VERIFIED",
            "ioc_verifications": [
                {"claim_id": "10.0.0.5", "status": "VERIFIED", "evidence": "source log"}
            ],
        })

    def test_all_verified_returns_all_events(self):
        mock_client = _make_mock_llm_client(self._verification_response(["VERIFIED"]))
        result = GroundingVerifier(client=mock_client).run(self._schema(), self._timeline())
        assert isinstance(result, GroundedResult)
        assert len(result.events) == 1
        assert result.unsupported_removed == 0

    def test_unsupported_event_removed(self):
        mock_client = _make_mock_llm_client(self._verification_response(["UNSUPPORTED"]))
        result = GroundingVerifier(client=mock_client).run(self._schema(), self._timeline())
        assert len(result.events) == 0
        assert result.unsupported_removed == 1

    def test_uncertain_event_kept_but_flagged(self):
        mock_client = _make_mock_llm_client(self._verification_response(["UNCERTAIN"]))
        result = GroundingVerifier(client=mock_client).run(self._schema(), self._timeline())
        assert len(result.events) == 1
        assert result.events[0].uncertain is True
        assert result.uncertain_count == 1

    def test_mixed_statuses_filtered_correctly(self):
        tl = self._timeline(n_events=3)
        mock_client = _make_mock_llm_client(
            self._verification_response(["VERIFIED", "UNSUPPORTED", "UNCERTAIN"])
        )
        result = GroundingVerifier(client=mock_client).run(self._schema(), tl)
        assert len(result.events) == 2  # VERIFIED + UNCERTAIN kept
        assert result.unsupported_removed == 1
        assert result.uncertain_count == 1

    def test_unsupported_executive_summary_cleared(self):
        mock_client = _make_mock_llm_client(json.dumps({
            "event_verifications": [
                {"claim_id": "EVT-001", "status": "VERIFIED", "evidence": "log"}
            ],
            "executive_summary_status": "UNSUPPORTED",
            "root_cause_status": "VERIFIED",
            "ioc_verifications": [],
        }))
        result = GroundingVerifier(client=mock_client).run(self._schema(), self._timeline())
        assert result.executive_summary != "A single SSH intrusion event was detected."
        assert "verified" in result.executive_summary.lower() or "unsupported" in result.executive_summary.lower() or result.executive_summary == ""

    def test_result_is_grounded_result_instance(self):
        mock_client = _make_mock_llm_client(self._verification_response(["VERIFIED"]))
        result = GroundingVerifier(client=mock_client).run(self._schema(), self._timeline())
        assert isinstance(result, GroundedResult)


# ═══════════════════════════════════════════════════════════════════════════════
# 5. REPORT GENERATOR TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestIocTypeClassification:
    def test_ipv4(self):
        assert _ioc_type("192.168.1.100") == "IP Address"

    def test_md5_hash(self):
        assert _ioc_type("d41d8cd98f00b204e9800998ecf8427e") == "File Hash"

    def test_sha256_hash(self):
        assert _ioc_type("a" * 64) == "File Hash"

    def test_domain(self):
        assert _ioc_type("malware.evil.com") == "Domain"

    def test_unix_filepath(self):
        assert _ioc_type("/tmp/malware.sh") == "File Path"

    def test_windows_filepath(self):
        assert _ioc_type("C:\\Windows\\Temp\\payload.exe") == "File Path"

    def test_unknown_indicator(self):
        assert _ioc_type("SOME_UNKNOWN_IOC_TYPE") == "Indicator"


class TestReportGenerator:
    def _grounded(self, **overrides) -> GroundedResult:
        return _make_grounded_result(**overrides)

    def test_render_returns_markdown_string(self, tmp_path):
        g = self._grounded()
        gen = ReportGenerator()
        md, _ = gen.render(
            g,
            analyst_name="T. Tester",
            incident_id="INC-TEST-001",
            classification="CONFIDENTIAL",
            generate_pdf=False,
            output_dir=tmp_path,
        )
        assert isinstance(md, str)
        assert len(md) > 100

    def test_markdown_contains_incident_id(self, tmp_path):
        g = self._grounded()
        gen = ReportGenerator()
        md, _ = gen.render(
            g,
            analyst_name="T. Tester",
            incident_id="INC-UNIQUE-XYZ",
            classification="RESTRICTED",
            generate_pdf=False,
            output_dir=tmp_path,
        )
        assert "INC-UNIQUE-XYZ" in md

    def test_markdown_contains_analyst_name(self, tmp_path):
        g = self._grounded()
        gen = ReportGenerator()
        md, _ = gen.render(
            g,
            analyst_name="Ana Reyes",
            incident_id="INC-001",
            classification="INTERNAL",
            generate_pdf=False,
            output_dir=tmp_path,
        )
        assert "Ana Reyes" in md

    def test_classification_in_output(self, tmp_path):
        g = self._grounded()
        gen = ReportGenerator()
        md, _ = gen.render(
            g,
            analyst_name="Analyst",
            incident_id="INC-001",
            classification="TLP:RED",
            generate_pdf=False,
            output_dir=tmp_path,
        )
        assert "TLP:RED" in md

    def test_uncertain_tag_in_output(self, tmp_path):
        uncertain_event = TimelineEvent(
            event_id="EVT-001",
            timestamp="2024-01-15T08:30:00",
            description="Possible lateral movement (unconfirmed)",
            source_ref="analyst note",
            uncertain=True,
        )
        g = _make_grounded_result(events=[uncertain_event], uncertain_count=1)
        gen = ReportGenerator()
        md, _ = gen.render(
            g,
            analyst_name="Analyst",
            incident_id="INC-001",
            classification="CONFIDENTIAL",
            generate_pdf=False,
            output_dir=tmp_path,
        )
        assert "UNCERTAIN" in md.upper() or "uncertain" in md.lower()

    def test_no_pdf_when_disabled(self, tmp_path):
        g = self._grounded()
        gen = ReportGenerator()
        _, pdf_path = gen.render(
            g,
            analyst_name="Analyst",
            incident_id="INC-001",
            classification="INTERNAL",
            generate_pdf=False,
            output_dir=tmp_path,
        )
        assert pdf_path is None

    def test_pdf_saved_to_output_dir(self, tmp_path):
        """PDF is saved to output_dir when generate_pdf=True (skipped if WeasyPrint unavailable)."""
        try:
            import weasyprint  # noqa: F401
            import markdown as _md  # noqa: F401
        except ImportError:
            pytest.skip("WeasyPrint or markdown not importable in this environment")
        g = self._grounded()
        gen = ReportGenerator()
        _, pdf_path = gen.render(
            g,
            analyst_name="Analyst",
            incident_id="INC-001",
            classification="INTERNAL",
            generate_pdf=True,
            output_dir=tmp_path,
        )
        assert pdf_path is not None
        assert pdf_path.exists()
        assert pdf_path.suffix == ".pdf"


# ═══════════════════════════════════════════════════════════════════════════════
# 6. END-TO-END PIPELINE TESTS (mocked LLM)
# ═══════════════════════════════════════════════════════════════════════════════


def _mock_pipeline_responses(n_events: int = 2):
    """Return (timeline_json, grounding_json) for a pipeline with n_events."""
    events = [
        {
            "event_id": f"EVT-{i:03}",
            "timestamp": f"2024-01-15T08:{i:02}:00",
            "description": f"Pipeline event {i}",
            "source_ref": f"event[{i-1}]",
            "uncertain": False,
        }
        for i in range(1, n_events + 1)
    ]
    timeline_json = json.dumps({
        "events": events,
        "executive_summary": "Test pipeline summary.",
        "affected_assets": ["host01"],
        "ioc_list": ["10.0.0.1", "a1b2c3d4e5f6" + "a" * 26],
        "containment_actions": ["Blocked at firewall"],
        "root_cause": "Unpatched service",
        "lessons_learned": ["Patch faster"],
        "severity": "HIGH",
        "mitre_techniques": ["T1190 - Exploit Public-Facing Application"],
        "detection_time_minutes": 10,
        "containment_time_minutes": 30,
        "remediation_tasks": [
            {"task": "Patch the affected service", "owner": "IT Ops", "priority": "HIGH", "due_date": "7 days"}
        ],
    })
    grounding_json = json.dumps({
        "event_verifications": [
            {"claim_id": f"EVT-{i:03}", "status": "VERIFIED", "evidence": f"log line {i}"}
            for i in range(1, n_events + 1)
        ],
        "executive_summary_status": "VERIFIED",
        "root_cause_status": "VERIFIED",
        "ioc_verifications": [
            {"claim_id": "10.0.0.1", "status": "VERIFIED", "evidence": "firewall log"}
        ],
    })
    return timeline_json, grounding_json


class TestEndToEndPipeline:
    def _run_pipeline(self, raw_input: str, analyst_notes=None, tmp_path=None):
        timeline_json, grounding_json = _mock_pipeline_responses(2)
        call_count = 0

        def side_effect(system_prompt, user_message, **kwargs):
            nonlocal call_count
            call_count += 1
            return timeline_json if call_count == 1 else grounding_json

        mock_client = MagicMock(spec=LLMClient)
        mock_client.complete.side_effect = side_effect

        schema = parse(raw_input, analyst_notes=analyst_notes)
        timeline = TimelineAgent(client=mock_client).run(schema)
        grounded = GroundingVerifier(client=mock_client).run(schema, timeline)
        output_dir = tmp_path if tmp_path else Path("/tmp")
        md, _ = ReportGenerator().render(
            grounded,
            analyst_name="Test Analyst",
            incident_id="INC-E2E-001",
            classification="CONFIDENTIAL",
            generate_pdf=False,
            output_dir=output_dir,
        )
        return schema, timeline, grounded, md

    def test_ransomware_fixture_pipeline(self, tmp_path):
        fixture = _FIXTURES / "ransomware_alert.json"
        if not fixture.exists():
            pytest.skip("Fixture file not found")
        raw = fixture.read_text()
        schema, timeline, grounded, md = self._run_pipeline(raw, tmp_path=tmp_path)
        assert schema.input_source == "json"
        assert len(timeline.events) > 0
        assert isinstance(grounded, GroundedResult)
        assert "INC-E2E-001" in md

    def test_phishing_fixture_pipeline(self, tmp_path):
        fixture = _FIXTURES / "phishing_siem_export.txt"
        if not fixture.exists():
            pytest.skip("Fixture file not found")
        raw = fixture.read_text()
        schema, timeline, grounded, md = self._run_pipeline(raw, tmp_path=tmp_path)
        assert len(timeline.events) > 0
        assert isinstance(grounded, GroundedResult)

    def test_analyst_notes_fixture_pipeline(self, tmp_path):
        fixture = _FIXTURES / "analyst_notes_raw.txt"
        if not fixture.exists():
            pytest.skip("Fixture file not found")
        raw = fixture.read_text()
        schema, timeline, grounded, md = self._run_pipeline(
            raw, analyst_notes="Insider threat suspected", tmp_path=tmp_path
        )
        assert schema.analyst_notes == "Insider threat suspected"
        assert isinstance(grounded, GroundedResult)

    def test_pipeline_llm_called_exactly_twice(self):
        timeline_json, grounding_json = _mock_pipeline_responses(1)
        responses = [timeline_json, grounding_json]
        mock_client = MagicMock(spec=LLMClient)
        mock_client.complete.side_effect = responses
        schema = parse("2024-01-15T08:30:00 login succeeded from 10.0.0.5")
        timeline = TimelineAgent(client=mock_client).run(schema)
        GroundingVerifier(client=mock_client).run(schema, timeline)
        assert mock_client.complete.call_count == 2

    def test_grounded_result_has_no_unsupported(self):
        timeline_json, grounding_json = _mock_pipeline_responses(2)
        call_count = 0

        def side_effect(system_prompt, user_message, **kwargs):
            nonlocal call_count
            call_count += 1
            return timeline_json if call_count == 1 else grounding_json

        mock_client = MagicMock(spec=LLMClient)
        mock_client.complete.side_effect = side_effect
        schema = parse("2024-01-15T08:30:00 intrusion detected on server01")
        timeline = TimelineAgent(client=mock_client).run(schema)
        grounded = GroundingVerifier(client=mock_client).run(schema, timeline)
        assert grounded.unsupported_removed == 0

    def test_report_contains_ioc_section(self, tmp_path):
        _, _, _, md = self._run_pipeline(
            "2024-01-15T08:30:00 malware beacon to 10.0.0.1",
            tmp_path=tmp_path,
        )
        assert "10.0.0.1" in md or "IOC" in md.upper()
