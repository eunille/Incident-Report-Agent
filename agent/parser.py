# agent/parser.py
"""
Normalize raw incident input (paste / JSON / logfile) into IncidentSchema.
This is the first stage of the pipeline — the agent never sees un-normalized data.
"""

import json
import re
from datetime import datetime
from typing import Any, Union

from schemas.incident_schema import IncidentSchema, RawEvent

# ── Timestamp extraction ──────────────────────────────────────────────────────

# Common timestamp patterns found in logs and SIEM exports
_TS_PATTERNS = [
    # ISO 8601 / RFC 3339
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
    # US-style: 04/22/2026 14:32:01
    r"\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}",
    # Syslog: Apr 22 14:32:01
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}",
]
_TS_REGEX = re.compile("|".join(_TS_PATTERNS))

_TS_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%b %d %H:%M:%S",
]


def _parse_timestamp(raw: str) -> datetime | None:
    """Try to parse a raw timestamp string into a datetime. Returns None on failure."""
    raw = raw.strip().rstrip("Z")
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


def _extract_timestamp(text: str) -> datetime | None:
    """Find and parse the first timestamp in a string."""
    match = _TS_REGEX.search(text)
    if match:
        return _parse_timestamp(match.group())
    return None


# ── Input-type normalisers ────────────────────────────────────────────────────


def _normalize_paste(text: str) -> IncidentSchema:
    """
    Normalize free-form pasted text.

    Strategy: Split on blank lines or lines that start a new timestamp to
    create logical event groups. Each group becomes a RawEvent.
    """
    lines = text.splitlines()
    groups: list[list[str]] = []
    current: list[str] = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            if current:
                groups.append(current)
                current = []
        else:
            # Start a new group when the line begins with a recognizable timestamp
            if current and _TS_REGEX.match(stripped):
                groups.append(current)
                current = []
            current.append(stripped)

    if current:
        groups.append(current)

    # Fallback: treat the whole text as a single event if no groups formed
    if not groups:
        groups = [[text.strip()]]

    events: list[RawEvent] = []
    for group in groups:
        block = "\n".join(group)
        events.append(
            RawEvent(
                timestamp=_extract_timestamp(block),
                source="analyst note",
                description=group[0][:200],  # first line as short description
                raw_text=block,
            )
        )

    return IncidentSchema(events=events, input_source="paste")


def _normalize_json(data: dict[str, Any] | list[Any]) -> IncidentSchema:
    """
    Normalize a SIEM JSON export (Splunk / Sentinel format) or generic alert list.

    Handles:
    - List of event dicts  [ {"timestamp": ..., "message": ...}, ... ]
    - Splunk results wrapper  { "results": [...] }
    - Sentinel incidents wrapper  { "value": [...] }
    - Single event dict  { "timestamp": ..., "message": ... }
    """
    # Unwrap common wrappers
    if isinstance(data, dict):
        if "results" in data:
            data = data["results"]
        elif "value" in data:
            data = data["value"]
        elif "events" in data:
            data = data["events"]
        else:
            data = [data]  # single event dict

    if not isinstance(data, list):
        data = [data]

    events: list[RawEvent] = []
    for item in data:
        if not isinstance(item, dict):
            continue

        # Extract timestamp from common field names
        ts_raw = (
            item.get("timestamp")
            or item.get("_time")
            or item.get("TimeGenerated")
            or item.get("createdDateTime")
            or item.get("time")
        )
        ts = _parse_timestamp(str(ts_raw)) if ts_raw else None

        # Extract description from common field names
        description = (
            item.get("message")
            or item.get("description")
            or item.get("title")
            or item.get("EventMessage")
            or item.get("summary")
            or str(item)[:200]
        )

        # Extract source
        source = (
            item.get("source")
            or item.get("host")
            or item.get("sourcetype")
            or item.get("providerName")
            or "SIEM"
        )

        events.append(
            RawEvent(
                timestamp=ts,
                source=str(source),
                description=str(description)[:500],
                raw_text=json.dumps(item, default=str),
            )
        )

    return IncidentSchema(events=events, input_source="json")


def _normalize_logfile(content: str) -> IncidentSchema:
    """
    Normalize a raw log file (.log / .txt).

    Strategy: Treat each line that contains a parseable timestamp as an event.
    Lines without timestamps are appended to the previous event's raw_text.
    """
    lines = content.splitlines()
    raw_events: list[tuple[datetime | None, list[str]]] = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        ts = _extract_timestamp(stripped)
        if ts is not None or not raw_events:
            raw_events.append((ts, [stripped]))
        else:
            raw_events[-1][1].append(stripped)

    # Fallback: single event
    if not raw_events:
        raw_events = [(None, [content.strip()])]

    events: list[RawEvent] = []
    for ts, lines_group in raw_events:
        block = "\n".join(lines_group)
        events.append(
            RawEvent(
                timestamp=ts,
                source="logfile",
                description=lines_group[0][:200],
                raw_text=block,
            )
        )

    return IncidentSchema(events=events, input_source="logfile")


# ── Public API ────────────────────────────────────────────────────────────────


def parse(
    raw: Union[str, bytes, dict[str, Any], list[Any]],
    *,
    analyst_notes: str | None = None,
    force_source: str | None = None,
) -> IncidentSchema:
    """
    Parse raw incident data into a normalised IncidentSchema.

    Args:
        raw: Paste text (str), JSON bytes/str/dict/list, or log file bytes/str.
        analyst_notes: Optional free-text analyst notes appended to the schema.
        force_source: Override auto-detection. One of "paste", "json", "logfile".

    Returns:
        IncidentSchema ready for the timeline agent.

    Raises:
        ValueError: If the input cannot be parsed.
    """
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")

    schema: IncidentSchema

    if force_source == "json" or isinstance(raw, (dict, list)):
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Input declared as JSON but is not valid JSON: {exc}") from exc
        schema = _normalize_json(raw)  # type: ignore[arg-type]

    elif force_source == "paste":
        schema = _normalize_paste(str(raw))

    elif force_source == "logfile":
        schema = _normalize_logfile(str(raw))

    else:
        # Auto-detect: try JSON first, fall back to log-line heuristic, else paste
        if isinstance(raw, str):
            stripped = raw.lstrip()
            if stripped.startswith(("{", "[")):
                try:
                    data = json.loads(raw)
                    schema = _normalize_json(data)
                except json.JSONDecodeError:
                    schema = _normalize_paste(raw)
            elif _TS_REGEX.search(raw):
                schema = _normalize_logfile(raw)
            else:
                schema = _normalize_paste(raw)
        else:
            schema = _normalize_paste(str(raw))

    # Attach analyst notes if provided
    if analyst_notes:
        schema = schema.model_copy(update={"analyst_notes": analyst_notes.strip()})

    return schema
