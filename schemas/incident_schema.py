# schemas/incident_schema.py
from pydantic import BaseModel, field_validator
from typing import List, Optional
from datetime import datetime


class RawEvent(BaseModel):
    """A single event parsed from the raw incident input."""

    timestamp: Optional[datetime] = None
    source: str  # e.g. "Splunk", "analyst note", "EDR alert"
    description: str
    raw_text: str  # original, unmodified — used for grounding verification

    @field_validator("source", "description", "raw_text", mode="before")
    @classmethod
    def _strip_whitespace(cls, v: str) -> str:
        return v.strip() if isinstance(v, str) else v


class IncidentSchema(BaseModel):
    """Normalised representation of all incident data passed through the pipeline."""

    events: List[RawEvent]
    analyst_notes: Optional[str] = None
    input_source: str  # "paste" | "json" | "logfile"

    @field_validator("input_source", mode="before")
    @classmethod
    def _validate_source(cls, v: str) -> str:
        allowed = {"paste", "json", "logfile"}
        if v not in allowed:
            raise ValueError(f"input_source must be one of {allowed}, got '{v}'")
        return v
