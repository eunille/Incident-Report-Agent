# agent/report_generator.py
"""
Report Generator — Phase 4 of the pipeline.

Fills the Jinja2 template with GroundedResult data, renders to Markdown,
and optionally converts to PDF via WeasyPrint.

The renderer only accepts GroundedResult objects — never raw LLM output.
"""

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from agent.grounding_verifier import GroundedResult

# ── Paths ──────────────────────────────────────────────────────────────────────

_PACKAGE_ROOT = Path(__file__).resolve().parent.parent
_TEMPLATES_DIR = _PACKAGE_ROOT / "templates"
_OUTPUTS_DIR = _PACKAGE_ROOT / "outputs"
_TEMPLATE_NAME = "incident_report.md.j2"


# ── Jinja2 custom filters ──────────────────────────────────────────────────────

_IP_RE = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$"           # IPv4
    r"|^[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7}$",  # IPv6 (colon-separated groups)
    re.IGNORECASE,
)
_HASH_RE = re.compile(r"^[0-9a-f]{32,128}$", re.IGNORECASE)  # MD5/SHA1/SHA256/SHA512
_DOMAIN_RE = re.compile(r"^(?:[a-z0-9\-]+\.)+[a-z]{2,}$", re.IGNORECASE)


def _ioc_type(value: str) -> str:
    """Heuristically classify an IOC string for the table."""
    v = value.strip()
    if _HASH_RE.match(v):
        return "File Hash"
    if _IP_RE.match(v):
        return "IP Address"
    if v.startswith(("/", "C:\\", "c:\\")):
        return "File Path"
    if _DOMAIN_RE.match(v):
        return "Domain"
    return "Indicator"


def _build_jinja_env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        undefined=StrictUndefined,
        autoescape=False,  # Markdown output, not HTML
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["ioc_type"] = _ioc_type
    return env


# ── PDF rendering ──────────────────────────────────────────────────────────────


def _markdown_to_pdf(markdown_text: str, output_path: Path) -> None:
    """Convert Markdown → HTML → PDF using WeasyPrint."""
    try:
        import markdown as md_lib
        from weasyprint import HTML, CSS
    except ImportError as exc:
        raise ImportError(
            "PDF generation requires 'weasyprint' and 'markdown'. "
            "Run: pip install weasyprint markdown"
        ) from exc

    html_body = md_lib.markdown(
        markdown_text,
        extensions=["tables", "fenced_code"],
    )

    # Minimal but readable CSS for the PDF
    css = CSS(
        string="""
        @page { margin: 2cm; size: A4; }
        body { font-family: 'DejaVu Sans', Arial, sans-serif; font-size: 11pt;
               line-height: 1.6; color: #1a1a1a; }
        h1 { font-size: 18pt; border-bottom: 2px solid #333; padding-bottom: 6px; }
        h2 { font-size: 14pt; margin-top: 24px; border-bottom: 1px solid #ccc; }
        h3 { font-size: 12pt; }
        code { background: #f4f4f4; padding: 2px 4px; border-radius: 3px;
               font-family: 'DejaVu Sans Mono', monospace; font-size: 9pt; }
        table { border-collapse: collapse; width: 100%; margin: 12px 0; }
        th, td { border: 1px solid #ccc; padding: 6px 10px; text-align: left; }
        th { background: #f0f0f0; font-weight: bold; }
        blockquote { border-left: 4px solid #f0ad4e; padding-left: 12px;
                     color: #666; margin: 12px 0; }
        """
    )

    full_html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Incident Report</title></head>
<body>{html_body}</body></html>"""

    HTML(string=full_html).write_pdf(str(output_path), stylesheets=[css])


# ── Public API ─────────────────────────────────────────────────────────────────


class ReportGenerator:
    """
    Renders a GroundedResult into a Markdown report and optionally a PDF.

    Usage:
        gen = ReportGenerator()
        md, pdf_path = gen.render(grounded, generate_pdf=True)
    """

    def __init__(self, templates_dir: Optional[Path] = None) -> None:
        self._env = _build_jinja_env() if templates_dir is None else Environment(
            loader=FileSystemLoader(str(templates_dir)),
            undefined=StrictUndefined,
            autoescape=False,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        if templates_dir:
            self._env.filters["ioc_type"] = _ioc_type

    def render(
        self,
        grounded: GroundedResult,
        *,
        analyst_name: str = "[ANALYST NAME]",
        incident_id: str = "[INCIDENT-ID]",
        classification: str = "CONFIDENTIAL",
        generate_pdf: bool = False,
        output_dir: Optional[Path] = None,
    ) -> tuple[str, Optional[Path]]:
        """
        Render the grounded result to Markdown (and optionally PDF).

        Args:
            grounded: Verified GroundedResult from GroundingVerifier.run().
            analyst_name: Name of the reviewing analyst.
            incident_id: Incident tracking ID.
            classification: Report classification label.
            generate_pdf: If True, also render a PDF and return its path.
            output_dir: Directory to save output files. Defaults to outputs/.

        Returns:
            Tuple of (markdown_text, pdf_path_or_None).
        """
        report_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        template = self._env.get_template(_TEMPLATE_NAME)
        markdown_text: str = template.render(
            report_date=report_date,
            analyst_name=analyst_name,
            incident_id=incident_id,
            classification=classification,
            executive_summary=grounded.executive_summary,
            events=grounded.events,
            affected_assets=grounded.affected_assets,
            ioc_list=grounded.ioc_list,
            containment_actions=grounded.containment_actions,
            root_cause=grounded.root_cause,
            lessons_learned=grounded.lessons_learned,
            unsupported_removed=grounded.unsupported_removed,
            uncertain_count=grounded.uncertain_count,
            severity=grounded.severity,
            mitre_techniques=grounded.mitre_techniques,
            detection_time_minutes=grounded.detection_time_minutes,
            containment_time_minutes=grounded.containment_time_minutes,
            remediation_tasks=grounded.remediation_tasks,
        )

        pdf_path: Optional[Path] = None

        if generate_pdf:
            save_dir = output_dir or _OUTPUTS_DIR
            save_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            safe_id = re.sub(r"[^a-zA-Z0-9_\-]", "_", incident_id)
            pdf_path = save_dir / f"incident_report_{safe_id}_{ts}.pdf"
            _markdown_to_pdf(markdown_text, pdf_path)

        return markdown_text, pdf_path
