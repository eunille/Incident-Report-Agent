# ui/app.py
"""
Incident Report Writer — Streamlit UI.
Layout: Navbar → Stepper (full-width) → Two-column workspace
Left col: Report settings → Incident data → Analyst notes → Generate
Right col: Generated report output
"""

import os
import sys
import traceback
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
load_dotenv(_ROOT / ".env")

from agent.grounding_verifier import GroundingVerifier
from agent.llm_client import LLMClient
from agent.parser import parse
from agent.report_generator import ReportGenerator
from agent.timeline_agent import TimelineAgent

st.set_page_config(
    page_title="Incident Report Writer",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(
    '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"/>',
    unsafe_allow_html=True,
)

st.markdown("""<style>
html,body,[class*="css"]{font-family:'Inter','Segoe UI',sans-serif;}
[data-testid="stSidebar"]{display:none!important;}
[data-testid="stHeader"]{display:none!important;}
#MainMenu{visibility:hidden;}footer{visibility:hidden;}
.main .block-container{padding-top:0!important;padding-bottom:2rem;max-width:100%!important;}
section[data-testid="stMain"]>div:first-child{padding-top:0!important;}

/* Navbar */
.irw-nav{position:sticky;top:0;z-index:999;background:#0d1117;border-bottom:1px solid #21262d;padding:0 2rem;height:54px;display:flex;align-items:center;justify-content:space-between;}
.irw-brand{display:flex;align-items:center;gap:10px;color:#e6edf3;font-size:1rem;font-weight:700;}
.irw-brand-icon{color:#58a6ff;font-size:1.15rem;}
.irw-brand-sub{font-size:0.7rem;color:#8b949e;font-weight:400;letter-spacing:0.6px;text-transform:uppercase;}
.irw-nav-right{display:flex;align-items:center;gap:14px;}
.irw-badge{display:inline-flex;align-items:center;gap:6px;padding:3px 12px;border-radius:20px;font-size:0.74rem;font-weight:600;border:1px solid;}
.p-groq{background:#0d1f0d;color:#3fb950;border-color:#238636;}
.p-gemini{background:#0d0d1f;color:#79b8ff;border-color:#1f6feb;}
.p-claude{background:#1f0d00;color:#ffa657;border-color:#d2690e;}
.p-none{background:#111;color:#8b949e;border-color:#30363d;}
.irw-nav-link{color:#8b949e;font-size:0.8rem;text-decoration:none;display:flex;align-items:center;gap:5px;padding:3px 8px;border-radius:4px;}
.irw-nav-link:hover{color:#e6edf3;}

/* Stepper */
.irw-stepper{background:#0d1117;border-bottom:1px solid #21262d;padding:14px 2rem;}
.stepper-row{display:flex;align-items:center;width:100%;}
.stepper-item{display:flex;flex-direction:column;align-items:center;position:relative;flex:1;}
.stepper-item:not(:last-child)::after{content:'';position:absolute;top:14px;left:50%;width:100%;height:2px;background:#21262d;z-index:0;}
.stepper-item.s-done:not(:last-child)::after{background:#238636;}
.stepper-item.s-run:not(:last-child)::after{background:linear-gradient(to right,#1f6feb,#21262d);}
.stepper-item.s-warn:not(:last-child)::after{background:#d29922;}
.stepper-circle{width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:0.75rem;font-weight:700;z-index:1;border:2px solid;}
.s-pending .stepper-circle{background:#0d1117;border-color:#30363d;color:#555;}
.s-run .stepper-circle{background:#1f6feb22;border-color:#1f6feb;color:#58a6ff;}
.s-done .stepper-circle{background:#23863622;border-color:#238636;color:#3fb950;}
.s-warn .stepper-circle{background:#d2990022;border-color:#d29922;color:#d29922;}
.s-error .stepper-circle{background:#f8514922;border-color:#f85149;color:#f85149;}
.stepper-label{font-size:0.7rem;color:#555;margin-top:6px;text-align:center;white-space:nowrap;}
.s-run .stepper-label{color:#58a6ff;}
.s-done .stepper-label{color:#3fb950;}
.s-warn .stepper-label{color:#d29922;}
.s-error .stepper-label{color:#f85149;}

/* Workspace */
.irw-workspace{padding:1.4rem 2rem;}

/* Section headers */
.irw-sh{display:flex;align-items:center;gap:7px;font-size:0.72rem;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:#8b949e;border-bottom:1px solid #21262d;padding-bottom:5px;margin-bottom:12px;margin-top:16px;}
.irw-sh:first-child{margin-top:0;}

/* Widget overrides */
[data-testid="stTextInput"] input{background:#0d1117!important;border:1px solid #30363d!important;border-radius:5px!important;color:#e6edf3!important;font-size:0.85rem!important;}
[data-testid="stTextArea"] textarea{background:#0d1117!important;border:1px solid #30363d!important;border-radius:6px!important;color:#e6edf3!important;font-size:0.87rem!important;}
[data-testid="stSelectbox"]>div>div{background:#0d1117!important;border:1px solid #30363d!important;border-radius:5px!important;color:#e6edf3!important;font-size:0.85rem!important;}
[data-testid="stRadio"] label{color:#c9d1d9!important;font-size:0.84rem!important;}
[data-testid="stCheckbox"] label{color:#c9d1d9!important;font-size:0.84rem!important;}
label[data-testid="stWidgetLabel"] p{color:#8b949e!important;font-size:0.72rem!important;font-weight:600!important;text-transform:uppercase!important;letter-spacing:0.5px!important;}

/* Generate button */
div[data-testid="stButton"]>button[kind="primary"]{background:linear-gradient(135deg,#1f6feb,#0969da)!important;color:#fff!important;border:none!important;border-radius:6px!important;padding:0.6rem 1.4rem!important;font-weight:700!important;font-size:0.9rem!important;width:100%!important;transition:opacity 0.2s!important;}
div[data-testid="stButton"]>button[kind="primary"]:hover{opacity:0.85!important;}
div[data-testid="stButton"]>button[kind="primary"]:disabled{opacity:0.35!important;}

/* Download buttons */
div[data-testid="stDownloadButton"]>button{border-radius:6px!important;font-size:0.82rem!important;background:#21262d!important;color:#c9d1d9!important;border:1px solid #30363d!important;}
div[data-testid="stDownloadButton"]>button:hover{background:#30363d!important;color:#e6edf3!important;}

/* Metrics */
[data-testid="metric-container"]{background:#161b22!important;border:1px solid #21262d!important;border-radius:7px!important;padding:9px 13px!important;}
[data-testid="metric-container"] label{color:#8b949e!important;font-size:0.7rem!important;}
[data-testid="metric-container"] [data-testid="stMetricValue"]{color:#e6edf3!important;font-size:1.35rem!important;font-weight:700!important;}

/* Severity badges */
.sv-CRITICAL{display:inline-block;padding:2px 10px;border-radius:4px;font-size:0.76rem;font-weight:700;background:#3d0000;color:#f85149;border:1px solid #f85149;}
.sv-HIGH{display:inline-block;padding:2px 10px;border-radius:4px;font-size:0.76rem;font-weight:700;background:#2d1a00;color:#ffa657;border:1px solid #ffa657;}
.sv-MEDIUM{display:inline-block;padding:2px 10px;border-radius:4px;font-size:0.76rem;font-weight:700;background:#2a2000;color:#d2a90a;border:1px solid #d2a90a;}
.sv-LOW{display:inline-block;padding:2px 10px;border-radius:4px;font-size:0.76rem;font-weight:700;background:#0d2a16;color:#3fb950;border:1px solid #3fb950;}
.sv-UNKNOWN{display:inline-block;padding:2px 10px;border-radius:4px;font-size:0.76rem;font-weight:700;background:#1a1a1a;color:#8b949e;border:1px solid #30363d;}

/* Report area */
.irw-report{background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:1.5rem 1.8rem;min-height:420px;}
.irw-empty{display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:420px;gap:12px;}
.irw-empty i{font-size:2.8rem;color:#21262d;}
.irw-empty p{font-size:0.87rem;color:#30363d;margin:0;}

/* Skeleton loader */
@keyframes shimmer{0%{background-position:-600px 0}100%{background-position:600px 0}}
.skeleton{background:linear-gradient(90deg,#161b22 25%,#21262d 50%,#161b22 75%);background-size:600px 100%;animation:shimmer 1.4s infinite linear;border-radius:4px;}
.skeleton-header{height:24px;width:55%;margin-bottom:16px;}
.skeleton-line{height:13px;margin-bottom:10px;}
.skeleton-line.w100{width:100%;}
.skeleton-line.w85{width:85%;}
.skeleton-line.w70{width:70%;}
.skeleton-line.w45{width:45%;}
.skeleton-line.w30{width:30%;}
.skeleton-block{height:80px;width:100%;margin-bottom:14px;border-radius:6px;}
.skeleton-table-row{height:32px;width:100%;margin-bottom:6px;border-radius:3px;}
.skeleton-badge{height:22px;width:100px;border-radius:20px;display:inline-block;margin-right:8px;}
.skeleton-metric{height:60px;width:100%;border-radius:7px;}
.irw-skeleton-wrap{padding:0;}

/* Callouts */
.cw{background:#2a1e00;border-left:3px solid #d2a90a;border-radius:4px;padding:7px 11px;font-size:0.81rem;color:#d2a90a;margin:5px 0;}
.ce{background:#2a0a0a;border-left:3px solid #f85149;border-radius:4px;padding:7px 11px;font-size:0.81rem;color:#f85149;margin:5px 0;}
.irw-hr{border:none;border-top:1px solid #21262d;margin:10px 0;}

/* Report typography */
.irw-report h1{color:#e6edf3;font-size:1.35rem;margin-bottom:4px;}
.irw-report h2{color:#58a6ff;font-size:1.05rem;border-bottom:1px solid #21262d;padding-bottom:3px;margin-top:20px;}
.irw-report h3{color:#79c0ff;font-size:0.92rem;}
.irw-report table{width:100%;border-collapse:collapse;font-size:0.82rem;margin:8px 0;}
.irw-report th{background:#161b22;color:#8b949e;text-align:left;padding:6px 9px;border:1px solid #21262d;font-size:0.73rem;text-transform:uppercase;letter-spacing:0.5px;}
.irw-report td{padding:6px 9px;border:1px solid #21262d;color:#c9d1d9;vertical-align:top;}
.irw-report tr:nth-child(even) td{background:#0a0e14;}
.irw-report code{background:#161b22;color:#79c0ff;padding:1px 5px;border-radius:3px;font-size:0.81rem;}
.irw-report blockquote{border-left:3px solid #30363d;margin:6px 0;padding:5px 11px;color:#8b949e;font-size:0.82rem;}
.irw-report li{margin-bottom:2px;}
.irw-report strong{color:#e6edf3;}
.irw-report p{line-height:1.6;color:#c9d1d9;}
</style>""", unsafe_allow_html=True)


# ── Provider ───────────────────────────────────────────────────────────────────

def _provider_info():
    ep = os.environ.get("LLM_PROVIDER", "").lower()
    if not ep:
        if os.environ.get("GROQ_API_KEY"):   ep = "groq"
        elif os.environ.get("GEMINI_API_KEY"): ep = "gemini"
        elif os.environ.get("ANTHROPIC_API_KEY"): ep = "claude"
    _MAP = {
        "groq":   ("Groq · llama-3.3-70b", "p-groq",   '<i class="fa-solid fa-bolt"></i>'),
        "gemini": ("Gemini · 2.0-flash",    "p-gemini", '<i class="fa-solid fa-gem"></i>'),
        "claude": ("Claude",                "p-claude", '<i class="fa-solid fa-robot"></i>'),
    }
    name, css, icon = _MAP.get(ep, ("No provider", "p-none", '<i class="fa-solid fa-circle-exclamation"></i>'))
    _KEY_MAP = {"groq": "GROQ_API_KEY", "gemini": "GEMINI_API_KEY"}
    _FB = {"groq": "gemini", "gemini": "groq"}
    fb = _FB.get(ep)
    if fb and os.environ.get(_KEY_MAP.get(fb, "")):
        name += " + fallback"
    return name, css, icon

_pname, _pcss, _picon = _provider_info()


# ── Navbar ─────────────────────────────────────────────────────────────────────

st.markdown(f"""<div class="irw-nav">
<div class="irw-brand">
  <span class="irw-brand-icon"><i class="fa-solid fa-shield-halved"></i></span>
  <div><div>Incident Report Writer</div><div class="irw-brand-sub">AI-Powered Post-Incident Analysis</div></div>
</div>
<div class="irw-nav-right">
  <span class="irw-badge {_pcss}">{_picon} {_pname}</span>
  <a class="irw-nav-link" href="#"><i class="fa-solid fa-circle-question"></i> Help</a>
</div>
</div>""", unsafe_allow_html=True)


# ── Stepper (full-width, below navbar) ────────────────────────────────────────

_STEP_LABELS = ["Parse & Normalize", "Timeline (LLM 1)", "Grounding (LLM 2)", "Render Report"]
_STEP_ICONS = {
    "pending": '<i class="fa-regular fa-circle"></i>',
    "running": '<i class="fa-solid fa-circle-notch fa-spin"></i>',
    "done":    '<i class="fa-solid fa-circle-check"></i>',
    "warn":    '<i class="fa-solid fa-triangle-exclamation"></i>',
    "error":   '<i class="fa-solid fa-circle-xmark"></i>',
}

stepper_placeholder = st.empty()


_SKELETON_HTML = (
    '<div class="irw-skeleton-wrap">'
    '<div class="skeleton skeleton-badge"></div>'
    '<div style="height:8px"></div>'
    '<div style="display:flex;gap:8px;margin-bottom:14px">'
    + "".join(f'<div style="flex:1"><div class="skeleton skeleton-metric"></div></div>' for _ in range(4))
    + '</div>'
    '<div class="skeleton skeleton-header"></div>'
    + "".join(f'<div class="skeleton skeleton-line w{w}"></div>' for w in ["100","85","70","100","85","45"])
    + '<div class="skeleton skeleton-block"></div>'
    + "".join(f'<div class="skeleton skeleton-table-row"></div>' for _ in range(5))
    + '</div>'
)


def _render_skeleton(placeholder) -> None:
    placeholder.markdown(
        f'<div class="irw-report">{_SKELETON_HTML}</div>',
        unsafe_allow_html=True,
    )


def _render_stepper(statuses: list[str]) -> None:
    items = ""
    for label, status in zip(_STEP_LABELS, statuses):
        icon = _STEP_ICONS.get(status, _STEP_ICONS["pending"])
        items += (
            f'<div class="stepper-item s-{status}">'
            f'<div class="stepper-circle">{icon}</div>'
            f'<div class="stepper-label">{label}</div>'
            f'</div>'
        )
    stepper_placeholder.markdown(
        f'<div class="irw-stepper"><div class="stepper-row">{items}</div></div>',
        unsafe_allow_html=True,
    )


_render_stepper(["pending", "pending", "pending", "pending"])


# ── Two-column workspace ───────────────────────────────────────────────────────

st.markdown('<div class="irw-workspace">', unsafe_allow_html=True)

left_col, right_col = st.columns([5, 7], gap="large")


# ═══════════════════════════════════════════════════════
# LEFT: Report settings → Incident data → Notes → Generate
# ═══════════════════════════════════════════════════════

with left_col:

    # ── Report settings (top of left column) ──
    st.markdown('<div class="irw-sh"><i class="fa-solid fa-sliders"></i> Report Settings</div>', unsafe_allow_html=True)

    r1, r2 = st.columns(2)
    with r1:
        analyst_name = st.text_input("Analyst Name", placeholder="e.g. J. Reyes")
    with r2:
        incident_id = st.text_input("Incident ID", placeholder="e.g. INC-2026-001")

    cls_c, pdf_c = st.columns([3, 2])
    with cls_c:
        classification = st.selectbox(
            "Classification",
            ["CONFIDENTIAL", "RESTRICTED", "INTERNAL", "TLP:RED", "TLP:AMBER", "TLP:GREEN"],
        )
    with pdf_c:
        st.markdown("<br>", unsafe_allow_html=True)
        generate_pdf = st.checkbox("Generate PDF", value=True)

    # ── Incident data ──
    st.markdown('<div class="irw-sh"><i class="fa-solid fa-file-import"></i> Incident Data</div>', unsafe_allow_html=True)

    input_mode = st.radio(
        "input_mode",
        ["Paste text", "Upload file"],
        horizontal=True,
        label_visibility="collapsed",
    )

    raw_text: str | None = None
    force_source: str | None = None

    if input_mode == "Paste text":
        raw_text = st.text_area(
            "raw_input",
            height=220,
            placeholder=(
                "Paste SIEM alert JSON, raw log lines, analyst notes, or a mix.\n"
                "Format is auto-detected (JSON \u00b7 logfile \u00b7 freetext)."
            ),
            label_visibility="collapsed",
        )
    else:
        up = st.file_uploader(
            "Upload",
            type=["json", "log", "txt"],
            help="Splunk/Sentinel JSON, .log files, or plain-text analyst notes",
            label_visibility="collapsed",
        )
        if up:
            raw_text = up.read().decode("utf-8", errors="replace")
            force_source = "json" if up.name.endswith(".json") else "logfile"
            icon = "fa-file-code" if force_source == "json" else "fa-file-lines"
            label = "JSON \u2014 parsing as SIEM export" if force_source == "json" else "Log/text file"
            st.markdown(f'<div class="cw"><i class="fa-solid {icon}"></i> Detected: {label}</div>', unsafe_allow_html=True)

    # ── Analyst notes ──
    st.markdown('<div class="irw-sh"><i class="fa-solid fa-note-sticky"></i> Analyst Notes</div>', unsafe_allow_html=True)
    analyst_notes_input = st.text_area(
        "analyst_notes",
        height=80,
        placeholder="Additional context, observations, or open questions (optional).",
        label_visibility="collapsed",
    )

    st.markdown('<hr class="irw-hr"/>', unsafe_allow_html=True)

    generate_btn = st.button(
        "\u26a1  Generate Report",
        type="primary",
        disabled=not raw_text or not raw_text.strip(),
    )

    # ── About ──
    st.markdown('<div class="irw-sh" style="margin-top:24px"><i class="fa-solid fa-circle-info"></i> About</div>', unsafe_allow_html=True)
    st.markdown(
        '<p style="font-size:0.76rem;color:#8b949e;line-height:1.6;">'
        'Two-pass LLM pipeline: timeline reconstruction then grounding verification. '
        'Report follows NIST SP 800-61r2 / SANS IR structure with MITRE ATT&amp;CK tagging.'
        '</p>',
        unsafe_allow_html=True,
    )


# ═══════════════════════════════════════════════════════
# RIGHT: Generated report
# ═══════════════════════════════════════════════════════

with right_col:

    st.markdown('<div class="irw-sh"><i class="fa-solid fa-file-shield"></i> Generated Report</div>', unsafe_allow_html=True)

    output_placeholder = st.empty()
    output_placeholder.markdown(
        '<div class="irw-report irw-empty">'
        '<i class="fa-solid fa-shield-halved"></i>'
        '<p>Fill in the settings and incident data, then click <strong style="color:#8b949e">Generate Report</strong>.</p>'
        '</div>',
        unsafe_allow_html=True,
    )


# ═══════════════════════════════════════════════════════
# PIPELINE EXECUTION
# ═══════════════════════════════════════════════════════

if generate_btn and raw_text and raw_text.strip():

    statuses = ["pending", "pending", "pending", "pending"]
    error_occurred = False
    markdown_report: str | None = None
    pdf_bytes: bytes | None = None
    grounded = None

    # Show skeleton loader immediately
    with right_col:
        _render_skeleton(output_placeholder)

    try:
        llm_client = LLMClient.from_env()

        # Step 1 — Parse
        statuses[0] = "running"
        _render_stepper(statuses)
        schema = parse(raw_text, analyst_notes=analyst_notes_input or None, force_source=force_source)
        statuses[0] = "done"
        _render_stepper(statuses)

        # Step 2 — Timeline (refresh skeleton to indicate LLM working)
        statuses[1] = "running"
        _render_stepper(statuses)
        with right_col:
            _render_skeleton(output_placeholder)
            timeline_agent = TimelineAgent(client=llm_client)
            timeline = timeline_agent.run(schema)
        statuses[1] = "done"
        _render_stepper(statuses)

        # Step 3 — Grounding
        statuses[2] = "running"
        _render_stepper(statuses)
        with right_col:
            _render_skeleton(output_placeholder)
            verifier = GroundingVerifier(client=llm_client)
            grounded = verifier.run(schema, timeline)
        statuses[2] = "warn" if (grounded.unsupported_removed > 0 or grounded.uncertain_count > 0) else "done"
        _render_stepper(statuses)

        # Step 4 — Render
        statuses[3] = "running"
        _render_stepper(statuses)
        with right_col:
            _render_skeleton(output_placeholder)
            gen = ReportGenerator()
            markdown_report, pdf_path = gen.render(
                    grounded,
                    analyst_name=analyst_name or "[ANALYST NAME]",
                    incident_id=incident_id or "[INCIDENT-ID]",
                    classification=classification,
                    generate_pdf=generate_pdf,
                )
                if pdf_path and pdf_path.exists():
                    pdf_bytes = pdf_path.read_bytes()
        statuses[3] = "done"
        _render_stepper(statuses)

    except ValueError as exc:
        error_occurred = True
        idx = next((i for i, s in enumerate(statuses) if s == "running"), 0)
        statuses[idx] = "error"
        _render_stepper(statuses)
        with right_col:
            output_placeholder.markdown(
                f'<div class="ce"><i class="fa-solid fa-circle-xmark"></i> <strong>Pipeline error:</strong> {exc}</div>',
                unsafe_allow_html=True,
            )

    except Exception as exc:
        error_occurred = True
        idx = next((i for i, s in enumerate(statuses) if s == "running"), 0)
        statuses[idx] = "error"
        _render_stepper(statuses)
        with right_col:
            output_placeholder.empty()
            st.markdown(
                f'<div class="ce"><i class="fa-solid fa-triangle-exclamation"></i> <strong>Error:</strong> {exc}</div>',
                unsafe_allow_html=True,
            )
            with st.expander("Traceback"):
                st.code(traceback.format_exc())

    # ── Show output ────────────────────────────────────────────────────────────
    if not error_occurred and markdown_report and grounded:
        with right_col:
            output_placeholder.empty()

            # Severity + SLA strip
            sev = (grounded.severity or "UNKNOWN").upper()
            sv_cls = f"sv-{sev}" if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "sv-UNKNOWN"
            sla = []
            if grounded.detection_time_minutes is not None:
                sla.append(f'<i class="fa-solid fa-stopwatch"></i> Detection: <strong>{grounded.detection_time_minutes} min</strong>')
            if grounded.containment_time_minutes is not None:
                sla.append(f'<i class="fa-solid fa-shield-check"></i> Containment: <strong>{grounded.containment_time_minutes} min</strong>')
            sla_html = "&nbsp;&nbsp;|&nbsp;&nbsp;".join(sla)

            st.markdown(
                '<div style="display:flex;align-items:center;gap:14px;margin-bottom:10px;flex-wrap:wrap;">'
                f'<span style="font-size:0.71rem;color:#8b949e;text-transform:uppercase;letter-spacing:0.5px">Severity</span>'
                f'<span class="{sv_cls}">{sev}</span>'
                + (f'<span style="font-size:0.81rem;color:#8b949e;">{sla_html}</span>' if sla_html else "")
                + '</div>',
                unsafe_allow_html=True,
            )

            # Metrics
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Events", len(grounded.events))
            m2.metric("IOCs", len(grounded.ioc_list))
            m3.metric("Uncertain", grounded.uncertain_count, delta_color="inverse")
            m4.metric("Removed", grounded.unsupported_removed, delta_color="inverse")

            if grounded.uncertain_count > 0:
                st.markdown(
                    f'<div class="cw"><i class="fa-solid fa-triangle-exclamation"></i> '
                    f'{grounded.uncertain_count} item(s) flagged [UNCERTAIN] — analyst review required.</div>',
                    unsafe_allow_html=True,
                )
            if grounded.unsupported_removed > 0:
                st.markdown(
                    f'<div class="ce"><i class="fa-solid fa-circle-minus"></i> '
                    f'{grounded.unsupported_removed} unsupported claim(s) removed.</div>',
                    unsafe_allow_html=True,
                )

            st.markdown('<hr class="irw-hr"/>', unsafe_allow_html=True)

            try:
                import markdown as _md
                report_html = _md.markdown(markdown_report, extensions=["tables", "fenced_code"])
            except ImportError:
                report_html = f"<pre>{markdown_report}</pre>"

            st.markdown(f'<div class="irw-report">{report_html}</div>', unsafe_allow_html=True)

            st.markdown('<hr class="irw-hr"/>', unsafe_allow_html=True)

            dl1, dl2, _ = st.columns([2, 2, 3])
            with dl1:
                st.download_button(
                    label="\u2b07 Download Markdown",
                    data=markdown_report.encode("utf-8"),
                    file_name=f"incident_report_{incident_id or 'report'}.md",
                    mime="text/markdown",
                    use_container_width=True,
                )
            with dl2:
                if pdf_bytes:
                    st.download_button(
                        label="\u2b07 Download PDF",
                        data=pdf_bytes,
                        file_name=f"incident_report_{incident_id or 'report'}.pdf",
                        mime="application/pdf",
                        use_container_width=True,
                    )
                else:
                    st.markdown(
                        '<p style="font-size:0.76rem;color:#8b949e;padding-top:8px;">'
                        '<i class="fa-solid fa-circle-info"></i> PDF unavailable in this environment.</p>',
                        unsafe_allow_html=True,
                    )

st.markdown('</div>', unsafe_allow_html=True)
