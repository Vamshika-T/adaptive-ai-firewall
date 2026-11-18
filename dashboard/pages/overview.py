from pathlib import Path
import csv
import html

import pandas as pd
import streamlit as st

from dashboard.data.state import get_security_events


# -----------------------------------------------------------------------------
# PAGE SETUP + VISUAL STYLE
# -----------------------------------------------------------------------------
st.title("Security Overview")
st.caption("Adaptive Context-Aware AI Firewall · Live Security Console")

events = get_security_events()

st.markdown(
    """
    <style>
    .overview-hero {
        background: linear-gradient(115deg, #111827 0%, #1e3a5f 58%, #164e63 100%);
        border: 1px solid #29445f; border-radius: 16px; padding: 22px 24px;
        color: #f8fafc; margin: 4px 0 18px 0;
    }
    .overview-hero h2 { color:#ffffff !important; margin:0 0 5px 0; font-size:25px; }
    .overview-hero p { color:#dbeafe !important; margin:0; font-size:13px; }
    .eyebrow { color:#93c5fd !important; font-size:10px; font-weight:800;
        letter-spacing:1.7px; text-transform:uppercase; margin-bottom:8px; }
    .level-card { background:var(--secondary-background-color); border:1px solid rgba(120,130,145,.25);
        border-radius:14px; padding:17px 16px; min-height:190px; }
    .level-card.fast { border-top:5px solid #16a34a; }
    .level-card.contextual { border-top:5px solid #d97706; }
    .level-card.deep { border-top:5px solid #dc2626; }
    .level-tag { font-size:10px; font-weight:800; letter-spacing:1.3px; opacity:.7; }
    .level-name { font-size:19px; font-weight:800; margin:8px 0; }
    .level-desc { font-size:12px; line-height:1.55; min-height:48px; opacity:.78; }
    .level-trigger { font-size:11px; line-height:1.6; margin-top:10px;
        padding-top:9px; border-top:1px solid rgba(120,130,145,.25); opacity:.8; }
    .section-note { opacity:.68; font-size:12px; margin-top:-7px; margin-bottom:12px; }
    .flow-node { background:var(--secondary-background-color); border:1px solid rgba(120,130,145,.25);
        border-radius:11px; padding:12px 9px; text-align:center; }
    .flow-title { font-size:12px; font-weight:800; }
    .flow-sub { font-size:10px; opacity:.65; margin-top:3px; }
    .flow-arrow { text-align:center; opacity:.55; font-size:20px; padding-top:6px; }
    .viz-card { background:var(--secondary-background-color); border:1px solid rgba(120,130,145,.22);
        border-radius:14px; padding:16px; height:100%; }
    .viz-title { font-size:13px; font-weight:800; margin-bottom:12px; }
    .viz-sub { font-size:11px; opacity:.65; margin-top:8px; }
    .bar-row { display:grid; grid-template-columns:105px 1fr 35px; gap:9px;
        align-items:center; margin:12px 0; font-size:12px; }
    .bar-track { height:10px; border-radius:99px; background:rgba(130,140,155,.18); overflow:hidden; }
    .bar-fill { height:100%; border-radius:99px; }
    .bar-value { text-align:right; font-weight:800; font-variant-numeric:tabular-nums; }
    .donut-wrap { display:flex; align-items:center; gap:18px; flex-wrap:wrap; }
    .donut { width:126px; height:126px; border-radius:50%; position:relative; flex:0 0 126px; }
    .donut-hole { position:absolute; inset:23px; border-radius:50%;
        background:var(--secondary-background-color); display:flex; align-items:center;
        justify-content:center; flex-direction:column; }
    .donut-total { font-size:23px; font-weight:850; line-height:1.1; }
    .donut-caption { font-size:9px; opacity:.65; text-transform:uppercase; letter-spacing:.8px; }
    .legend { display:grid; gap:8px; font-size:11px; }
    .legend-item { display:flex; align-items:center; gap:7px; }
    .legend-dot { width:9px; height:9px; border-radius:3px; display:inline-block; }
    .event-card { background:var(--secondary-background-color); border:1px solid rgba(120,130,145,.25);
        border-radius:12px; padding:13px 15px; margin:8px 0; }
    .event-top { display:flex; align-items:center; justify-content:space-between; gap:10px; flex-wrap:wrap; }
    .event-tool { font-weight:800; font-size:13px; }
    .event-meta { font-size:11px; opacity:.68; margin-top:5px; }
    .pill { display:inline-block; border-radius:99px; padding:4px 9px; font-size:10px;
        font-weight:800; letter-spacing:.35px; margin-left:4px; }
    .pill-fast { background:#dcfce7; color:#166534; }
    .pill-contextual { background:#ffedd5; color:#9a3412; }
    .pill-deep { background:#fee2e2; color:#991b1b; }
    .pill-allow { background:#dcfce7; color:#166534; }
    .pill-block { background:#fee2e2; color:#991b1b; }
    .pill-escalate { background:#fef3c7; color:#92400e; }
    .pill-monitor { background:#dbeafe; color:#1e40af; }
    .empty-panel { border:1px dashed rgba(120,130,145,.45); border-radius:12px;
        padding:17px; opacity:.75; font-size:12px; }
    .metric-strip { display:flex; gap:8px; flex-wrap:wrap; margin:8px 0 14px; }
    .metric-chip { background:var(--secondary-background-color); border:1px solid rgba(120,130,145,.2);
        border-radius:10px; padding:9px 12px; min-width:115px; }
    .metric-chip strong { display:block; font-size:20px; line-height:1.2; }
    .metric-chip span { font-size:10px; opacity:.68; }
    </style>
    """,
    unsafe_allow_html=True,
)


def esc(value):
    return html.escape(str(value if value is not None else ""))


def render_horizontal_bars(items, colors, max_value=None, suffix=""):
    """Render compact, theme-aware horizontal bars without Streamlit's dark chart canvas."""
    values = [max(0, float(v)) for _, v in items]
    scale = max_value if max_value is not None else (max(values) if values else 1)
    scale = max(scale, 1)
    parts = []
    for (label, value), color in zip(items, colors):
        width = max(0, min(100, (float(value) / scale) * 100))
        shown = f"{value:g}{suffix}" if isinstance(value, (int, float)) else esc(value)
        parts.append(
            f'<div class="bar-row"><div>{esc(label)}</div>'
            f'<div class="bar-track"><div class="bar-fill" style="width:{width:.1f}%;background:{color}"></div></div>'
            f'<div class="bar-value">{shown}</div></div>'
        )
    return "".join(parts)


def render_donut(counts, palette):
    total = sum(counts.values())
    if total <= 0:
        gradient = "conic-gradient(#94a3b8 0deg 360deg)"
    else:
        stops = []
        current = 0.0
        for (label, value), color in zip(counts.items(), palette):
            end = current + (value / total * 360)
            stops.append(f"{color} {current:.1f}deg {end:.1f}deg")
            current = end
        gradient = "conic-gradient(" + ", ".join(stops) + ")"
    legend = "".join(
        f'<div class="legend-item"><span class="legend-dot" style="background:{color}"></span>'
        f'<span>{esc(label)}</span><strong style="margin-left:auto">{value}</strong></div>'
        for (label, value), color in zip(counts.items(), palette)
    )
    return (
        f'<div class="donut-wrap"><div class="donut" style="background:{gradient}">'
        f'<div class="donut-hole"><div class="donut-total">{total}</div>'
        f'<div class="donut-caption">requests</div></div></div>'
        f'<div class="legend">{legend}</div></div>'
    )



def render_line_chart(points):
    # Responsive SVG risk trend with a theme-aware canvas.
    if not points:
        return '<div class="empty-panel">Risk trend will appear after requests are processed.</div>'

    width, height = 720, 220
    left, right, top, bottom = 42, 18, 18, 42
    plot_w, plot_h = width - left - right, height - top - bottom
    points = points[-12:]

    coords = []
    for index, (label, value) in enumerate(points):
        x = left + (plot_w * index / max(1, len(points) - 1))
        y = top + plot_h - (max(0, min(100, value)) / 100) * plot_h
        coords.append((x, y, label, value))

    polyline = " ".join(f"{x:.1f},{y:.1f}" for x, y, _, _ in coords)
    area = f"{left},{top + plot_h} " + polyline + f" {left + plot_w},{top + plot_h}"

    grid = []
    for value in (0, 25, 50, 75, 100):
        y = top + plot_h - (value / 100) * plot_h
        grid.append(
            f'<line x1="{left}" y1="{y:.1f}" x2="{left + plot_w}" y2="{y:.1f}" '
            f'stroke="currentColor" stroke-opacity=".12" stroke-dasharray="3 5"/>'
            f'<text x="{left - 9}" y="{y + 4:.1f}" text-anchor="end" '
            f'font-size="10" fill="currentColor" opacity=".55">{value}</text>'
        )

    dots = []
    for x, y, label, value in coords:
        dots.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4.5" fill="#0ea5e9" '
            f'stroke="var(--secondary-background-color)" stroke-width="2">'
            f'<title>{html.escape(label)}: {value:.1f}/100</title></circle>'
        )

    labels = []
    label_indices = [0] if len(coords) == 1 else sorted(set([0, len(coords)//2, len(coords)-1]))
    for idx in label_indices:
        x, y, label, value = coords[idx]
        labels.append(
            f'<text x="{x:.1f}" y="{height - 13}" text-anchor="middle" '
            f'font-size="9" fill="currentColor" opacity=".6">{html.escape(label[:13])}</text>'
        )

    return f'''
    <div style="width:100%;overflow:hidden">
      <svg viewBox="0 0 {width} {height}" role="img" aria-label="Risk score trend"
           style="width:100%;height:auto;display:block;color:var(--text-color)">
        <defs>
          <linearGradient id="riskAreaFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="#0ea5e9" stop-opacity=".24"/>
            <stop offset="100%" stop-color="#0ea5e9" stop-opacity="0"/>
          </linearGradient>
        </defs>
        {''.join(grid)}
        <polygon points="{area}" fill="url(#riskAreaFill)"/>
        <polyline points="{polyline}" fill="none" stroke="#0ea5e9"
                  stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round"/>
        {''.join(dots)}
        {''.join(labels)}
      </svg>
    </div>
    '''



def render_recorded_flow(event):
    """Show the request lifecycle using only fields present in dashboard events."""
    level = str(event.get("inspection_level") or "UNKNOWN").upper()
    action = str(event.get("action") or "UNKNOWN").upper()
    checks = event.get("checks") or []
    reasons = event.get("reasons") or []
    risk = event.get("risk_score", "N/A")

    if not isinstance(checks, list):
        checks = [str(checks)]
    if not isinstance(reasons, list):
        reasons = [str(reasons)]

    stages = [
        ("01", "REQUEST RECEIVED", "Tool request and arguments recorded", True),
        ("02", "INSPECTION ROUTED", f"{level} inspection selected", level in ("FAST", "CONTEXTUAL", "DEEP")),
        ("03", "RECORDED SECURITY CHECKS", f"{len(checks)} check item(s) recorded", bool(checks)),
        ("04", "RISK ASSESSMENT", f"Risk score: {risk}/100", risk not in (None, "")),
        ("05", "FINAL ENFORCEMENT", f"{action} · Executed: {'Yes' if event.get('executed') else 'No'}", action in ("ALLOW", "BLOCK", "ESCALATE", "MONITOR")),
    ]

    rows = []
    for number, title, subtitle, available in stages:
        state_color = "#16a34a" if available else "#94a3b8"
        state_text = "RECORDED" if available else "NOT AVAILABLE IN EVENT"
        rows.append(
            f'<div style="display:flex;gap:12px;align-items:center;padding:10px 0;'
            f'border-bottom:1px solid rgba(120,130,145,.16)">'
            f'<div style="width:30px;height:30px;flex:0 0 30px;border-radius:50%;'
            f'background:{state_color}1a;color:{state_color};display:flex;align-items:center;'
            f'justify-content:center;font-size:11px;font-weight:800">{number}</div>'
            f'<div style="flex:1"><div style="font-size:12px;font-weight:800">{title}</div>'
            f'<div style="font-size:11px;opacity:.68">{html.escape(str(subtitle))}</div></div>'
            f'<div style="font-size:9px;font-weight:800;color:{state_color}">{state_text}</div>'
            f'</div>'
        )
    return '<div class="viz-card">' + "".join(rows) + '</div>'


# -----------------------------------------------------------------------------
# HERO + TOP METRICS
# -----------------------------------------------------------------------------
st.markdown(
    """
    <div class="overview-hero">
      <div class="eyebrow">Runtime protection · Enterprise AI</div>
      <h2>Adaptive inspection at a glance</h2>
      <p>Requests are routed to an inspection depth based on sensitivity, context,
      provenance and risk signals. The firewall then enforces a separate security decision.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

total_events = len(events)
blocked_count = sum(e.get("action") == "BLOCK" for e in events)
escalated_count = sum(e.get("action") == "ESCALATE" for e in events)
allowed_count = sum(e.get("action") == "ALLOW" for e in events)
monitored_count = sum(e.get("action") == "MONITOR" for e in events)

metric_cols = st.columns(4)
metrics = [
    ("SECURITY EVENTS", total_events, "Requests processed in this session"),
    ("BLOCKED", blocked_count, "Requests prevented"),
    ("ESCALATED", escalated_count, "Requests requiring review"),
    ("ALLOWED", allowed_count, "Requests permitted by the firewall"),
]
for col, (label, value, description) in zip(metric_cols, metrics):
    with col:
        st.markdown(
            f"""<div class="metric-card"><div class="metric-label">{label}</div>
            <div class="metric-value">{value}</div><div class="metric-description">{description}</div></div>""",
            unsafe_allow_html=True,
        )

# -----------------------------------------------------------------------------
# INSPECTION LEVELS: ALWAYS VISIBLE + LIVE COUNTS
# -----------------------------------------------------------------------------
st.markdown('<div class="section-title">Adaptive Inspection Levels</div>', unsafe_allow_html=True)
st.markdown('<div class="section-note">All three levels remain visible. Counts update from requests recorded in this session.</div>', unsafe_allow_html=True)

level_order = ["FAST", "CONTEXTUAL", "DEEP"]
level_counts = {
    level: sum(str(e.get("inspection_level", "")).upper() == level for e in events)
    for level in level_order
}
level_info = [
    ("FAST", "fast", "01 · LIGHTWEIGHT", "Low-risk requests with no significant contextual signals.",
     "Typical signals: low sensitivity · trusted provenance · no taint · no suspicious context", "#16a34a"),
    ("CONTEXTUAL", "contextual", "02 · CONTEXT-AWARE", "Adds intent, trajectory and semantic risk analysis when context warrants it.",
     "Typical signals: sensitivity ≥ 50 · context sources · suspicious intent · moderate semantic or trajectory risk", "#d97706"),
    ("DEEP", "deep", "03 · HIGH SCRUTINY", "Deeper checks for tainted or untrusted context, highly sensitive resources or stronger risk signals.",
     "Typical signals: tainted input · untrusted provenance · sensitivity ≥ 75 · trajectory ≥ 30 · semantic risk ≥ 60", "#dc2626"),
]
level_cols = st.columns(3, gap="medium")
for col, (name, css, tag, desc, trigger, color) in zip(level_cols, level_info):
    with col:
        st.markdown(
            f"""<div class="level-card {css}">
            <div class="level-tag">{tag}</div><div class="level-name">{name}</div>
            <div class="level-desc">{desc}</div>
            <div class="metric-chip" style="display:inline-block;margin:5px 0 3px">
              <strong>{level_counts[name]}</strong><span> requests this session</span>
            </div>
            <div class="level-trigger"><b>Routing signals</b><br>{trigger}</div>
            </div>""",
            unsafe_allow_html=True,
        )

# Per-level counts, percentages and average risk (derived from recorded events).
st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)
comparison_cols = st.columns(3)
for col, level in zip(comparison_cols, level_order):
    level_events = [
        event for event in events
        if str(event.get("inspection_level", "")).upper() == level
    ]
    level_risks = []
    for item in level_events:
        try:
            level_risks.append(float(item.get("risk_score")))
        except (TypeError, ValueError):
            pass
    pct = (len(level_events) / total_events * 100) if total_events else 0
    avg = (sum(level_risks) / len(level_risks)) if level_risks else None
    with col:
        st.caption(
            f"{level}: {len(level_events)} requests · {pct:.1f}% of session · "
            + (f"average risk {avg:.1f}/100" if avg is not None else "average risk N/A")
        )

st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
flow_cols = st.columns([1, .16, 1, .16, 1, .16, 1])
flow_nodes = [
    ("INCOMING REQUEST", "Tool · user · arguments · context"),
    ("ADAPTIVE ROUTER", "FAST / CONTEXTUAL / DEEP"),
    ("SECURITY ANALYSIS", "Identity · intent · trajectory · semantics"),
    ("RISK & ENFORCEMENT", "ALLOW · MONITOR · ESCALATE · BLOCK"),
]
for idx, (title, subtitle) in enumerate(flow_nodes):
    with flow_cols[idx * 2]:
        st.markdown(
            f'<div class="flow-node"><div class="flow-title">{title}</div><div class="flow-sub">{subtitle}</div></div>',
            unsafe_allow_html=True,
        )
    if idx < 3:
        with flow_cols[idx * 2 + 1]:
            st.markdown('<div class="flow-arrow">→</div>', unsafe_allow_html=True)
st.caption("Inspection depth and final action are separate: a DEEP request can still be ALLOW, while a FAST request can be blocked by authorization.")

# -----------------------------------------------------------------------------
# LIVE ANALYTICS: CUSTOM LIGHTWEIGHT VISUALS
# -----------------------------------------------------------------------------
st.markdown('<div class="section-title">Live Session Analytics</div>', unsafe_allow_html=True)
st.markdown('<div class="section-note">Live visuals use only requests recorded in the current dashboard session.</div>', unsafe_allow_html=True)

action_order = ["ALLOW", "MONITOR", "ESCALATE", "BLOCK"]
action_counts = {a: sum(str(e.get("action", "")).upper() == a for e in events) for a in action_order}
risk_values = []
for event in events:
    try:
        risk_values.append(float(event.get("risk_score")))
    except (TypeError, ValueError):
        pass

left, right = st.columns(2, gap="medium")
with left:
    st.markdown('<div class="viz-card"><div class="viz-title">Inspection-level distribution</div>', unsafe_allow_html=True)
    if events:
        st.markdown(render_horizontal_bars(
            [(k, level_counts[k]) for k in level_order],
            ["#16a34a", "#d97706", "#dc2626"],
            max_value=max(level_counts.values()) or 1
        ), unsafe_allow_html=True)
        st.markdown(
            f'<div class="viz-sub">FAST {level_counts["FAST"]} · CONTEXTUAL {level_counts["CONTEXTUAL"]} · DEEP {level_counts["DEEP"]}</div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown('<div class="empty-panel">No live requests yet. The three inspection levels and their routing criteria are shown above. Run requests to populate these counts.</div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

with right:
    st.markdown('<div class="viz-card"><div class="viz-title">Firewall decision mix</div>', unsafe_allow_html=True)
    if events:
        st.markdown(render_donut(
            action_counts,
            ["#16a34a", "#3b82f6", "#d97706", "#dc2626"]
        ), unsafe_allow_html=True)
        st.markdown('<div class="viz-sub">Counts represent final firewall actions, not inspection levels.</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="empty-panel">No decisions recorded yet. ALLOW, MONITOR, ESCALATE and BLOCK will appear here.</div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

# Risk distribution + risk by request shown as readable horizontal bars
risk_col1, risk_col2 = st.columns(2, gap="medium")
with risk_col1:
    st.markdown('<div class="viz-card"><div class="viz-title">Risk score bands</div>', unsafe_allow_html=True)
    buckets = {"0–19 · Low": 0, "20–39 · Guarded": 0, "40–59 · Elevated": 0, "60–79 · High": 0, "80–100 · Critical": 0}
    for score in risk_values:
        if score < 20: buckets["0–19 · Low"] += 1
        elif score < 40: buckets["20–39 · Guarded"] += 1
        elif score < 60: buckets["40–59 · Elevated"] += 1
        elif score < 80: buckets["60–79 · High"] += 1
        else: buckets["80–100 · Critical"] += 1
    if risk_values:
        st.markdown(render_horizontal_bars(
            list(buckets.items()),
            ["#16a34a", "#84cc16", "#eab308", "#f97316", "#dc2626"],
            max_value=max(buckets.values()) or 1
        ), unsafe_allow_html=True)
    else:
        st.markdown('<div class="empty-panel">Risk-score bands will populate after requests are processed.</div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

with risk_col2:
    st.markdown('<div class="viz-card"><div class="viz-title">Risk score trend</div>', unsafe_allow_html=True)
    trend_points = []
    for i, event in enumerate(events):
        try:
            score = float(event.get("risk_score"))
            tool = str(event.get("tool") or "request")
            trend_points.append((f"#{i + 1} {tool}", score))
        except (TypeError, ValueError):
            continue
    st.markdown(render_line_chart(trend_points), unsafe_allow_html=True)
    if trend_points:
        latest_score = trend_points[-1][1]
        average_score = sum(value for _, value in trend_points) / len(trend_points)
        st.markdown(
            f'<div class="viz-sub">Latest: <b>{latest_score:.1f}/100</b> '
            f'&nbsp; · &nbsp; Session average: <b>{average_score:.1f}/100</b> '
            f'&nbsp; · &nbsp; Showing up to 12 recent requests</div>',
            unsafe_allow_html=True,
        )
    st.markdown('</div>', unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# SECURITY PROTECTION SUMMARY
# -----------------------------------------------------------------------------
st.markdown('<div class="section-title">Session Protection Summary</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="section-note">Counts are based on recorded firewall outcomes. '
    'A BLOCK is not automatically classified as an attack.</div>',
    unsafe_allow_html=True,
)

executed_count = sum(bool(event.get("executed")) for event in events)
not_executed_count = total_events - executed_count
summary_cols = st.columns(4)
summary_items = [
    ("Executed", executed_count, "Requests with a returned tool result"),
    ("Not executed", not_executed_count, "Blocked, escalated, monitored or otherwise withheld"),
    ("Escalated", escalated_count, "Requests requiring additional scrutiny"),
    ("Blocked", blocked_count, "Requests denied by enforcement"),
]
for col, (label, value, hint) in zip(summary_cols, summary_items):
    with col:
        st.metric(label, value, help=hint)

# -----------------------------------------------------------------------------
# REQUEST-BY-REQUEST INSPECTION HISTORY + FILTERS
# -----------------------------------------------------------------------------
st.markdown('<div class="section-title">Inspection Activity Timeline</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="section-note">Filter the session history by inspection depth, '
    'final decision or tool. Select a request to inspect its recorded lifecycle.</div>',
    unsafe_allow_html=True,
)

if not events:
    st.markdown(
        '<div class="empty-panel">No request history yet. Run requests in the AI Agent Console '
        'and this timeline will show each request, inspection level, risk score and final action.</div>',
        unsafe_allow_html=True,
    )
else:
    filter_col1, filter_col2, filter_col3 = st.columns(3)
    with filter_col1:
        level_filter = st.multiselect(
            "Inspection level",
            ["FAST", "CONTEXTUAL", "DEEP"],
            default=["FAST", "CONTEXTUAL", "DEEP"],
            key="overview_level_filter",
        )
    with filter_col2:
        action_filter = st.multiselect(
            "Final decision",
            ["ALLOW", "MONITOR", "ESCALATE", "BLOCK"],
            default=["ALLOW", "MONITOR", "ESCALATE", "BLOCK"],
            key="overview_action_filter",
        )
    with filter_col3:
        available_tools = sorted({
            str(event.get("tool") or "Unknown")
            for event in events
        })
        tool_filter = st.multiselect(
            "Tool",
            available_tools,
            default=available_tools,
            key="overview_tool_filter",
        )

    filtered_events = []
    for event in events:
        event_level = str(event.get("inspection_level") or "UNKNOWN").upper()
        event_action = str(event.get("action") or "UNKNOWN").upper()
        event_tool = str(event.get("tool") or "Unknown")
        if (
            event_level in level_filter
            and event_action in action_filter
            and event_tool in tool_filter
        ):
            filtered_events.append(event)

    st.caption(f"Showing {len(filtered_events)} of {len(events)} recorded requests.")

    if not filtered_events:
        st.info("No requests match the selected filters. Adjust the filters to see more events.")
    else:
        for idx, event in enumerate(reversed(filtered_events)):
            level = str(event.get("inspection_level") or "UNKNOWN").upper()
            action = str(event.get("action") or "UNKNOWN").upper()
            level_class = level.lower() if level in ("FAST", "CONTEXTUAL", "DEEP") else "fast"
            action_class = action.lower() if action in ("ALLOW", "BLOCK", "ESCALATE", "MONITOR") else "monitor"
            try:
                risk_text = f'{float(event.get("risk_score")):.1f}/100'
            except (TypeError, ValueError):
                risk_text = "N/A"
            tool = esc(event.get("tool") or "Unknown tool")
            timestamp = esc(event.get("timestamp") or "")
            user = esc(event.get("user_id") or "")
            executed = bool(event.get("executed", False))
            request_id = esc(event.get("request_id") or "")
            display_number = len(filtered_events) - idx

            st.markdown(
                f"""<div class="event-card">
                  <div class="event-top">
                    <div class="event-tool">Request #{display_number} &nbsp; {tool}</div>
                    <div><span class="pill pill-{level_class}">{esc(level)}</span>
                    <span class="pill pill-{action_class}">{esc(action)}</span></div>
                  </div>
                  <div class="event-meta">{timestamp} &nbsp; · &nbsp; User {user} &nbsp; · &nbsp; Risk {risk_text}
                  &nbsp; · &nbsp; Executed: {"Yes" if executed else "No"}</div>
                  <div class="event-meta">Request ID: {request_id}</div>
                </div>""",
                unsafe_allow_html=True,
            )

            with st.expander(f"View request flow, checks and reasons · {request_id or f'Request #{display_number}'}"):
                st.markdown("**Recorded request lifecycle**")
                st.markdown(render_recorded_flow(event), unsafe_allow_html=True)

                arguments = event.get("arguments", {})
                if arguments:
                    st.markdown("**Tool arguments**")
                    st.json(arguments)

                reasons = event.get("reasons", [])
                if reasons:
                    st.markdown("**Security reasons**")
                    if isinstance(reasons, list):
                        for reason in reasons:
                            st.write(f"• {reason}")
                    else:
                        st.write(reasons)

                checks = event.get("checks", [])
                if checks:
                    st.markdown("**Recorded security checks**")
                    if isinstance(checks, list):
                        for check in checks:
                            st.write(f"• {check}")
                    else:
                        st.write(checks)

# -----------------------------------------------------------------------------
# SAVED EVALUATION RESULTS: CUSTOM HORIZONTAL BARS, SEPARATE FROM LIVE DATA
# -----------------------------------------------------------------------------
st.markdown('<div class="section-title">Evaluation Snapshot</div>', unsafe_allow_html=True)
st.markdown('<div class="section-note">Pre-recorded controlled-comparison results shipped with the project. These are experimental results, not current-session activity.</div>', unsafe_allow_html=True)

comparison_dir = Path(__file__).resolve().parents[2] / "evaluation" / "comparison_results"
metrics_file = comparison_dir / "method_metrics.csv"

if metrics_file.exists():
    try:
        with metrics_file.open("r", newline="", encoding="utf-8-sig") as handle:
            method_rows = list(csv.DictReader(handle))
        if method_rows:
            eval_specs = [
                ("Attack prevention", "attack_prevention_rate", "%", "#16a34a"),
                ("Legitimate-task success", "legitimate_success_rate", "%", "#0ea5e9"),
                ("Deep inspection usage", "deep_inspection_rate", "%", "#8b5cf6"),
                ("Dangerous execution", "dangerous_execution_rate", "%", "#dc2626"),
            ]
            for row_start in range(0, len(eval_specs), 2):
                eval_cols = st.columns(2, gap="medium")
                for col, (title, key, suffix, color) in zip(eval_cols, eval_specs[row_start:row_start+2]):
                    with col:
                        st.markdown(f'<div class="viz-card"><div class="viz-title">{title} by method</div>', unsafe_allow_html=True)
                        chart_items = []
                        for record in method_rows:
                            try:
                                val = float(record.get(key, 0) or 0)
                                if val <= 1 and key.endswith("_rate"):
                                    val *= 100
                            except (TypeError, ValueError):
                                val = 0
                            chart_items.append((record.get("method", "Unknown"), val))
                        st.markdown(render_horizontal_bars(
                            chart_items, [color] * len(chart_items), max_value=100, suffix="%"
                        ), unsafe_allow_html=True)
                        st.markdown('</div>', unsafe_allow_html=True)
            st.caption("Source: evaluation/comparison_results/method_metrics.csv. AgentVisor-style STI is a deterministic approximation, not the original AgentVisor implementation.")
        else:
            st.info("The saved comparison file exists but contains no result rows.")
    except (OSError, csv.Error, ValueError) as exc:
        st.warning(f"Could not load saved evaluation results: {exc}")
else:
    st.info("Saved comparison metrics were not found in the project evaluation folder.")

# -----------------------------------------------------------------------------
# SYSTEM STATUS - ORIGINAL CONTENT RETAINED
# -----------------------------------------------------------------------------
st.markdown('<div class="section-title">System Status</div>', unsafe_allow_html=True)
status_col1, status_col2, status_col3 = st.columns(3)
with status_col1:
    st.markdown("""<div class="info-box"><strong>Firewall</strong><br>Frozen security implementation is ready.</div>""", unsafe_allow_html=True)
with status_col2:
    st.markdown("""<div class="info-box"><strong>Gemini Agent</strong><br>Connected through the existing secured GeminiAgent interface.</div>""", unsafe_allow_html=True)
with status_col3:
    st.markdown("""<div class="info-box"><strong>Monitoring</strong><br>Live firewall security events are displayed in this dashboard.</div>""", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# RECENT SECURITY EVENTS - ORIGINAL TABLE RETAINED
# -----------------------------------------------------------------------------
st.markdown('<div class="section-title">Recent Security Events</div>', unsafe_allow_html=True)
if not events:
    st.markdown("""<div class="empty-state"><strong>No security events yet.</strong><br><br>Events will appear here once the Gemini agent generates a tool request and the firewall processes it.</div>""", unsafe_allow_html=True)
else:
    display_events = []
    for event in events:
        display_events.append({
            "Time": event.get("timestamp", ""),
            "User": event.get("user_id", ""),
            "Tool": event.get("tool", ""),
            "Action": event.get("action", ""),
            "Risk": event.get("risk_score", ""),
            "Inspection": event.get("inspection_level", ""),
            "Executed": event.get("executed", False),
        })
    st.dataframe(display_events, use_container_width=True, hide_index=True)

# -----------------------------------------------------------------------------
# LATEST EVENT DETAILS - ORIGINAL CONTENT RETAINED
# -----------------------------------------------------------------------------
if events:
    latest_event = events[-1]
    st.markdown('<div class="section-title">Latest Security Event</div>', unsafe_allow_html=True)
    action = latest_event.get("action", "UNKNOWN")
    if action == "BLOCK":
        st.error(f"BLOCKED — {latest_event.get('tool', 'Unknown tool')}")
    elif action == "ESCALATE":
        st.warning(f"ESCALATED — {latest_event.get('tool', 'Unknown tool')}")
    elif action == "MONITOR":
        st.warning(f"MONITOR — {latest_event.get('tool', 'Unknown tool')}")
    elif action == "ALLOW":
        st.success(f"ALLOWED — {latest_event.get('tool', 'Unknown tool')}")
    else:
        st.info(f"Security decision: {action}")

    detail_col1, detail_col2 = st.columns(2)
    with detail_col1:
        st.markdown(f"**Request ID:** `{latest_event.get('request_id', '')}`")
        st.markdown(f"**Session ID:** `{latest_event.get('session_id', '')}`")
        st.markdown(f"**User:** `{latest_event.get('user_id', '')}`")
        st.markdown(f"**Tool:** `{latest_event.get('tool', '')}`")
    with detail_col2:
        st.markdown(f"**Risk Score:** `{latest_event.get('risk_score', '')}`")
        st.markdown(f"**Inspection:** `{latest_event.get('inspection_level', '')}`")
        st.markdown(f"**Executed:** `{latest_event.get('executed', False)}`")
        st.markdown(f"**Action:** `{action}`")

    arguments = latest_event.get("arguments", {})
    if arguments:
        with st.expander("Tool Arguments"):
            st.json(arguments)

    reasons = latest_event.get("reasons", [])
    if reasons:
        with st.expander("Security Reasons"):
            if isinstance(reasons, list):
                for reason in reasons:
                    st.write(f"• {reason}")
            else:
                st.write(reasons)

    checks = latest_event.get("checks", [])
    if checks:
        with st.expander("Security Checks"):
            if isinstance(checks, list):
                for check in checks:
                    st.write(f"• {check}")
            else:
                st.write(checks)
