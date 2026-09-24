import streamlit as st

from dashboard.data.state import get_security_events


# ------------------------------------------------------------------
# Page title
# ------------------------------------------------------------------

st.title("Security Overview")

st.caption(
    "Adaptive Context-Aware AI Firewall — Security Console"
)


# ------------------------------------------------------------------
# Current security metrics
# ------------------------------------------------------------------

events = get_security_events()

total_events = len(events)

blocked_count = sum(
    1
    for event in events
    if event.get("action") == "BLOCK"
)

escalated_count = sum(
    1
    for event in events
    if event.get("action") == "ESCALATE"
)

allowed_count = sum(
    1
    for event in events
    if event.get("action") == "ALLOW"
)


# ------------------------------------------------------------------
# Metrics
# ------------------------------------------------------------------

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">Security Events</div>
            <div class="metric-value">{total_events}</div>
            <div class="metric-description">
                Firewall requests processed
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col2:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">Blocked</div>
            <div class="metric-value">{blocked_count}</div>
            <div class="metric-description">
                Requests prevented
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col3:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">Escalated</div>
            <div class="metric-value">{escalated_count}</div>
            <div class="metric-description">
                Requests requiring additional scrutiny
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col4:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">Allowed</div>
            <div class="metric-value">{allowed_count}</div>
            <div class="metric-description">
                Authorized requests executed
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ------------------------------------------------------------------
# System Status
# ------------------------------------------------------------------

st.markdown(
    '<div class="section-title">System Status</div>',
    unsafe_allow_html=True,
)

status_col1, status_col2, status_col3 = st.columns(3)

with status_col1:
    st.markdown(
        """
        <div class="info-box">
            <strong>🛡️ Firewall</strong><br>
            Frozen security implementation is ready.
        </div>
        """,
        unsafe_allow_html=True,
    )

with status_col2:
    st.markdown(
        """
        <div class="info-box">
            <strong>🤖 Gemini Agent</strong><br>
            Connected through the existing secured
            GeminiAgent interface.
        </div>
        """,
        unsafe_allow_html=True,
    )

with status_col3:
    st.markdown(
        """
        <div class="info-box">
            <strong>📊 Monitoring</strong><br>
            Live firewall security events are displayed
            in this dashboard.
        </div>
        """,
        unsafe_allow_html=True,
    )


# ------------------------------------------------------------------
# Recent Security Events
# ------------------------------------------------------------------

st.markdown(
    '<div class="section-title">Recent Security Events</div>',
    unsafe_allow_html=True,
)

if not events:

    st.markdown(
        """
        <div class="empty-state">
            <strong>No security events yet.</strong><br><br>
            Events will appear here once the Gemini agent
            generates a tool request and the firewall processes it.
        </div>
        """,
        unsafe_allow_html=True,
    )

else:

    # --------------------------------------------------------------
    # Event table
    # --------------------------------------------------------------

    display_events = []

    for event in events:

        display_events.append(
            {
                "Time": event.get("timestamp", ""),
                "User": event.get("user_id", ""),
                "Tool": event.get("tool", ""),
                "Action": event.get("action", ""),
                "Risk": event.get("risk_score", ""),
                "Inspection": event.get(
                    "inspection_level",
                    "",
                ),
                "Executed": event.get(
                    "executed",
                    False,
                ),
            }
        )

    st.dataframe(
        display_events,
        use_container_width=True,
        hide_index=True,
    )


# ------------------------------------------------------------------
# Latest Event Details
# ------------------------------------------------------------------

if events:

    latest_event = events[-1]

    st.markdown(
        '<div class="section-title">Latest Security Event</div>',
        unsafe_allow_html=True,
    )

    action = latest_event.get(
        "action",
        "UNKNOWN",
    )

    if action == "BLOCK":

        st.error(
            f"⛔ BLOCKED — {latest_event.get('tool', 'Unknown tool')}"
        )

    elif action == "ESCALATE":

        st.warning(
            f"⚠️ ESCALATED — {latest_event.get('tool', 'Unknown tool')}"
        )

    elif action == "MONITOR":

        st.warning(
            f"👁️ MONITOR — {latest_event.get('tool', 'Unknown tool')}"
        )

    elif action == "ALLOW":

        st.success(
            f"✓ ALLOWED — {latest_event.get('tool', 'Unknown tool')}"
        )

    else:

        st.info(
            f"Security decision: {action}"
        )

    detail_col1, detail_col2 = st.columns(2)

    with detail_col1:

        st.markdown(
            f"**Request ID:** "
            f"`{latest_event.get('request_id', '')}`"
        )

        st.markdown(
            f"**Session ID:** "
            f"`{latest_event.get('session_id', '')}`"
        )

        st.markdown(
            f"**User:** "
            f"`{latest_event.get('user_id', '')}`"
        )

        st.markdown(
            f"**Tool:** "
            f"`{latest_event.get('tool', '')}`"
        )

    with detail_col2:

        st.markdown(
            f"**Risk Score:** "
            f"`{latest_event.get('risk_score', '')}`"
        )

        st.markdown(
            f"**Inspection:** "
            f"`{latest_event.get('inspection_level', '')}`"
        )

        st.markdown(
            f"**Executed:** "
            f"`{latest_event.get('executed', False)}`"
        )

        st.markdown(
            f"**Action:** "
            f"`{action}`"
        )

    # --------------------------------------------------------------
    # Arguments
    # --------------------------------------------------------------

    arguments = latest_event.get(
        "arguments",
        {},
    )

    if arguments:

        with st.expander("Tool Arguments"):

            st.json(arguments)

    # --------------------------------------------------------------
    # Security reasons
    # --------------------------------------------------------------

    reasons = latest_event.get(
        "reasons",
        [],
    )

    if reasons:

        with st.expander("Security Reasons"):

            if isinstance(reasons, list):

                for reason in reasons:
                    st.write(f"• {reason}")

            else:

                st.write(reasons)

    # --------------------------------------------------------------
    # Security checks
    # --------------------------------------------------------------

    checks = latest_event.get(
        "checks",
        [],
    )

    if checks:

        with st.expander("Security Checks"):

            if isinstance(checks, list):

                for check in checks:
                    st.write(f"• {check}")

            else:

                st.write(checks)
