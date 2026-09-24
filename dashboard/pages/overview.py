import streamlit as st

from dashboard.data.state import get_security_events


st.title("Security Overview")

st.caption(
    "Adaptive Context-Aware AI Firewall — Security Console"
)


# ------------------------------------------------------------------
# Current integration state
# ------------------------------------------------------------------

events = get_security_events()

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown(
        """
        <div class="metric-card">
            <div class="metric-label">Security Events</div>
            <div class="metric-value">0</div>
            <div class="metric-description">
                Waiting for firewall integration
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col2:
    st.markdown(
        """
        <div class="metric-card">
            <div class="metric-label">Blocked</div>
            <div class="metric-value">—</div>
            <div class="metric-description">
                Will use real firewall decisions
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col3:
    st.markdown(
        """
        <div class="metric-card">
            <div class="metric-label">Escalated</div>
            <div class="metric-value">—</div>
            <div class="metric-description">
                Will use real firewall decisions
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col4:
    st.markdown(
        """
        <div class="metric-card">
            <div class="metric-label">Allowed</div>
            <div class="metric-value">—</div>
            <div class="metric-description">
                Will use real firewall decisions
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ------------------------------------------------------------------
# Architecture status
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
            Agent integration will be connected in the next phase.
        </div>
        """,
        unsafe_allow_html=True,
    )

with status_col3:
    st.markdown(
        """
        <div class="info-box">
            <strong>📊 Monitoring</strong><br>
            Dashboard event pipeline is ready.
        </div>
        """,
        unsafe_allow_html=True,
    )


# ------------------------------------------------------------------
# Recent events
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
            Events will appear here once the dashboard is connected
            to the live firewall execution path.
        </div>
        """,
        unsafe_allow_html=True,
    )
else:
    st.dataframe(
        events,
        use_container_width=True,
        hide_index=True,
    )