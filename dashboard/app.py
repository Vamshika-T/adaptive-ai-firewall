import streamlit as st

from dashboard.components.styles import apply_dashboard_styles
from dashboard.data.state import (
    clear_dashboard_session,
    initialize_dashboard_state,
)


# ------------------------------------------------------------------
# Page configuration
# ------------------------------------------------------------------

st.set_page_config(
    page_title="Adaptive AI Firewall",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ------------------------------------------------------------------
# Initialize dashboard
# ------------------------------------------------------------------

initialize_dashboard_state()
apply_dashboard_styles()


# ------------------------------------------------------------------
# Sidebar
# ------------------------------------------------------------------

with st.sidebar:

    st.markdown(
        '<div style="font-size:1.15rem;font-weight:700;color:#f5f7fa;'
        'margin-bottom:0.2rem;">🛡️ Adaptive AI Firewall</div>'
        '<div style="font-size:0.78rem;color:#7f8b97;margin-bottom:1rem;">'
        'Enterprise Agent Security Console</div>',
        unsafe_allow_html=True,
    )

    st.markdown("---")

    st.markdown(
        '<div style="color:#73e6a1;font-size:0.82rem;'
        'font-weight:600;margin-bottom:0.8rem;">'
        '● FIREWALL READY'
        '</div>',
        unsafe_allow_html=True,
    )

    st.markdown("### Session")

    st.caption(
        st.session_state.dashboard_session_id
    )

    mode = st.selectbox(
        "Application Mode",
        ["Demo", "Gemini"],
        index=0,
        help=(
            "Demo mode will use controlled requests. "
            "Gemini mode will be connected in a later phase."
        ),
    )

    st.session_state.dashboard_mode = mode

    st.markdown("---")

    if st.button(
        "Reset Dashboard Session",
        use_container_width=True,
    ):
        clear_dashboard_session()
        st.rerun()

    st.markdown("---")

    st.caption(
        "Security decisions are made by the "
        "Adaptive AI Firewall, not by the dashboard."
    )


# ------------------------------------------------------------------
# Shared application header
# ------------------------------------------------------------------

header_html = (
    '<div class="security-header">'
    '<div class="security-title">'
    '🛡️ Adaptive Context-Aware AI Firewall'
    '</div>'
    '<div class="security-subtitle">'
    'Enterprise LLM Agent Security Console'
    '</div>'
    '<div class="status-pill status-ready">'
    '● SECURITY BACKEND READY'
    '</div>'
    '</div>'
)

st.markdown(
    header_html,
    unsafe_allow_html=True,
)


# ------------------------------------------------------------------
# Navigation
# ------------------------------------------------------------------

overview_page = st.Page(
    "pages/overview.py",
    title="Overview",
    icon=":material/dashboard:",
    default=True,
)

pg = st.navigation(
    {
        "Security Console": [
            overview_page,
        ],
    },
    position="sidebar",
    expanded=True,
)

pg.run()


# ------------------------------------------------------------------
# Footer
# ------------------------------------------------------------------

st.markdown(
    '<div class="dashboard-footer">'
    'Adaptive Context-Aware AI Firewall · '
    'Enterprise LLM Agent Security'
    '</div>',
    unsafe_allow_html=True,
)