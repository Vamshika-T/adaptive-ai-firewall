import streamlit as st

from dashboard.components.styles import apply_dashboard_styles
from dashboard.data.state import (
    clear_dashboard_session,
    initialize_dashboard_state,
)


# PAGE CONFIGURATION

st.set_page_config(
    page_title="Adaptive AI Firewall",
    page_icon="",
    layout="wide",
    initial_sidebar_state="expanded",
)


# INITIALIZATION

initialize_dashboard_state()
apply_dashboard_styles()


# SIDEBAR


with st.sidebar:

    st.markdown(
        """
        <div class="sidebar-brand">
            <div class="sidebar-brand-title">
                Adaptive AI Firewall
            </div>
            <div class="sidebar-brand-subtitle">
                Security Console
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        '<div class="sidebar-status">● Ready</div>',
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
            "Demo mode runs controlled ToolRequests through "
            "the firewall. Gemini mode sends natural-language "
            "requests through Gemini and the same firewall."
        ),
    )

    st.session_state.dashboard_mode = mode

    st.markdown("---")

    if st.button(
        "Reset Session",
        use_container_width=True,
    ):
        clear_dashboard_session()
        st.rerun()

    st.markdown("---")

    st.caption(
        "Security decisions are made by the firewall."
    )


# HEADER

header_html = (
    '<div class="security-header">'
    '<div class="security-title">'
    'Adaptive AI Firewall'
    '</div>'
    '<div class="security-subtitle">'
    'Enterprise LLM security console'
    '</div>'
    '<div class="status-pill status-ready">'
    '● System ready'
    '</div>'
    '</div>'
)

st.markdown(
    header_html,
    unsafe_allow_html=True,
)


# PAGES

overview_page = st.Page(
    "pages/overview.py",
    title="Overview",
    icon=":material/dashboard:",
    default=True,
)

chat_page = st.Page(
    "pages/chat.py",
    title="AI Agent Console",
    icon=":material/smart_toy:",
)

request_inspector_page = st.Page(
    "pages/request_inspector.py",
    title="Request Inspector",
    icon=":material/search:",
)

evaluation_page = st.Page(
    "pages/evaluation.py",
    title="Evaluation",
    icon=":material/analytics:",
)

architecture_page = st.Page(
    "pages/architecture.py",
    title="Architecture",
    icon=":material/account_tree:",
)


# NAVIGATION

pg = st.navigation(
    {
        "Security Console": [
            overview_page,
            chat_page,
            request_inspector_page,
            evaluation_page,
            architecture_page,
        ],
    },
    position="sidebar",
    expanded=True,
)


pg.run()


# FOOTER

st.markdown(
    '<div class="dashboard-footer">'
    'Adaptive Context-Aware AI Firewall · '
    'Enterprise LLM Agent Security'
    '</div>',
    unsafe_allow_html=True,
)