import streamlit as st


def get_dashboard_firewall():
    """
    Return one persistent FirewallInterceptor
    for the current dashboard session.
    """

    if "dashboard_firewall" not in st.session_state:

        from firewall.interceptor import (
            FirewallInterceptor
        )

        st.session_state.dashboard_firewall = (
            FirewallInterceptor()
        )

    return st.session_state.dashboard_firewall


def get_dashboard_gemini_agent():
    """
    Return one persistent GeminiAgent
    for the current dashboard session.
    """

    if "dashboard_gemini_agent" not in st.session_state:

        from agent.gemini_agent import (
            GeminiAgent
        )

        st.session_state.dashboard_gemini_agent = (
            GeminiAgent(
                session_id=(
                    st.session_state
                    .dashboard_session_id
                ),
                user_id="U001",
            )
        )

    return st.session_state.dashboard_gemini_agent