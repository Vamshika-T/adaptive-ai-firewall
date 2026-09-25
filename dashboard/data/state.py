import uuid
from datetime import datetime

import streamlit as st


def initialize_dashboard_state():
    """Initialize persistent dashboard state for the current browser session."""

    if "dashboard_session_id" not in st.session_state:
        st.session_state.dashboard_session_id = (
            f"DASH-{uuid.uuid4().hex[:8].upper()}"
        )

    if "dashboard_mode" not in st.session_state:
        st.session_state.dashboard_mode = "Demo"

    if "security_events" not in st.session_state:
        st.session_state.security_events = []

    if "last_request" not in st.session_state:
        st.session_state.last_request = None

    if "last_decision" not in st.session_state:
        st.session_state.last_decision = None

    if "last_result" not in st.session_state:
        st.session_state.last_result = None

    if "chat_messages" not in st.session_state:
        st.session_state.chat_messages = []


def add_security_event(event):
    """Store an event produced by the real firewall integration."""

    event_with_timestamp = dict(event)

    if (
        "timestamp" not in event_with_timestamp
        or event_with_timestamp["timestamp"] is None
    ):
        event_with_timestamp["timestamp"] = datetime.now().isoformat(
            timespec="seconds"
        )

    st.session_state.security_events.append(
        event_with_timestamp
    )


def clear_dashboard_session():
    """Reset dashboard state and recreate runtime objects on demand."""

    st.session_state.security_events = []
    st.session_state.last_request = None
    st.session_state.last_decision = None
    st.session_state.last_result = None
    st.session_state.chat_messages = []

    st.session_state.pop(
        "dashboard_firewall",
        None,
    )

    st.session_state.pop(
        "dashboard_gemini_agent",
        None,
    )

    st.session_state.pop(
        "dashboard_evaluation_records",
        None,
    )

    st.session_state.pop(
        "dashboard_evaluation_metrics",
        None,
    )


def get_security_events():
    """Return all security events recorded in this dashboard session."""

    return st.session_state.security_events