import uuid
from datetime import datetime

import streamlit as st


def initialize_dashboard_state():
    """Initialize dashboard-level session state.

    This stores UI/session information only.
    Security decisions remain owned by the firewall.
    """

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
    """Add an event produced by the real firewall integration.

    A1 only establishes the storage interface.
    The actual firewall integration will be added later.
    """

    event_with_timestamp = dict(event)

    if "timestamp" not in event_with_timestamp:
        event_with_timestamp["timestamp"] = datetime.now().isoformat(
            timespec="seconds"
        )

    st.session_state.security_events.append(event_with_timestamp)


def clear_dashboard_session():
    """Reset dashboard-only state."""

    st.session_state.security_events = []
    st.session_state.last_request = None
    st.session_state.last_decision = None
    st.session_state.last_result = None
    st.session_state.chat_messages = []


def get_security_events():
    """Return the current dashboard security-event list."""

    return st.session_state.security_events