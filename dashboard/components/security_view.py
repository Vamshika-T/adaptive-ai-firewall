import streamlit as st


def display_security_event(
    event
):
    """Display one firewall security event."""

    action = event.get(
        "action",
        "UNKNOWN"
    )

    tool = event.get(
        "tool",
        "unknown_tool"
    )

    if action == "BLOCK":

        st.error(
            f"⛔ BLOCKED — {tool}"
        )

    elif action == "ESCALATE":

        st.warning(
            f"⚠️ ESCALATED — {tool}"
        )

    elif action == "MONITOR":

        st.warning(
            f"👁️ MONITOR — {tool}"
        )

    elif action == "ALLOW":

        st.success(
            f"✓ ALLOWED — {tool}"
        )

    else:

        st.info(
            f"Security decision: {action}"
        )

    col1, col2 = st.columns(2)

    with col1:

        st.write(
            f"**Tool:** `{tool}`"
        )

        st.write(
            f"**User:** `{event.get('user_id', '')}`"
        )

        st.write(
            f"**Risk:** `{event.get('risk_score', '')}`"
        )

    with col2:

        st.write(
            f"**Inspection:** "
            f"`{event.get('inspection_level', '')}`"
        )

        st.write(
            f"**Executed:** "
            f"`{event.get('executed', False)}`"
        )

        st.write(
            f"**Request:** "
            f"`{event.get('request_id', '')}`"
        )

    if event.get("arguments"):

        with st.expander(
            "Tool Arguments"
        ):

            st.json(
                event["arguments"]
            )

    if event.get("reasons"):

        with st.expander(
            "Security Reasons"
        ):

            for reason in event["reasons"]:

                st.write(
                    f"• {reason}"
                )

    if event.get("checks"):

        with st.expander(
            "Security Checks"
        ):

            for check in event["checks"]:

                st.write(
                    f"• {check}"
                )


def display_security_monitor(
    events,
    limit=5,
):
    """Display recent firewall events."""

    st.markdown(
        "### 🛡️ Security Monitor"
    )

    if not events:

        st.info(
            "No firewall events yet."
        )

        return

    recent_events = events[-limit:]

    for index, event in enumerate(
        recent_events,
        start=1,
    ):

        label = (
            f"{event.get('action', 'UNKNOWN')} — "
            f"{event.get('tool', 'unknown_tool')} — "
            f"Risk {event.get('risk_score', 0)}"
        )

        with st.expander(
            label,
            expanded=(
                index == len(recent_events)
            ),
        ):

            display_security_event(
                event
            )