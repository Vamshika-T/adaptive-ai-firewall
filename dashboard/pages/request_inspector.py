import streamlit as st

from dashboard.data.state import get_security_events


st.title("🔎 Request Inspector")

st.caption(
    "Inspect the latest ToolRequest and the firewall decision "
    "that processed it."
)


request = st.session_state.get(
    "last_request"
)

decision = st.session_state.get(
    "last_decision"
)

result = st.session_state.get(
    "last_result"
)

events = get_security_events()


if request is None or decision is None:

    st.info(
        "No request has been processed in this dashboard session yet. "
        "Run a Demo scenario or use Gemini mode first."
    )

else:

    action = getattr(
        decision,
        "action",
        "UNKNOWN"
    )

    risk = getattr(
        decision,
        "risk_score",
        0.0
    )

    inspection = getattr(
        decision,
        "inspection_level",
        "UNKNOWN"
    )

    if action == "BLOCK":

        st.error(
            f"⛔ BLOCK — {request.tool}"
        )

    elif action == "ESCALATE":

        st.warning(
            f"⚠️ ESCALATE — {request.tool}"
        )

    elif action == "MONITOR":

        st.warning(
            f"👁️ MONITOR — {request.tool}"
        )

    else:

        st.success(
            f"✓ {action} — {request.tool}"
        )


    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Risk",
        f"{risk:.1f}"
    )

    col2.metric(
        "Inspection",
        inspection
    )

    col3.metric(
        "Executed",
        "Yes" if result is not None else "No"
    )

    col4.metric(
        "Security Events",
        len(events)
    )


    st.markdown("### ToolRequest")

    request_data = {

        "request_id":
            request.request_id,

        "session_id":
            request.session_id,

        "user_id":
            request.user_id,

        "tool":
            request.tool,

        "arguments":
            request.arguments,

        "intent":
            request.intent,

        "context_sources":
            request.context_sources,

        "tainted":
            request.tainted,

        "source_type":
            request.source_type,

        "function_call_id":
            request.function_call_id,

        "timestamp":
            request.timestamp.isoformat(
                timespec="seconds"
            ),
    }

    st.json(
        request_data
    )


    st.markdown(
        "### Firewall Decision"
    )

    decision_data = {

        "action":
            action,

        "risk_score":
            risk,

        "inspection_level":
            inspection,

        "reasons":
            getattr(
                decision,
                "reasons",
                []
            ),

        "checks":
            getattr(
                decision,
                "checks",
                []
            ),
    }

    st.json(
        decision_data
    )


    st.markdown(
        "### Tool Result"
    )

    if result is None:

        st.info(
            "No enterprise tool result was produced "
            "because execution did not proceed."
        )

    else:

        st.json(
            result
        )


    st.markdown(
        "### Security Context"
    )

    context_col1, context_col2 = st.columns(2)

    with context_col1:

        st.write(
            "**Tainted:**",
            request.tainted
        )

        st.write(
            "**Context sources:**",
            request.context_sources
            or "None"
        )

    with context_col2:

        st.write(
            "**Source type:**",
            request.source_type
        )

        st.write(
            "**Function call ID:**",
            request.function_call_id
            or "None"
        )


st.markdown(
    "### Event History"
)


if not events:

    st.info(
        "No firewall events recorded yet."
    )

else:

    rows = []

    for event in events:

        rows.append(
            {
                "Time":
                    event.get(
                        "timestamp",
                        ""
                    ),

                "Request":
                    event.get(
                        "request_id",
                        ""
                    ),

                "User":
                    event.get(
                        "user_id",
                        ""
                    ),

                "Tool":
                    event.get(
                        "tool",
                        ""
                    ),

                "Action":
                    event.get(
                        "action",
                        ""
                    ),

                "Risk":
                    event.get(
                        "risk_score",
                        ""
                    ),

                "Inspection":
                    event.get(
                        "inspection_level",
                        ""
                    ),

                "Executed":
                    event.get(
                        "executed",
                        False
                    ),
            }
        )

    st.dataframe(
        rows,
        use_container_width=True,
        hide_index=True
    )