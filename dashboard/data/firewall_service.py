import streamlit as st

from firewall.interceptor import FirewallInterceptor
from models.schemas import ToolRequest

from dashboard.data.state import add_security_event


def _event_value(
    obj,
    attribute,
    default=None,
):
    return getattr(
        obj,
        attribute,
        default,
    )


def create_security_event(item):
    """
    Convert a real firewall result into dashboard event data.

    The dashboard does not decide ALLOW/BLOCK/etc.
    It only displays what the firewall returned.
    """

    request = item["request"]

    decision = item["decision"]

    result = item["result"]

    timestamp = _event_value(
        request,
        "timestamp",
        None,
    )

    if timestamp is not None:
        timestamp = timestamp.isoformat(
            timespec="seconds"
        )

    return {
        "request_id": request.request_id,

        "session_id": request.session_id,

        "user_id": request.user_id,

        "tool": request.tool,

        "arguments": dict(
            request.arguments
        ),

        "action": _event_value(
            decision,
            "action",
            "UNKNOWN",
        ),

        "risk_score": _event_value(
            decision,
            "risk_score",
            0.0,
        ),

        "inspection_level": _event_value(
            decision,
            "inspection_level",
            "UNKNOWN",
        ),

        "reasons": list(
            _event_value(
                decision,
                "reasons",
                [],
            )
        ),

        "checks": list(
            _event_value(
                decision,
                "checks",
                [],
            )
        ),

        "executed": result is not None,

        "timestamp": timestamp,
    }


def record_firewall_item(item):
    """
    Record one actual firewall execution.

    No security decision is made here.
    """

    event = create_security_event(
        item
    )

    add_security_event(
        event
    )

    st.session_state.last_request = (
        item["request"]
    )

    st.session_state.last_decision = (
        item["decision"]
    )

    st.session_state.last_result = (
        item["result"]
    )

    return event


def record_gemini_tool_results(
    tool_results
):
    """Record all firewall results produced during a Gemini turn."""

    events = []

    for item in tool_results:

        events.append(
            record_firewall_item(
                item
            )
        )

    return events


def build_tool_request(
    scenario,
    session_id,
    request_id,
    *,
    tool=None,
    arguments=None,
    intent=None,
    user_id=None,
    tainted=None,
    context_sources=None,
    source_type="dashboard",
):
    """Create a ToolRequest using the existing project schema."""

    return ToolRequest(

        request_id=request_id,

        session_id=session_id,

        user_id=(
            user_id
            or scenario["user_id"]
        ),

        tool=(
            tool
            or scenario["tool"]
        ),

        arguments=dict(
            (
                scenario.get(
                    "arguments",
                    {}
                )
                if arguments is None
                else arguments
            )
        ),

        intent=(
            scenario.get(
                "intent",
                scenario.get(
                    "name",
                    ""
                ),
            )
            if intent is None
            else intent
        ),

        context_sources=list(
            (
                scenario.get(
                    "context_sources",
                    []
                )
                if context_sources is None
                else context_sources
            )
        ),

        tainted=(
            scenario.get(
                "tainted",
                False
            )
            if tainted is None
            else tainted
        ),

        source_type=source_type,
    )


def execute_scenario(
    scenario,
    session_id,
):
    """
    Execute an existing evaluation scenario.

    One FirewallInterceptor is used for the entire scenario so
    trajectory, provenance and resource state are real.
    """

    firewall = FirewallInterceptor()

    items = []

    request_number = 1

    # ----------------------------------------------------------
    # Prelude actions
    # ----------------------------------------------------------

    for prelude in scenario.get(
        "prelude",
        []
    ):

        request = build_tool_request(

            prelude,

            session_id,

            f"{session_id}-PRE{request_number:03d}",

            tool=prelude["tool"],

            arguments=prelude.get(
                "arguments",
                {}
            ),

            intent=prelude.get(
                "intent",
                ""
            ),

            user_id=prelude["user_id"],

            tainted=prelude.get(
                "tainted",
                False
            ),

            context_sources=prelude.get(
                "context_sources",
                []
            ),
        )

        decision, result = (
            firewall.execute(
                request
            )
        )

        items.append(
            {
                "request": request,
                "decision": decision,
                "result": result,
            }
        )

        request_number += 1

    # ----------------------------------------------------------
    # Main request / repeated requests
    # ----------------------------------------------------------

    repeat = scenario.get(
        "repeat",
        1
    )

    for _ in range(repeat):

        request = build_tool_request(

            scenario,

            session_id,

            f"{session_id}-REQ{request_number:03d}",
        )

        decision, result = (
            firewall.execute(
                request
            )
        )

        items.append(
            {
                "request": request,
                "decision": decision,
                "result": result,
            }
        )

        request_number += 1

    return items


def record_scenario_items(
    items
):
    """Add scenario results to the dashboard event stream."""

    return [
        record_firewall_item(item)
        for item in items
    ]