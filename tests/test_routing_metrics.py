from datetime import datetime

from firewall.interceptor import FirewallInterceptor
from models.schemas import ToolRequest


def main():
    firewall = FirewallInterceptor()

    request = ToolRequest(
        request_id="routing-metrics-001",
        session_id="routing-metrics-session",
        user_id="U001",
        tool="get_calendar_events",
        arguments={
            "user_email": "alice@company.com"
        },
        timestamp=datetime.now(),
    )

    before = firewall.get_routing_metrics()

    print("Metrics before inspection:")
    print(before)

    decision = firewall.inspect(request)

    print("\nInspection decision:")
    print("Action:", decision.action)
    print("Inspection level:", decision.inspection_level)

    after = firewall.get_routing_metrics()

    print("\nMetrics after inspection:")
    print(after)

    # Exactly one preliminary and one final routing decision
    assert sum(after["preliminary"].values()) == (
        sum(before["preliminary"].values()) + 1
    ), "Preliminary routing counter did not increase exactly once."

    assert sum(after["final"].values()) == (
        sum(before["final"].values()) + 1
    ), "Final routing counter did not increase exactly once."

    # Each routing decision must use a valid inspection level
    valid_levels = {"FAST", "CONTEXTUAL", "DEEP"}

    assert decision.inspection_level in valid_levels, (
        f"Unexpected inspection level: {decision.inspection_level}"
    )

    assert sum(after["preliminary"].values()) == sum(
        after["final"].values()
    ), "Preliminary and final routing totals do not match."

    # inspect() alone must not invoke the semantic auditor.
    assert after["semantic_auditor_calls"] == (
        before["semantic_auditor_calls"]
    ), "Semantic auditor was called during inspect() unexpectedly."

    print("\nROUTING METRICS BEHAVIOR TEST PASSED.")


if __name__ == "__main__":
    main()