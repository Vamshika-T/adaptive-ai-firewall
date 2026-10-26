from datetime import datetime
from unittest.mock import patch

import firewall.interceptor as interceptor_module
from firewall.interceptor import FirewallInterceptor
from models.schemas import ToolRequest


def make_deep_request(number):
    return ToolRequest(
        request_id=f"budget-test-{number}",
        session_id="deep-budget-regression",
        user_id="U001",
        tool="send_email_message",
        arguments={
            "sender": "alice@company.com",
            "recipient": "bob@company.com",
            "subject": "Review",
            "body": "Review this.",
        },
        intent="Send this email for review.",
        tainted=True,
        timestamp=datetime.now(),
    )


def test_exhausted_deep_budget_skips_expensive_inspection():
    firewall = FirewallInterceptor()

    # Use the real inspection functions for the first ten requests.
    for number in range(1, 11):
        decision, _ = firewall.execute(make_deep_request(number))

        assert decision.inspection_level == "DEEP", (
            f"Request {number} did not take the DEEP route: "
            f"{decision.inspection_level}"
        )

    assert (
        firewall.resource_guard.session_deep_inspections.get(
            "deep-budget-regression", 0
        )
        == 10
    ), "The first ten requests should consume the deep-inspection budget."

    # The eleventh request must be rejected before expensive checks begin.
    with (
        patch.object(
            interceptor_module,
            "analyze_intent",
            wraps=interceptor_module.analyze_intent,
        ) as intent_mock,
        patch.object(
            interceptor_module,
            "analyze_trajectory",
            wraps=interceptor_module.analyze_trajectory,
        ) as trajectory_mock,
        patch.object(
            interceptor_module,
            "analyze_semantic_risk",
            wraps=interceptor_module.analyze_semantic_risk,
        ) as semantic_mock,
        patch.object(
            firewall.semantic_auditor,
            "audit",
            wraps=firewall.semantic_auditor.audit,
        ) as audit_mock,
    ):
        decision, result = firewall.execute(make_deep_request(11))

    assert decision.action == "BLOCK"
    assert decision.inspection_level == "DEEP"
    assert result is None
    assert any(
        "deep inspection budget" in reason.lower()
        for reason in decision.reasons
    )

    assert intent_mock.call_count == 0
    assert trajectory_mock.call_count == 0
    assert semantic_mock.call_count == 0
    assert audit_mock.call_count == 0

    assert (
        firewall.resource_guard.session_deep_inspections.get(
            "deep-budget-regression", 0
        )
        == 10
    ), "The rejected request must not consume additional deep budget."
