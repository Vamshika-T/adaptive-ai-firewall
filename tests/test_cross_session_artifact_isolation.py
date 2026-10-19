
from unittest.mock import patch

from firewall.interceptor import FirewallInterceptor
from models.schemas import ToolRequest


def test_cross_session_parent_artifact_is_blocked():
    firewall = FirewallInterceptor()

    # Create a legitimate restricted artifact in Session A.
    parent = firewall.information_flow.record_artifact(
        session_id="SESSION_A",
        tool="query_database",
        resource="payroll",
        result={
            "employee_id": "U001",
            "salary": 145000,
        },
        sensitivity="RESTRICTED",
        provenance_sources=["database:payroll"],
    )

    # Attempt to reuse Session A's artifact from Session B.
    request = ToolRequest(
        request_id="CROSS-SESSION-REQ-001",
        session_id="SESSION_B",
        user_id="U001",
        tool="search_employee",
        arguments={"employee_id": "U001"},
        intent="Look up an employee.",
        parent_artifact_ids=[parent["artifact_id"]],
    )

    with patch(
        "firewall.interceptor.execute_tool"
    ) as mocked_execute_tool:
        decision, result = firewall.execute(
            request,
            original_task="Look up an employee.",
        )

    assert decision.action == "BLOCK", (
        f"Expected BLOCK, got {decision.action}: {decision.reasons}"
    )

    assert result is None
    mocked_execute_tool.assert_not_called()

    assert any(
        "Artifact lineage validation" in check
        for check in decision.checks
    )

    assert any(
        "unknown" in reason.lower()
        for reason in decision.reasons
    )

    print("PASSED: Parent artifact exists in Session A")
    print("PASSED: Session B cannot reuse Session A's artifact")
    print("PASSED: Enterprise tool was not executed")
    print("\nCROSS-SESSION ISOLATION TEST PASSED")


if __name__ == "__main__":
    test_cross_session_parent_artifact_is_blocked()
