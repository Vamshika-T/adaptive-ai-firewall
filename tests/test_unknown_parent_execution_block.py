
from unittest.mock import patch

from firewall.interceptor import FirewallInterceptor
from models.schemas import ToolRequest


def test_unknown_parent_blocks_tool_execution():
    firewall = FirewallInterceptor()

    request = ToolRequest(
        request_id="UNKNOWN-PARENT-REQ-001",
        session_id="UNKNOWN-PARENT-SESSION-001",
        user_id="U001",
        tool="search_employee",
        arguments={
            "employee_id": "U001",
        },
        intent="Look up my employee record.",
        parent_artifact_ids=[
            "UNKNOWN-PARENT-SESSION-001:artifact:9999"
        ],
    )

    with patch(
        "firewall.interceptor.execute_tool"
    ) as mocked_execute_tool:
        decision, result = firewall.execute(
            request,
            original_task="Look up my employee record.",
        )

    assert decision.action == "BLOCK", (
        f"Expected BLOCK, got {decision.action}. "
        f"Reasons: {decision.reasons}"
    )

    assert decision.risk_score >= 100, (
        f"Expected risk score >= 100, got {decision.risk_score}"
    )

    assert result is None

    mocked_execute_tool.assert_not_called()

    assert any(
        "Artifact lineage validation" in check
        for check in decision.checks
    ), f"Lineage validation was not recorded: {decision.checks}"

    assert any(
        "unknown" in reason.lower()
        for reason in decision.reasons
    ), f"Unknown-parent reason missing: {decision.reasons}"

    print("PASSED: Fabricated parent ID rejected")
    print("PASSED: Request blocked")
    print("PASSED: Enterprise tool was not executed")
    print("PASSED: Lineage validation recorded")

    print("\nUNKNOWN-PARENT EXECUTION TEST PASSED")


if __name__ == "__main__":
    test_unknown_parent_blocks_tool_execution()
