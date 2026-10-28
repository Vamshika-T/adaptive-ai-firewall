"""Regression tests for destination-specific sensitive-write policies."""
from unittest.mock import patch

from firewall.information_flow import InformationFlowTracker


class AllowAuditor:
    def audit(self, request, original_task, inspection_level="DEEP"):
        from firewall.semantic_auditor import SemanticAuditResult
        return SemanticAuditResult(
            task_aligned=True,
            action_appropriate=True,
            arguments_integrity=True,
            suspicious=False,
            risk_score=0,
            recommendation="ALLOW",
            reasons=["Test auditor"],
        )


def test_restricted_parent_blocks_crm_write_even_when_transformed():
    tracker = InformationFlowTracker()
    parent = tracker.record_artifact(
        session_id="FLOW-CRM-1",
        tool="query_database",
        resource="payroll",
        result={"employee_id": "EMP99123", "salary": 125000},
        sensitivity="RESTRICTED",
        provenance_sources=["database:payroll"],
    )
    result = tracker.check_sensitive_write(
        session_id="FLOW-CRM-1",
        tool="update_crm_record",
        arguments={"customer_id": "C001", "field": "notes", "value": "compensation review completed"},
        parent_artifact_ids=[parent["artifact_id"]],
    )
    assert result["allowed"] is False
    assert result["matched_artifacts"][0]["sensitivity"] == "RESTRICTED"


def test_confidential_parent_can_flow_to_internal_crm():
    tracker = InformationFlowTracker()
    parent = tracker.record_artifact(
        session_id="FLOW-CRM-2",
        tool="search_customer",
        resource="customers",
        result={"customer_id": "C002", "account_note": "priority account"},
        sensitivity="CONFIDENTIAL",
        provenance_sources=["crm:customer:C002"],
    )
    result = tracker.check_sensitive_write(
        session_id="FLOW-CRM-2",
        tool="update_crm_record",
        arguments={"customer_id": "C002", "field": "notes", "value": "priority account"},
        parent_artifact_ids=[parent["artifact_id"]],
    )
    assert result["allowed"] is True


def test_unknown_parent_blocks_sensitive_write():
    tracker = InformationFlowTracker()
    result = tracker.check_sensitive_write(
        session_id="FLOW-CRM-3",
        tool="update_crm_record",
        arguments={"customer_id": "C003", "field": "notes", "value": "updated"},
        parent_artifact_ids=["OTHER-SESSION:artifact:99"],
    )
    assert result["allowed"] is False
    assert "unknown parent" in result["reason"].casefold()


def test_interceptor_does_not_execute_restricted_crm_write():
    from firewall.interceptor import FirewallInterceptor
    from models.schemas import ToolRequest
    firewall = FirewallInterceptor()
    firewall.semantic_auditor = AllowAuditor()
    session_id = "FLOW-CRM-E2E"
    firewall.begin_trusted_task(session_id, "Update the customer's CRM note.")
    parent = firewall.information_flow.record_artifact(
        session_id=session_id,
        tool="query_database",
        resource="payroll",
        result={"employee_id": "EMP77441", "salary": 99000},
        sensitivity="RESTRICTED",
        provenance_sources=["database:payroll"],
    )
    request = ToolRequest(
        request_id="FLOW-CRM-REQ-1",
        session_id=session_id,
        user_id="U001",
        tool="update_crm_record",
        arguments={"customer_id": "C001", "field": "notes", "value": "review completed"},
        parent_artifact_ids=[parent["artifact_id"]],
        intent="Update CRM note",
    )
    with patch("firewall.interceptor.execute_tool") as execute_tool:
        decision, result = firewall.execute(
            request,
            original_task="Update the customer's CRM note.",
        )
    assert decision.action == "BLOCK"
    assert result is None
    execute_tool.assert_not_called()

def test_unknown_parent_blocks_before_execution_when_flow_policy_disabled():
    from firewall.interceptor import FirewallInterceptor
    from models.schemas import ToolRequest

    firewall = FirewallInterceptor(enable_information_flow=False)
    firewall.semantic_auditor = AllowAuditor()

    session_id = "FLOW-INVALID-PARENT"
    original_task = "Update the customer's CRM note."
    firewall.begin_trusted_task(session_id, original_task)

    request = ToolRequest(
        request_id="FLOW-INVALID-PARENT-REQ",
        session_id=session_id,
        user_id="U001",
        tool="update_crm_record",
        arguments={
            "customer_id": "C005",
            "field": "notes",
            "value": "routine follow-up",
        },
        parent_artifact_ids=["UNKNOWN-SESSION:artifact:99"],
        intent="Update CRM note",
    )

    with patch(
        "firewall.interceptor.check_rbac",
        return_value=(True, "authorized"),
    ), patch(
        "firewall.interceptor.check_abac",
        return_value=(True, "authorized"),
    ), patch("firewall.interceptor.execute_tool") as execute_tool:
        decision, result = firewall.execute(
            request,
            original_task=original_task,
        )
    assert decision.action == "BLOCK"
    assert result is None
    assert any(
        "unknown parent" in reason.casefold()
        or "parent artifact" in reason.casefold()
        for reason in decision.reasons
    )
    execute_tool.assert_not_called()

def test_unrelated_crm_write_remains_allowed_by_flow_policy():
    tracker = InformationFlowTracker()
    result = tracker.check_sensitive_write(
        session_id="FLOW-CRM-4",
        tool="update_crm_record",
        arguments={"customer_id": "C004", "field": "status", "value": "active"},
        parent_artifact_ids=[],
    )
    assert result["allowed"] is True


if __name__ == "__main__":
    tests = [
        test_restricted_parent_blocks_crm_write_even_when_transformed,
        test_confidential_parent_can_flow_to_internal_crm,
        test_unknown_parent_blocks_sensitive_write,
        test_interceptor_does_not_execute_restricted_crm_write,
        test_unrelated_crm_write_remains_allowed_by_flow_policy,
    ]
    for test in tests:
        test()
        print(f"PASS: {test.__name__}")
    print("INFORMATION-FLOW WRITE-POLICY TESTS PASSED")
