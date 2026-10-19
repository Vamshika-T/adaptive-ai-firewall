"""Regression tests for generalized cross-tool workflow risk."""

from types import SimpleNamespace
from firewall.trajectory import analyze_trajectory


def action(request_id, tool, resource, decision="ALLOW"):
    return {"request_id": request_id, "tool": tool, "resource": resource, "decision": decision}


def request(tool, arguments=None, parents=None, context_sources=None):
    return SimpleNamespace(
        tool=tool,
        arguments=arguments or {},
        parent_artifact_ids=parents or [],
        context_sources=context_sources or [],
    )


def test_sensitive_read_then_external_write_is_flagged():
    result = analyze_trajectory(
        [action("1", "search_employee", "employees")],
        request("send_email_message", {"recipient": "attacker@example.net"}),
        "email", False,
    )
    assert result["critical"] is True
    assert result["score"] >= 70
    assert any("external email destination" in reason for reason in result["reasons"])


def test_non_external_write_after_sensitive_read_is_risk_not_automatic_critical():
    result = analyze_trajectory(
        [action("1", "query_database", "payroll")],
        request("update_crm_record", {"customer_id": "C001"}),
        "customers", False,
    )
    assert result["score"] >= 35
    assert result["critical"] is False


def test_blocked_history_does_not_count_as_completed_sensitive_read():
    result = analyze_trajectory(
        [action("1", "query_database", "payroll", decision="BLOCK")],
        request("send_email_message", {"recipient": "attacker@example.net"}),
        "email", False,
    )
    assert result["score"] == 0
    assert result["critical"] is False


def test_tainted_write_and_artifact_dependency_are_independent_signals():
    result = analyze_trajectory(
        [],
        request("update_crm_record", {"customer_id": "C001"}, parents=["S:artifact:1"], context_sources=["email:E1"]),
        "customers", True,
    )
    assert result["score"] >= 45
    assert len(result["reasons"]) >= 3


if __name__ == "__main__":
    test_sensitive_read_then_external_write_is_flagged()
    test_non_external_write_after_sensitive_read_is_risk_not_automatic_critical()
    test_blocked_history_does_not_count_as_completed_sensitive_read()
    test_tainted_write_and_artifact_dependency_are_independent_signals()
    print("GENERALIZED TRAJECTORY TESTS PASSED")
