"""Fail-closed regression tests for malformed semantic-auditor results."""
from unittest.mock import patch

from firewall.interceptor import FirewallInterceptor
from firewall.semantic_auditor import SemanticAuditResult
from models.decisions import SecurityDecision
from models.schemas import ToolRequest


class FakeAuditor:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error

    def audit(self, request, original_task, inspection_level="DEEP"):
        if self.error:
            raise self.error
        return self.result


def make_request():
    return ToolRequest(
        request_id="AUDIT-FAIL-001",
        session_id="AUDIT-FAIL-SESSION",
        user_id="U001",
        tool="send_email_message",
        arguments={
            "sender": "alice@company.com",
            "recipient": "external@example.org",
            "subject": "Report",
            "body": "Sensitive report",
        },
    )


def valid_result(**overrides):
    fields = {
        "task_aligned": True,
        "action_appropriate": True,
        "arguments_integrity": True,
        "suspicious": False,
        "risk_score": 0.0,
        "recommendation": "ALLOW",
        "reasons": ["test auditor"],
    }
    fields.update(overrides)
    return fields


def run_case(auditor_result=None, auditor_error=None):
    firewall = FirewallInterceptor()
    firewall.begin_trusted_task(
        "AUDIT-FAIL-SESSION", "Send the approved report to the recipient."
    )
    firewall.semantic_auditor = FakeAuditor(auditor_result, auditor_error)
    # Force the request through the semantic-audit path while keeping this
    # test focused on the audit trust boundary.
    firewall.inspect = lambda request: SecurityDecision(
        request_id=request.request_id,
        action="ALLOW",
        risk_score=10,
        inspection_level="DEEP",
        reasons=[],
        checks=["test deterministic checks"],
    )
    request = make_request()
    with patch("firewall.interceptor.execute_tool", return_value={"sent": True}) as execute:
        decision, result = firewall.execute(
            request,
            original_task="Send the approved report to the recipient.",
        )
    return decision, result, execute


def test_auditor_exception_fails_closed():
    decision, result, execute = run_case(auditor_error=TimeoutError("timeout"))
    assert decision.action == "ESCALATE"
    assert result is None
    execute.assert_not_called()


def test_missing_fields_fail_closed():
    decision, result, execute = run_case(auditor_result={"recommendation": "ALLOW"})
    assert decision.action == "ESCALATE"
    assert result is None
    execute.assert_not_called()


def test_out_of_range_model_construct_result_fails_closed():
    # Deliberately bypass Pydantic validation to exercise the interceptor's
    # independent validation boundary.
    invalid = SemanticAuditResult.model_construct(**valid_result(risk_score=101.0))
    decision, result, execute = run_case(auditor_result=invalid)
    assert decision.action == "ESCALATE"
    assert result is None
    execute.assert_not_called()


def test_invalid_recommendation_fails_closed():
    invalid = SemanticAuditResult.model_construct(
        **valid_result(recommendation="APPROVE")
    )
    decision, result, execute = run_case(auditor_result=invalid)
    assert decision.action == "ESCALATE"
    assert result is None
    execute.assert_not_called()


def test_valid_allow_response_keeps_normal_path():
    decision, result, execute = run_case(
        auditor_result=SemanticAuditResult.model_validate(valid_result())
    )
    assert decision.action == "ALLOW"
    assert result == {"sent": True}
    execute.assert_called_once()


if __name__ == "__main__":
    for test in (
        test_auditor_exception_fails_closed,
        test_missing_fields_fail_closed,
        test_out_of_range_model_construct_result_fails_closed,
        test_invalid_recommendation_fails_closed,
        test_valid_allow_response_keeps_normal_path,
    ):
        test()
        print(f"PASS: {test.__name__}")
    print("AUDITOR FAILURE-PATH TESTS PASSED")
