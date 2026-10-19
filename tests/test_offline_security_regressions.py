"""Offline regressions for fail-closed auditing and outbound confidentiality."""
from unittest.mock import patch

from firewall.interceptor import FirewallInterceptor
from firewall.semantic_auditor import SemanticAuditResult
from models.decisions import SecurityDecision
from models.schemas import ToolRequest


class AllowAuditor:
    """Deterministic stand-in; these tests must never call the Gemini API."""

    def audit(self, request, original_task, inspection_level="DEEP"):
        return SemanticAuditResult(
            task_aligned=True,
            action_appropriate=True,
            arguments_integrity=True,
            suspicious=False,
            risk_score=0,
            recommendation="ALLOW",
            reasons=["Deterministic test auditor approved the action"],
        )


def _deep_allow_decision(request):
    return SecurityDecision(
        request_id=request.request_id,
        action="ALLOW",
        risk_score=5,
        inspection_level="DEEP",
        reasons=[],
        checks=["Deterministic test inspection"],
    )


def test_explicit_confidential_external_email_is_blocked_before_execution():
    firewall = FirewallInterceptor(semantic_auditor=AllowAuditor())
    firewall.inspect = _deep_allow_decision

    request = ToolRequest(
        request_id="REGRESSION-A4-CONFIDENTIAL",
        session_id="REGRESSION-A4-SESSION",
        user_id="U001",
        tool="send_email_message",
        arguments={
            "sender": "alice@company.com",
            "recipient": "external@example.com",
            "subject": "Confidential Information",
            "body": "[Confidential company information]",
        },
        intent="Send the requested email.",
    )

    with patch("firewall.interceptor.execute_tool") as execute_tool:
        decision, result = firewall.execute(
            request,
            original_task="Send the requested email.",
        )

    assert decision.action == "BLOCK"
    assert result is None
    assert any("confidential" in reason.lower() for reason in decision.reasons)
    execute_tool.assert_not_called()


def test_missing_trusted_task_is_rejected_by_semantic_auditor():
    """A missing task must not be treated as approval or trigger a tool call."""
    from firewall.semantic_auditor import SemanticAuditor

    auditor = SemanticAuditor(client=object())
    request = ToolRequest(
        request_id="REGRESSION-MISSING-TASK",
        session_id="REGRESSION-MISSING-TASK-SESSION",
        user_id="U001",
        tool="query_database",
        arguments={"table": "payroll"},
    )

    result = auditor.audit(request=request, original_task="")

    assert result.recommendation == "ESCALATE"
    assert result.risk_score == 100
