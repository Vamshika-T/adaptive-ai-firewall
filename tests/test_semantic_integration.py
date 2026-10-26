
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import Mock, patch

from firewall.interceptor import FirewallInterceptor
from models.schemas import ToolRequest
from firewall.semantic_auditor import SemanticAuditResult


class FakeAuditor:
    def __init__(self, recommendation, risk_score=0):
        self.recommendation = recommendation
        self.risk_score = risk_score
        self.calls = []

    def audit(
        self,
        request,
        original_task=None,
        inspection_level=None,
    ):
        self.calls.append(inspection_level)

        return SemanticAuditResult(
            task_aligned=self.recommendation == "ALLOW",
            action_appropriate=self.recommendation == "ALLOW",
            arguments_integrity=self.recommendation == "ALLOW",
            recommendation=self.recommendation,
            risk_score=self.risk_score,
            reasons=["Fake auditor used in integration test."],
            suspicious=self.recommendation in {"BLOCK", "ESCALATE"},
        )



def make_decision(
    action="ALLOW",
    risk_score=10,
    level="CONTEXTUAL",
    audit_required=False,
):
    checks = ["Initial security checks"]

    if audit_required:
        checks.append("Model-based semantic audit required")

    return SimpleNamespace(
        request_id="integration-test-001",
        action=action,
        risk_score=risk_score,
        inspection_level=level,
        reasons=["Initial firewall decision."],
        checks=checks,
    )



def make_request():
    return ToolRequest(
        request_id="integration-test-001",
        session_id="integration-test-session",
        user_id="U001",
        tool="search_employee",
        arguments={"employee_id": "U001"},
        intent="Look up employee U001.",
        context_sources=[],
        tainted=False,
        timestamp=datetime.now(),
    )


def make_firewall(decision, auditor):
    firewall = FirewallInterceptor()

    # Isolate execute() from unrelated authorization and routing
    # behavior so these tests focus on auditor integration.
    firewall.inspect = Mock(return_value=decision)
    firewall.semantic_auditor = auditor
    firewall.add_history = Mock()

    return firewall


def test_auditor_block_prevents_tool_execution():
    auditor = FakeAuditor("BLOCK", 95)
    firewall = make_firewall(
        make_decision(
            action="ALLOW",
            audit_required=True,
        ),
        auditor,
    )

    with patch(
        "firewall.interceptor.execute_tool"
    ) as execute_tool:
        decision, result = firewall.execute(
            make_request(),
            original_task="Look up employee U001.",
        )

    assert decision.action == "BLOCK"
    assert decision.risk_score >= 85
    assert result is None
    execute_tool.assert_not_called()


def test_auditor_escalate_prevents_tool_execution():
    auditor = FakeAuditor("ESCALATE", 60)
    firewall = make_firewall(
        make_decision(
            action="ALLOW",
            audit_required=True,
        ),
        auditor,
    )

    with patch(
        "firewall.interceptor.execute_tool"
    ) as execute_tool:
        decision, result = firewall.execute(
            make_request(),
            original_task="Look up employee U001.",
        )

    assert decision.action == "ESCALATE"
    assert decision.risk_score >= 60
    assert result is None
    execute_tool.assert_not_called()


def test_auditor_allow_does_not_lower_existing_risk():
    auditor = FakeAuditor("ALLOW", 5)
    firewall = make_firewall(
        make_decision(
            action="MONITOR",
            risk_score=10,
        ),
        auditor,
    )

    with patch(
        "firewall.interceptor.execute_tool",
        return_value={"status": "ok"},
    ) as execute_tool:
        decision, result = firewall.execute(
            make_request(),
            original_task="Look up employee U001.",
        )

    assert decision.action == "MONITOR"
    assert decision.risk_score >= 10

    # MONITOR requires approval under the current enforcement
    # policy, so an ALLOW recommendation cannot authorize execution.
    assert result is None
    execute_tool.assert_not_called()


def test_fast_request_skips_model_auditor():
    auditor = FakeAuditor("BLOCK", 95)
    firewall = make_firewall(
        make_decision(
            action="ALLOW",
            risk_score=5,
            level="FAST",
        ),
        auditor,
    )

    with patch(
        "firewall.interceptor.execute_tool",
        return_value={"status": "ok"},
    ) as execute_tool:
        decision, result = firewall.execute(
            make_request(),
            original_task="Look up employee U001.",
        )

    assert decision.action == "ALLOW"
    assert decision.inspection_level == "FAST"
    assert result == {"status": "ok"}
    assert auditor.calls == []
    execute_tool.assert_called_once()


def test_contextual_request_invokes_model_auditor():
    auditor = FakeAuditor("ALLOW", 5)
    firewall = make_firewall(
        make_decision(
            action="ALLOW",
            risk_score=10,
            level="CONTEXTUAL",
            audit_required=True,
        ),
        auditor,
    )

    with patch(
        "firewall.interceptor.execute_tool",
        return_value={"status": "ok"},
    ) as execute_tool:
        decision, result = firewall.execute(
            make_request(),
            original_task="Look up employee U001.",
        )

    assert auditor.calls == ["CONTEXTUAL"]
    assert "Model-based semantic security audit" in decision.checks
    assert decision.risk_score >= 10
    assert decision.action == "ALLOW"
    assert result == {"status": "ok"}
    execute_tool.assert_called_once()


def test_deep_request_invokes_model_auditor():
    auditor = FakeAuditor("ALLOW", 5)
    firewall = make_firewall(
        make_decision(
            action="ALLOW",
            risk_score=20,
            level="DEEP",
        ),
        auditor,
    )

    with patch(
        "firewall.interceptor.execute_tool",
        return_value={"status": "ok"},
    ) as execute_tool:
        decision, result = firewall.execute(
            make_request(),
            original_task="Look up employee U001.",
        )

    assert auditor.calls == ["DEEP"]
    assert "Model-based semantic security audit" in decision.checks
    assert decision.risk_score >= 20
    assert decision.action == "ALLOW"
    assert result == {"status": "ok"}
    execute_tool.assert_called_once()


def main():
    tests = [
        test_auditor_block_prevents_tool_execution,
        test_auditor_escalate_prevents_tool_execution,
        test_auditor_allow_does_not_lower_existing_risk,
        test_fast_request_skips_model_auditor,
        test_contextual_request_invokes_model_auditor,
        test_deep_request_invokes_model_auditor,
    ]

    for test in tests:
        test()
        print(f"PASSED: {test.__name__}")

    print("\nALL SEMANTIC INTEGRATION TESTS PASSED.")


if __name__ == "__main__":
    main()
