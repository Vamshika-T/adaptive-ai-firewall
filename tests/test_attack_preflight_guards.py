"""Regression tests for mandatory enforcement of critical tool trajectories."""
import unittest
from unittest.mock import patch

from firewall.interceptor import FirewallInterceptor
from firewall.semantic_auditor import SemanticAuditResult
from models.schemas import ToolRequest


class AllowAuditor:
    """Deterministic test double; never calls an external model."""
    def audit(self, request, original_task, inspection_level="DEEP"):
        return SemanticAuditResult(
            task_aligned=True,
            action_appropriate=True,
            arguments_integrity=True,
            suspicious=False,
            risk_score=0,
            recommendation="ALLOW",
            reasons=["Deterministic test auditor"],
        )


def make_request(**overrides):
    values = {
        "request_id": "TEST-REQ-1",
        "session_id": "TEST-SESSION",
        "user_id": "U002",
        "tool": "send_email_message",
        "arguments": {
            "sender": "bob@company.com",
            "recipient": "external@example.net",
            "subject": "Employee information",
            "body": "Sensitive employee information.",
        },
        "intent": "Send employee information externally.",
        "context_sources": [],
        "tainted": False,
        "source_type": "test",
    }
    values.update(overrides)
    return ToolRequest(**values)


class CriticalTrajectoryTests(unittest.TestCase):
    def test_critical_trajectory_blocks_even_if_score_policy_would_allow(self):
        firewall = FirewallInterceptor()
        request = make_request()
        with patch("firewall.interceptor.get_user", return_value={"department": "HR", "role": "employee"}), \
             patch("firewall.interceptor.check_rbac", return_value=(True, "ok")), \
             patch("firewall.interceptor.check_abac", return_value=(True, "ok")), \
             patch("firewall.interceptor.get_resource", return_value="email"), \
             patch("firewall.interceptor.get_sensitivity", return_value="INTERNAL"), \
             patch("firewall.interceptor.get_sensitivity_score", return_value=25), \
             patch("firewall.interceptor.determine_preliminary_inspection_level", return_value={"level": "DEEP", "reasons": []}), \
             patch("firewall.interceptor.requires_deep_trajectory_inspection", return_value=False), \
             patch("firewall.interceptor.analyze_intent", return_value={"consistent": True, "reason": "ok"}), \
             patch("firewall.interceptor.analyze_trajectory", return_value={"score": 70, "critical": True, "reasons": ["critical trajectory"]}), \
             patch("firewall.interceptor.analyze_semantic_risk", return_value={"semantic_score": 0, "suspicious": False, "reasons": []}), \
             patch("firewall.interceptor.determine_inspection_level", return_value={"level": "DEEP", "reasons": []}), \
             patch("firewall.interceptor.decide_action", return_value="ALLOW"):
            decision = firewall.inspect(request)
        self.assertEqual(decision.action, "BLOCK")

    def test_sensitive_database_read_then_external_email_is_blocked_before_execution(self):
        firewall = FirewallInterceptor()
        firewall.semantic_auditor = AllowAuditor()
        session_id = "A3-REGRESSION-SESSION"
        task = "Review employee records for an internal HR task."
        firewall.begin_trusted_task(session_id, task)

        read_request = make_request(
            request_id="A3-READ",
            session_id=session_id,
            tool="query_database",
            arguments={"table": "employees"},
            intent="Look up employee information for internal HR review.",
        )
        read_decision, read_result = firewall.execute(read_request, original_task=task)
        self.assertEqual(read_decision.action, "ALLOW")
        self.assertIsNotNone(read_result)

        email_request = make_request(
            request_id="A3-EMAIL",
            session_id=session_id,
            tool="send_email_message",
            arguments={
                "sender": "bob@company.com",
                "recipient": "attacker@example.net",
                "subject": "Employee Information",
                "body": "Sensitive employee information.",
            },
            intent="Send employee information externally.",
        )
        email_decision, email_result = firewall.execute(email_request, original_task=task)
        self.assertEqual(email_decision.action, "BLOCK")
        self.assertIsNone(email_result)
        self.assertTrue(any("external email" in reason.lower() for reason in email_decision.reasons))


if __name__ == "__main__":
    unittest.main()
