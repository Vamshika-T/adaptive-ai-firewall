"""Regression tests proving adaptive routes skip expensive checks on FAST."""
from datetime import datetime
from unittest.mock import patch

import firewall.interceptor as interceptor_module
from firewall.interceptor import FirewallInterceptor
from firewall.semantic_auditor import SemanticAuditResult
from models.schemas import ToolRequest


class FakeSemanticAuditor:
    def __init__(self):
        self.calls = []

    def audit(self, request, original_task=None, inspection_level="DEEP"):
        self.calls.append(inspection_level)
        return SemanticAuditResult(
            task_aligned=True,
            action_appropriate=True,
            arguments_integrity=True,
            suspicious=False,
            risk_score=0,
            recommendation="ALLOW",
            reasons=["Offline test auditor approved the request."],
        )


def make_request(name, *, context_sources=None, tainted=False):
    return ToolRequest(
        request_id=f"adaptive-depth-{name}",
        session_id=f"adaptive-depth-session-{name}",
        user_id="U001",
        tool="get_calendar_events",
        arguments={"user_email": "alice@company.com", "date": "2026-10-18"},
        context_sources=context_sources or [],
        tainted=tainted,
        timestamp=datetime.now(),
    )


def main():
    fake_auditor = FakeSemanticAuditor()
    with patch.object(interceptor_module, "SemanticAuditor", return_value=fake_auditor):
        firewall = FirewallInterceptor()

    real_intent = interceptor_module.analyze_intent
    real_trajectory = interceptor_module.analyze_trajectory
    real_semantic = interceptor_module.analyze_semantic_risk

    cases = [
        ("FAST", make_request("fast")),
        ("CONTEXTUAL", make_request("contextual", context_sources=["document:DOC001"])),
        ("DEEP", make_request("deep", tainted=True)),
    ]

    with (
        patch.object(interceptor_module, "analyze_intent", wraps=real_intent) as intent_mock,
        patch.object(interceptor_module, "analyze_trajectory", wraps=real_trajectory) as trajectory_mock,
        patch.object(interceptor_module, "analyze_semantic_risk", wraps=real_semantic) as semantic_mock,
    ):
        for expected, request in cases:
            before = (
                intent_mock.call_count,
                trajectory_mock.call_count,
                semantic_mock.call_count,
                len(fake_auditor.calls),
            )
            decision, _ = firewall.execute(
                request,
                original_task="Show my calendar events.",
            )
            after = (
                intent_mock.call_count,
                trajectory_mock.call_count,
                semantic_mock.call_count,
                len(fake_auditor.calls),
            )

            assert decision.inspection_level == expected, (
                f"{request.request_id}: expected {expected}, got {decision.inspection_level}"
            )
            delta = tuple(a - b for a, b in zip(after, before))

            if expected == "FAST":
                assert delta == (0, 0, 0, 0), f"FAST ran expensive checks: {delta}"
                assert "Intent consistency" not in decision.checks
                assert "Action trajectory analysis" not in decision.checks
                assert "Semantic/STI inspection" not in decision.checks
            else:
                assert delta[:3] == (1, 1, 1), f"{expected} check counts were {delta}"
                assert "Intent consistency" in decision.checks
                assert "Action trajectory analysis" in decision.checks
                assert "Semantic/STI inspection" in decision.checks
                # Model auditing is required only for requests that remain
                # eligible for execution. A request already set to MONITOR,
                # ESCALATE, or BLOCK must not incur another model call.
                expected_audit_calls = int(decision.action == "ALLOW")
                assert delta[3] == expected_audit_calls, (
                    f"{expected} audit count should be {expected_audit_calls} "
                    f"for action {decision.action}; got {delta}"
                )

    print("ADAPTIVE INSPECTION DEPTH TEST PASSED")
    print("FAST skips intent, trajectory, semantic/STI, and model audit checks.")
    print("CONTEXTUAL and DEEP execute contextual checks and audit once.")


if __name__ == "__main__":
    main()
