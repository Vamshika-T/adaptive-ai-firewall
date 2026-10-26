
"""Regression tests for adaptive semantic auditor routing."""
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


def make_request(request_id, context_sources=None, tainted=False):
    return ToolRequest(
        request_id=request_id,
        session_id="auditor-routing-" + request_id,
        user_id="U001",
        tool="get_calendar_events",
        arguments={
            "user_email": "alice@company.com",
            "date": "2026-10-18",
        },
        context_sources=context_sources or [],
        tainted=tainted,
        timestamp=datetime.now(),
    )


def test_auditor_routing():
    fake_auditor = FakeSemanticAuditor()

    with patch.object(
        interceptor_module,
        "SemanticAuditor",
        return_value=fake_auditor,
    ):
        firewall = FirewallInterceptor()

    cases = [
        ("FAST", make_request("fast-001")),
        (
            "CONTEXTUAL",
            make_request(
                "contextual-001",
                context_sources=["document:DOC001"],
            ),
        ),
        ("DEEP", make_request("deep-001", tainted=True)),
    ]

    for expected_level, request in cases:
        calls_before = len(fake_auditor.calls)

        decision, _ = firewall.execute(
            request,
            original_task="Show my calendar events.",
        )

        new_calls = fake_auditor.calls[calls_before:]

        print(f"\n{expected_level} test:")
        print("Action:", decision.action)
        print("Actual inspection:", decision.inspection_level)
        print("Risk score:", decision.risk_score)
        print("Reasons:")
        for reason in decision.reasons:
            print(" -", reason)
        print("Auditor calls for this request:", len(new_calls))

        assert decision.inspection_level == expected_level, (
            f"Expected inspection level {expected_level}, "
            f"got {decision.inspection_level}"
        )

        audit_required = (
            decision.inspection_level == "DEEP"
            or "Model-based semantic audit required" in decision.checks
        )

        if audit_required:
            assert len(new_calls) == 1, (
                f"{expected_level} inspection required exactly one audit, "
                f"but observed {len(new_calls)} calls."
            )
            assert new_calls[0] == decision.inspection_level, (
                f"Expected auditor level {decision.inspection_level}, "
                f"got {new_calls[0]}."
            )
        else:
            assert not new_calls, (
                f"{expected_level} inspection did not require a model audit, "
                f"but the auditor was called: {new_calls}"
            )

        if decision.action in {"BLOCK", "ESCALATE"}:
            print(
                "Final decision stopped or escalated the request. "
                "Auditor routing was checked independently."
            )

    print("\nFinal auditor inspection levels:", fake_auditor.calls)
    print("Routing metrics:", firewall.get_routing_metrics())
    print("\nAUDITOR ROUTING TEST PASSED.")


def main():
    test_auditor_routing()


if __name__ == "__main__":
    main()
