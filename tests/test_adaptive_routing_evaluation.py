
from datetime import datetime
from time import perf_counter
from unittest.mock import patch

from firewall.interceptor import FirewallInterceptor
from firewall.semantic_auditor import SemanticAuditResult
from models.schemas import ToolRequest


class FakeSemanticAuditor:
    def __init__(self):
        self.calls = []

    def audit(self, request, original_task=None, inspection_level=None):
        self.calls.append(inspection_level)
        return SemanticAuditResult(
            task_aligned=True,
            action_appropriate=True,
            arguments_integrity=True,
            suspicious=False,
            risk_score=0,
            recommendation="ALLOW",
            reasons=["Test auditor invoked."],
        )


def make_request(request_id, context_sources=None, tainted=False):
    return ToolRequest(
        request_id=request_id,
        session_id="evaluation-" + request_id,
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


def main():
    fake_auditor = FakeSemanticAuditor()

    with patch(
        "firewall.interceptor.SemanticAuditor",
        return_value=fake_auditor,
    ):
        firewall = FirewallInterceptor()

    cases = [
        ("FAST", make_request("eval-fast-001")),
        (
            "CONTEXTUAL",
            make_request(
                "eval-contextual-001",
                context_sources=["document:DOC001"],
            ),
        ),
        (
            "DEEP",
            make_request("eval-deep-001", tainted=True),
        ),
    ]

    total_elapsed = 0
    results = []

    print("\nADAPTIVE ROUTING EVALUATION")
    print("=" * 55)

    for expected_level, request in cases:
        calls_before = len(fake_auditor.calls)
        start = perf_counter()

        decision, _ = firewall.execute(
            request,
            original_task="Show my calendar events.",
        )

        elapsed = perf_counter() - start
        total_elapsed += elapsed

        actual_level = decision.inspection_level
        auditor_calls = len(fake_auditor.calls) - calls_before

        print(f"\nExpected level: {expected_level}")
        print(f"Actual level:   {actual_level}")
        print(f"Action:         {decision.action}")
        print(f"Risk score:     {decision.risk_score}")
        print(f"Auditor calls:  {auditor_calls}")
        print(f"Elapsed time:   {elapsed * 1000:.3f} ms")

        # Verify that the expected routing level was selected.
        assert actual_level == expected_level, (
            f"Expected {expected_level}, got {actual_level}"
        )

        # FAST must skip the semantic auditor.
        if expected_level == "FAST":
            assert auditor_calls == 0, (
                "FAST unexpectedly invoked the semantic auditor."
            )
        else:
            assert auditor_calls == 1, (
                f"{expected_level} should invoke the auditor once."
            )

        results.append({
            "level": actual_level,
            "action": str(decision.action),
            "elapsed": elapsed,
        })

    metrics = firewall.get_routing_metrics()

    print("\n" + "=" * 55)
    print("SUMMARY")
    print(f"Requests evaluated: {len(results)}")
    print(f"Total elapsed time: {total_elapsed * 1000:.3f} ms")
    print(
        "Average elapsed time: "
        f"{(total_elapsed / len(results)) * 1000:.3f} ms"
    )
    print(f"Routing metrics: {metrics}")
    print(f"Auditor call sequence: {fake_auditor.calls}")

    assert metrics["final"] == {
        "FAST": 1,
        "CONTEXTUAL": 1,
        "DEEP": 1,
    }
    assert metrics["semantic_auditor_calls"] == 2
    assert fake_auditor.calls == ["CONTEXTUAL", "DEEP"]

    print("\nADAPTIVE ROUTING EVALUATION PASSED.")


if __name__ == "__main__":
    main()
