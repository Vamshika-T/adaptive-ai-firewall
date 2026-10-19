
from datetime import datetime
from unittest.mock import patch

from firewall.interceptor import FirewallInterceptor
from models.schemas import ToolRequest


class FakeAuditResult:
    def __init__(self):
        self.reasons = ["Test auditor invoked."]
        self.risk_score = 0
        self.recommendation = "ALLOW"
        self.suspicious = False


class FakeSemanticAuditor:
    def __init__(self):
        self.calls = []

    def audit(self, request, original_task=None, inspection_level=None):
        self.calls.append(inspection_level)
        return FakeAuditResult()


def make_request(
    request_id,
    context_sources=None,
    tainted=False,
):
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


def main():
    fake_auditor = FakeSemanticAuditor()

    with patch(
        "firewall.interceptor.SemanticAuditor",
        return_value=fake_auditor,
    ):
        firewall = FirewallInterceptor()

    cases = [
        (
            "FAST",
            make_request("fast-001"),
        ),
        (
            "CONTEXTUAL",
            make_request(
                "contextual-001",
                context_sources=["document:DOC001"],
            ),
        ),
        (
            "DEEP",
            make_request(
                "deep-001",
                tainted=True,
            ),
        ),
    ]

    for expected_level, request in cases:
        decision, _ = firewall.execute(
            request,
            original_task="Show my calendar events.",
        )

        print(f"\n{expected_level} test:")
        print("Action:", decision.action)
        print("Actual inspection:", decision.inspection_level)
        print("Risk score:", decision.risk_score)
        print("Reasons:")
        for reason in decision.reasons:
            print(" -", reason)
        print("Auditor calls so far:", len(fake_auditor.calls))

        # A request blocked or escalated by deterministic checks
        # may not reach the semantic auditor.
        if decision.action in {"BLOCK", "ESCALATE"}:
            print("Auditor not expected: deterministic decision stopped execution.")
            continue

        if decision.inspection_level == "FAST":
            assert not fake_auditor.calls or (
                fake_auditor.calls[-1] != "FAST"
            ), "FAST requests must not invoke the semantic auditor."

        elif decision.inspection_level in {"CONTEXTUAL", "DEEP"}:
            assert fake_auditor.calls[-1] == decision.inspection_level, (
                "Eligible contextual/deep request did not invoke the auditor."
            )

    print("\nFinal auditor inspection levels:", fake_auditor.calls)
    print("Routing metrics:", firewall.get_routing_metrics())
    print("\nAUDITOR ROUTING TEST COMPLETED.")


if __name__ == "__main__":
    main()
