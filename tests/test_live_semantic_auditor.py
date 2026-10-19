
import os
import sys

from firewall.semantic_auditor import SemanticAuditor
from models.schemas import ToolRequest


def main():
    if not os.getenv("GEMINI_API_KEY"):
        print("LIVE TEST FAILED: GEMINI_API_KEY is not set.")
        print("Set your key in the terminal and retry.")
        sys.exit(1)

    auditor = SemanticAuditor()

    if auditor.client is None:
        print("LIVE TEST FAILED: Gemini client initialization failed.")
        print(auditor.initialization_error)
        sys.exit(1)

    request = ToolRequest(
        request_id="LIVE_AUDIT_TEST-REQ001",
        session_id="LIVE_AUDIT_TEST",
        user_id="U001",
        tool="get_calendar_events",
        arguments={"user_email": "alice@company.com"},
        intent="Show my calendar events.",
        context_sources=[],
        tainted=False,
        source_type="test",
        function_call_id=None,
    )

    original_task = "Show my calendar events."

    print("Calling the real Gemini semantic auditor...")

    result = auditor.audit(
        request=request,
        original_task=original_task,
        inspection_level="DEEP",
    )

    print("\nAUDIT RESULT")
    print("Task aligned:", result.task_aligned)
    print("Action appropriate:", result.action_appropriate)
    print("Arguments integrity:", result.arguments_integrity)
    print("Suspicious:", result.suspicious)
    print("Risk score:", result.risk_score)
    print("Recommendation:", result.recommendation)
    print("Reasons:", result.reasons)

    if any(
        reason == "Semantic audit could not safely complete"
        for reason in result.reasons
    ):
        print("\nLIVE TEST FAILED: The auditor returned its failure result.")
        sys.exit(1)

    print("\nLIVE GEMINI AUDITOR TEST PASSED.")
    print("A real Gemini response was received and validated.")
    print("Review the recommendation above; passing this test")
    print("does not by itself prove the auditor detects every attack.")


if __name__ == "__main__":
    main()
