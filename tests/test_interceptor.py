from agent.agent import DeterministicAgent
from firewall.interceptor import FirewallInterceptor
from firewall.semantic_auditor import SemanticAuditResult


# Create the test agent
agent = DeterministicAgent(
    session_id="FIREWALL_TEST_001",
    user_id="U001"
)


# Mock semantic auditor for regression testing
class FakeSemanticAuditor:
    def audit(
        self,
        request,
        original_task,
        inspection_level="DEEP",
    ):
        return SemanticAuditResult(
            task_aligned=True,
            action_appropriate=True,
            arguments_integrity=True,
            suspicious=False,
            risk_score=0,
            recommendation="ALLOW",
            reasons=[
                "Fake auditor used in regression test"
            ],
        )


# Create firewall with the mock auditor
def make_test_firewall():
    firewall = FirewallInterceptor()
    firewall.semantic_auditor = FakeSemanticAuditor()
    return firewall


firewall = make_test_firewall()


# Create a test request
request = agent.create_request(
    "search_employee",
    {
        "employee_id": "U001"
    }
)


# Execute through the firewall
decision, result = firewall.execute(
    request,
    original_task="Look up employee U001.",
)


# Display results
print("TOOL REQUEST:")
print(request)

print("\nSECURITY DECISION:")
print(decision)

print("\nTOOL RESULT:")
print(result)


# Assertions
assert decision.request_id == request.request_id, (
    "Request ID mismatch"
)

assert decision.action == "ALLOW", (
    f"Expected ALLOW, got {decision.action}"
)

assert result is not None, (
    "Expected a tool result, got None"
)

print("\nINTERCEPTOR TEST PASSED")
