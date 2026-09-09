from agent.agent import DeterministicAgent
from firewall.interceptor import FirewallInterceptor


agent = DeterministicAgent(
    session_id="FIREWALL_TEST_001",
    user_id="U001"
)

firewall = FirewallInterceptor()


request = agent.create_request(
    "search_employee",
    {
        "employee_id": "U001"
    }
)


decision, result = firewall.execute(request)


print("TOOL REQUEST:")
print(request)

print("\nSECURITY DECISION:")
print(decision)

print("\nTOOL RESULT:")
print(result)


assert decision.request_id == request.request_id
assert decision.action == "ALLOW"
assert result is not None