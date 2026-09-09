from agent.agent import DeterministicAgent


agent = DeterministicAgent(
    session_id="SESSION001",
    user_id="U001"
)


request, result = agent.execute(
    "search_employee",
    {
        "employee_id": "U001"
    }
)


print("TOOL REQUEST:")
print(request)

print("\nRESULT:")
print(result)