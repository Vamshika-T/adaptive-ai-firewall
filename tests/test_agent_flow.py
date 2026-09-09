from agent.agent import DeterministicAgent


agent = DeterministicAgent(
    session_id="SESSION001",
    user_id="U001"
)


request1, result1 = agent.execute(
    "read_email_inbox",
    {
        "user_email": "alice@company.com"
    }
)


request2, result2 = agent.execute(
    "query_database",
    {
        "table": "payroll"
    }
)


request3, result3 = agent.execute(
    "send_email_message",
    {
        "sender": "alice@company.com",
        "recipient": "external@gmail.com",
        "subject": "Test",
        "body": "Test message"
    }
)


print("REQUEST 1:")
print(request1)

print("\nRESULT 1:")
print(result1)

print("\nREQUEST 2:")
print(request2)

print("\nRESULT 2:")
print(result2)

print("\nREQUEST 3:")
print(request3)

print("\nRESULT 3:")
print(result3)

