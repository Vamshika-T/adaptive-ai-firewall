from agent.agent import Agent
from storage.state import SessionState
from tools.registry import ToolRegistry


def read_email_inbox(user_email):
    return {
        "tool": "read_email_inbox",
        "user_email": user_email,
        "message": "Test email"
    }


def query_database(table):
    return {
        "tool": "query_database",
        "table": table,
        "result": "Test database result"
    }


def send_email_message(to, message):
    return {
        "tool": "send_email_message",
        "to": to,
        "message": message
    }


registry = ToolRegistry()

registry.register(
    "read_email_inbox",
    read_email_inbox
)

registry.register(
    "query_database",
    query_database
)

registry.register(
    "send_email_message",
    send_email_message
)


agent = Agent(registry)

session = SessionState(
    session_id="SESSION001",
    user_id="U001"
)


request1 = agent.create_request(
    session_id="SESSION001",
    user_id="U001",
    tool="read_email_inbox",
    arguments={
        "user_email": "alice@company.com"
    }
)

result1 = agent.execute_request(
    request1,
    session
)


request2 = agent.create_request(
    session_id="SESSION001",
    user_id="U001",
    tool="query_database",
    arguments={
        "table": "payroll"
    }
)

result2 = agent.execute_request(
    request2,
    session
)


request3 = agent.create_request(
    session_id="SESSION001",
    user_id="U001",
    tool="send_email_message",
    arguments={
        "to": "external@gmail.com",
        "message": "Test message"
    }
)

result3 = agent.execute_request(
    request3,
    session
)


print("RESULT 1:")
print(result1)

print("\nRESULT 2:")
print(result2)

print("\nRESULT 3:")
print(result3)

print("\nACTION HISTORY:")

for action in session.get_history():
    print(action)