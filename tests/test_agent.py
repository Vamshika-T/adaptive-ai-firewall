from agent.agent import Agent
from storage.state import SessionState
from tools.registry import ToolRegistry


def get_employee(name):
    return {
        "name": name,
        "department": "Engineering"
    }


registry = ToolRegistry()

registry.register(
    "get_employee",
    get_employee
)


agent = Agent(registry)

session = SessionState(
    session_id="SESSION001",
    user_id="U001"
)


request = agent.create_request(
    session_id="SESSION001",
    user_id="U001",
    tool="get_employee",
    arguments={
        "name": "Alice"
    }
)


print("Tool Request:")
print(request)

print("\nExecuting request:")

result = agent.execute_request(
    request,
    session
)

print(result)

print("\nSession History:")

for action in session.get_history():
    print(action)