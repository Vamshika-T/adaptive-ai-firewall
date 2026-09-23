from agent.gemini_agent import GeminiAgent
from agent.tool_definitions import TOOLS


agent = GeminiAgent(
    session_id="GEMINI001",
    user_id="U001"
)


response = agent.generate(
    user_prompt=(
        "What meetings does alice@company.com "
        "have on 2026-09-23?"
    ),
    tools=TOOLS,
    system_instruction=(
        "You are an enterprise assistant. "
        "Use available tools when they are required "
        "to answer the user's request. "
        "Do not invent tool results."
    )
)


print("\n=== GEMINI RESPONSE ===")

print(response)


print("\n=== FUNCTION CALLS ===")

calls = agent.extract_function_calls(
    response
)

for call in calls:
    print(call)


print("\n=== TOOL REQUESTS ===")

requests = agent.function_calls_to_requests(
    response,
    intent=(
        "Retrieve the user's calendar events "
        "for the requested date."
    )
)

for request in requests:
    print(request)