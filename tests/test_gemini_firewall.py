from agent.gemini_agent import GeminiAgent
from agent.tool_definitions import TOOLS
from firewall.interceptor import FirewallInterceptor


# -----------------------------------------------------
# 1. Create Gemini agent
# -----------------------------------------------------

agent = GeminiAgent(
    session_id="GEMINI001",
    user_id="U001"
)


# -----------------------------------------------------
# 2. Create firewall
# -----------------------------------------------------

firewall = FirewallInterceptor()


# -----------------------------------------------------
# 3. Ask Gemini to perform an enterprise action
# -----------------------------------------------------

response = agent.generate(
    user_prompt=(
        "What meetings does alice@company.com "
        "have on 2026-09-23?"
    ),
    tools=TOOLS,
    system_instruction=(
        "You are an enterprise assistant. "
        "Use available tools when required. "
        "Do not invent tool results."
    )
)


# -----------------------------------------------------
# 4. Convert Gemini function calls to ToolRequests
# -----------------------------------------------------

requests = agent.function_calls_to_requests(
    response,
    intent=(
        "Retrieve the user's calendar events "
        "for the requested date."
    )
)


print("\n=== GEMINI TOOL REQUESTS ===")

for request in requests:
    print(request)


# -----------------------------------------------------
# 5. Send each request through the firewall
# -----------------------------------------------------

print("\n=== FIREWALL RESULTS ===")

for request in requests:

    decision, result = firewall.execute(
        request
    )

    print("\nTool:", request.tool)
    print("Decision:", decision.action)
    print("Risk:", decision.risk_score)
    print("Reasons:", decision.reasons)
    print("Result:", result)