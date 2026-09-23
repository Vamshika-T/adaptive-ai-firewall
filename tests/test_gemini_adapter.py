from agent.gemini_agent import GeminiAgent
from models.schemas import ToolRequest
from google.genai import types


agent = GeminiAgent(
    session_id="ADAPTER_TEST_001",
    user_id="U001"
)


# ---------------------------------------------------------
# Create a fake Gemini function-call response
# ---------------------------------------------------------

function_call = types.FunctionCall(
    id="call_001",
    name="get_calendar_events",
    args={
        "user_email": "alice@company.com",
        "date": "2026-09-23"
    }
)


response = types.GenerateContentResponse(
    candidates=[
        types.Candidate(
            content=types.Content(
                role="model",
                parts=[
                    types.Part(
                        function_call=function_call
                    )
                ]
            )
        )
    ]
)


# ---------------------------------------------------------
# Test function-call extraction
# ---------------------------------------------------------

calls = agent.extract_function_calls(response)

assert len(calls) == 1

assert calls[0]["id"] == "call_001"
assert calls[0]["name"] == "get_calendar_events"

assert calls[0]["arguments"] == {
    "user_email": "alice@company.com",
    "date": "2026-09-23"
}


# ---------------------------------------------------------
# Test ToolRequest conversion
# ---------------------------------------------------------

requests = agent.function_calls_to_requests(
    response,
    intent=(
        "Retrieve the user's calendar events "
        "for the requested date."
    )
)

assert len(requests) == 1

request = requests[0]

assert isinstance(request, ToolRequest)

assert request.session_id == "ADAPTER_TEST_001"
assert request.user_id == "U001"

assert request.tool == "get_calendar_events"

assert request.arguments == {
    "user_email": "alice@company.com",
    "date": "2026-09-23"
}

assert request.intent == (
    "Retrieve the user's calendar events "
    "for the requested date."
)

assert request.source_type == "gemini_agent"


print("\n========================================")
print("GEMINI ADAPTER TEST")
print("========================================")

print("\nFUNCTION CALL:")
print(calls[0])

print("\nTOOL REQUEST:")
print(request)

print("\n========================================")
print("GEMINI → TOOLREQUEST ADAPTER TEST PASSED")
print("========================================")