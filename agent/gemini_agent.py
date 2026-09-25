import os

from google import genai
from google.genai import types,errors

from models.schemas import ToolRequest


class GeminiAgent:
    def __init__(self, session_id, user_id, model="gemini-3.5-flash-lite"):
        self.session_id = session_id
        self.user_id = user_id
        self.model = model
        self.request_counter = 0

        api_key = os.getenv("GEMINI_API_KEY")

        if not api_key:
            raise RuntimeError(
                "GEMINI_API_KEY environment variable is not set."
            )

        self.client = genai.Client(api_key=api_key)

    def create_request(
        self,
        tool,
        arguments=None,
        intent="",
        function_call_id=None
    ):
        self.request_counter += 1

        return ToolRequest(
            request_id=f"{self.session_id}-REQ{self.request_counter:03d}",
            session_id=self.session_id,
            user_id=self.user_id,
            tool=tool,
            arguments=dict(arguments or {}),
            intent=intent,
            source_type="gemini_agent",
            function_call_id=function_call_id
        )

    def generate(
        self,
        user_prompt,
        tools,
        system_instruction=None
    ):
        config = types.GenerateContentConfig(
            tools=[
                types.Tool(
                    function_declarations=tools
                )
            ],
            automatic_function_calling={
                "disable": True
            }
        )

        if system_instruction:
            config.system_instruction = system_instruction

        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=user_prompt,
                config=config
            )
            return response

        except errors.APIError as error:
            print(
                f"GEMINI API ERROR [{getattr(error, 'code', 'UNKNOWN')}]: "
                f"{getattr(error, 'message', str(error))}"
            )
            return None

        return response

    def extract_function_calls(self, response):
        calls = []

        for candidate in response.candidates:

            if not candidate.content:
                continue

            for part in candidate.content.parts:

                if not part.function_call:
                    continue

                function_call = part.function_call

                calls.append({
                    "id": function_call.id,
                    "name": function_call.name,
                    "arguments": dict(
                        function_call.args or {}
                    )
                })

        return calls

    def function_calls_to_requests(
        self,
        response,
        intent=""
    ):
        calls = self.extract_function_calls(response)

        requests = []

        for call in calls:

            request = self.create_request(
                tool=call["name"],
                arguments=call["arguments"],
                intent=intent,
                function_call_id=call["id"]
            )

            requests.append(request)

        return requests

    def run_secured(
        self,
        user_prompt,
        tools,
        firewall,
        system_instruction=None,
        intent="",
        conversation_history=None
    ):
        config = types.GenerateContentConfig(
            tools=[
                types.Tool(
                    function_declarations=tools
                )
            ],
            automatic_function_calling={
                "disable": True
            }
        )

        if system_instruction:
            config.system_instruction = system_instruction

        # Use the actual user request as the intent when
        # no separate intent is explicitly provided.
        effective_intent = intent.strip() if intent else user_prompt

        contents = []

# Preserve previous dashboard conversation as Gemini context.
#
# Important:
# The firewall intent remains the CURRENT user request only.
# Previous messages are context for Gemini, not a replacement
# for the current ToolRequest intent.

        for message in conversation_history or []:

            role = (
                "model"
                if message.get("role") == "assistant"
                else "user"
            )

            text = str(
                message.get(
                "content",
                ""
                )
            )

            if not text.strip():
                continue

            contents.append(
                types.Content(
                    role=role,
                    parts=[
                        types.Part.from_text(
                            text=text
                        )
                    ]
                )
            )


            contents.append(
                types.Content(
                    role="user",
                    parts=[
                        types.Part.from_text(
                        text=user_prompt
                        )
                    ]
                )
            )

        tool_results = []

        max_rounds = 5

        for _ in range(max_rounds):

            try:
                response = self.client.models.generate_content(
                    model=self.model,
                    contents=contents,
                    config=config
                )

            except errors.APIError as error:
                return self._model_error_result(
                    error,
                    tool_results
                )

            requests = self.function_calls_to_requests(
                response,
                intent=effective_intent
            )

            # Gemini returned a normal text response.
            # No tool call is required.
            if not requests:

                return {
                    "status": "COMPLETED",
                    "response": response,
                    "text": response.text,
                    "tool_results": tool_results
                }

            # Preserve Gemini's original function-call content,
            # including the function-call metadata/signature.
            model_content = response.candidates[0].content

            contents.append(model_content)

            function_response_parts = []

            for request in requests:

                decision, result = firewall.execute(
                    request
                )

                tool_results.append({
                    "request": request,
                    "decision": decision,
                    "result": result
                })

                # Security enforcement happens BEFORE
                # the enterprise tool result is returned
                # to Gemini.
                if decision.action in {
                    "BLOCK",
                    "ESCALATE"
                }:

                    return {
                        "status": decision.action,
                        "response": None,
                        "text": (
                            "The requested action was blocked "
                            "by the security firewall."
                        ),
                        "tool_results": tool_results
                    }

                # Return the enterprise tool result to Gemini.
                function_response_parts.append(
                    types.Part.from_function_response(
                        name=request.tool,
                        response={
                            "output": result
                        }
                    )
                )

            contents.append(
                types.Content(
                    role="user",
                    parts=function_response_parts
                )
            )

        return {
            "status": "MAX_ROUNDS_EXCEEDED",
            "response": None,
            "text": (
                "The agent exceeded the maximum number "
                "of tool-calling rounds."
            ),
            "tool_results": tool_results
        }
    def _model_error_result(self, error, tool_results):
        code = getattr(error, "code", None)
        message = getattr(error, "message", str(error))

        if code == 429:
            status = "MODEL_QUOTA_ERROR"
            text = (
                "Gemini API quota was exhausted. "
                "No further model requests can be made until the quota resets."
            )
        elif code is not None and code >= 500:
            status = "MODEL_SERVICE_ERROR"
            text = f"Gemini service temporarily unavailable: {message}"
        else:
            status = "MODEL_API_ERROR"
            text = f"Gemini API request failed: {message}"

        return {
            "status": status,
            "response": None,
            "text": text,
            "tool_results": tool_results,
        }