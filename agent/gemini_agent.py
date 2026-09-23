import os
from google import genai
from google.genai import types

from models.schemas import ToolRequest


class GeminiAgent:

    def __init__(
        self,
        session_id,
        user_id,
        model="gemini-3.8-flash"
    ):
        self.session_id = session_id
        self.user_id = user_id
        self.model = model

        self.request_counter = 0

        api_key = os.getenv("GEMINI_API_KEY")

        if not api_key:
            raise RuntimeError(
                "GEMINI_API_KEY environment variable is not set."
            )

        self.client = genai.Client(
            api_key=api_key
        )

    def create_request(
        self,
        tool,
        arguments=None,
        intent=""
    ):
        self.request_counter += 1

        return ToolRequest(
            request_id=(
                f"{self.session_id}-REQ"
                f"{self.request_counter:03d}"
            ),
            session_id=self.session_id,
            user_id=self.user_id,
            tool=tool,
            arguments=dict(arguments or {}),
            intent=intent,
            source_type="gemini_agent"
        )

    def generate(
        self,
        user_prompt,
        tools,
        system_instruction=None
    ):
        """
        Send a user request to Gemini and return the response.

        Automatic function execution is disabled because all
        tool calls must first pass through the AI firewall.
        """

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
            config.system_instruction = (
                system_instruction
            )

        response = self.client.models.generate_content(
            model=self.model,
            contents=user_prompt,
            config=config
        )

        return response

    def extract_function_calls(
        self,
        response
    ):
        """
        Extract Gemini's requested function calls.

        Returns:
            list of dictionaries containing:
            function call ID + tool name + arguments
        """

        calls = []

        for candidate in response.candidates:

            if not candidate.content:
                continue

            for part in candidate.content.parts:

                if not part.function_call:
                    continue

                function_call = part.function_call

                calls.append(
                    {
                        "id": function_call.id,
                        "name": function_call.name,
                        "arguments": dict(
                            function_call.args or {}
                        )
                    }
                )

        return calls

    def function_calls_to_requests(
        self,
        response,
        intent=""
    ):
        """
        Convert Gemini function calls into the
        project's existing ToolRequest schema.
        """

        calls = self.extract_function_calls(
            response
        )

        requests = []

        for call in calls:

            request = self.create_request(
                tool=call["name"],
                arguments=call["arguments"],
                intent=intent
            )

            requests.append(request)

        return requests


    def run_secured(
        self,
        user_prompt,
        tools,
        firewall,
        system_instruction=None,
        intent=""
    ):
        """
        Run a complete secured Gemini tool-calling interaction.

        Gemini can request enterprise tools, but every request
        must pass through FirewallInterceptor before execution.

        Allowed tool results are sent back to Gemini so that
        Gemini can produce the final natural-language response.

        BLOCK and ESCALATE decisions stop the interaction and
        prevent the requested tool from executing.
        """

        # -------------------------------------------------
        # 1. Create Gemini configuration
        # -------------------------------------------------

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
            config.system_instruction = (
                system_instruction
            )

        # -------------------------------------------------
        # 2. Create initial conversation contents
        # -------------------------------------------------

        contents = [
            types.Content(
                role="user",
                parts=[
                    types.Part.from_text(
                        text=user_prompt
                    )
                ]
            )
        ]

        tool_results = []

        # -------------------------------------------------
        # 3. Allow multiple tool-calling rounds
        # -------------------------------------------------

        max_rounds = 5

        for _ in range(max_rounds):

            # -------------------------------------------------
            # 3A. Ask Gemini
            # -------------------------------------------------

            response = self.client.models.generate_content(
                model=self.model,
                contents=contents,
                config=config
            )

            # -------------------------------------------------
            # 3B. Check for function calls
            # -------------------------------------------------

            requests = self.function_calls_to_requests(
                response,
                intent=intent
            )

            # -------------------------------------------------
            # 3C. No function call = final Gemini answer
            # -------------------------------------------------

            if not requests:

                return {
                    "status": "COMPLETED",
                    "response": response,
                    "text": response.text,
                    "tool_results": tool_results
                }

            # -------------------------------------------------
            # 3D. Preserve Gemini's original model response
            #
            # IMPORTANT:
            # This preserves function-call information and
            # Gemini 3 thought signatures.
            # -------------------------------------------------

            model_content = (
                response.candidates[0].content
            )

            contents.append(
                model_content
            )

            # -------------------------------------------------
            # 3E. Firewall + tool execution
            # -------------------------------------------------

            function_response_parts = []

            for request in requests:

                decision, result = firewall.execute(
                    request
                )

                tool_results.append(
                    {
                        "request": request,
                        "decision": decision,
                        "result": result
                    }
                )

                # -------------------------------------------------
                # 3F. BLOCK / ESCALATE
                # -------------------------------------------------

                if decision.action in {
                    "BLOCK",
                    "ESCALATE"
                }:

                    return {
                        "status": decision.action,
                        "response": None,
                        "text": (
                            "The requested action was "
                            "blocked by the security firewall."
                        ),
                        "tool_results": tool_results
                    }

                # -------------------------------------------------
                # 3G. Convert approved tool result into
                #     Gemini FunctionResponse
                # -------------------------------------------------

                function_response_parts.append(
                    types.Part.from_function_response(
                        name=request.tool,
                        response={
                            "output": result
                        }
                    )
                )

            # -------------------------------------------------
            # 3H. Send approved tool results back to Gemini
            # -------------------------------------------------

            contents.append(
                types.Content(
                    role="user",
                    parts=function_response_parts
                )
            )

        # -------------------------------------------------
        # 4. Prevent infinite tool-calling loops
        # -------------------------------------------------

        return {
            "status": "MAX_ROUNDS_EXCEEDED",
            "response": None,
            "text": (
                "The agent exceeded the maximum number "
                "of tool-calling rounds."
            ),
            "tool_results": tool_results
        }