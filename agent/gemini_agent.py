import os
import json
from google import genai
from google.genai import types

from models.schemas import ToolRequest


class GeminiAgent:

    def __init__(
        self,
        session_id,
        user_id,
        model="gemini-3.6-flash"
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
            tool name + arguments
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