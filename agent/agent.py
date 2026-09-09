from models.schemas import ToolRequest
from tools.registry import execute_tool


class DeterministicAgent:
    def __init__(self, session_id, user_id):
        self.session_id = session_id
        self.user_id = user_id
        self.request_counter = 0

    def create_request(self, tool, arguments=None):
        self.request_counter += 1

        request = ToolRequest(
            request_id=f"{self.session_id}-REQ{self.request_counter:03d}",
            session_id=self.session_id,
            user_id=self.user_id,
            tool=tool,
            arguments=dict(arguments or {})
        )

        return request

    def execute(self, tool, arguments=None):
        request = self.create_request(tool, arguments)

        result = execute_tool(
            request.tool,
            request.arguments
        )

        return request, result