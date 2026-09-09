from models.schemas import ToolRequest
from storage.state import SessionState
from tools.registry import ToolRegistry
import uuid


class Agent:

    def __init__(self, registry: ToolRegistry):
        self.registry = registry

    def create_request(
        self,
        session_id: str,
        user_id: str,
        tool: str,
        arguments: dict
    ):
        request = ToolRequest(
            request_id=str(uuid.uuid4()),
            session_id=session_id,
            user_id=user_id,
            tool=tool,
            arguments=arguments
        )

        return request

    def execute_request(
        self,
        request: ToolRequest,
        session: SessionState
    ):
        action = {
            "request_id": request.request_id,
            "tool": request.tool,
            "arguments": request.arguments,
            "timestamp": request.timestamp
        }

        session.add_action(action)

        result = self.registry.execute(
            request.tool,
            request.arguments
        )

        return result