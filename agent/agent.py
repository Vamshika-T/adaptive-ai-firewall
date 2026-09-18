from models.schemas import ToolRequest
from tools.registry import execute_tool


def baseline_executor(request):
    """
    No-defense execution path.
    Used for baseline experiments.
    """

    return execute_tool(
        request.tool,
        request.arguments
    )


class DeterministicAgent:

    def __init__(
        self,
        session_id,
        user_id,
        executor=None
    ):

        self.session_id = session_id
        self.user_id = user_id

        self.request_counter = 0

        self.executor = (
            executor
            or baseline_executor
        )

    def create_request(
        self,
        tool,
        arguments=None,
        intent="",
        context_sources=None,
        tainted=False
    ):

        self.request_counter += 1

        request = ToolRequest(
            request_id=(
                f"{self.session_id}-REQ"
                f"{self.request_counter:03d}"
            ),

            session_id=self.session_id,

            user_id=self.user_id,

            tool=tool,

            arguments=dict(
                arguments or {}
            ),

            intent=intent,

            context_sources=list(
                context_sources or []
            ),

            tainted=tainted
        )

        return request

    def execute(
        self,
        tool,
        arguments=None,
        intent="",
        context_sources=None,
        tainted=False
    ):

        request = self.create_request(
            tool=tool,
            arguments=arguments,
            intent=intent,
            context_sources=context_sources,
            tainted=tainted
        )

        result = self.executor(
            request
        )

        return request, result