from models.schemas import ToolRequest
from models.decisions import SecurityDecision
from tools.registry import execute_tool


class FirewallInterceptor:

    def inspect(self, request: ToolRequest) -> SecurityDecision:
        """
        Inspect a tool request and return a security decision.

        Security policies will be added here through
        separate firewall components.
        """

        return SecurityDecision(
            request_id=request.request_id,
            action="ALLOW",
            risk_score=0.0,
            reasons=[
                "Initial firewall: no security policies enabled"
            ]
        )

    def execute(self, request: ToolRequest):
        """
        Inspect the request before executing the enterprise tool.
        """

        decision = self.inspect(request)

        if decision.action == "BLOCK":
            return decision, None

        if decision.action == "ESCALATE":
            return decision, None

        result = execute_tool(
            request.tool,
            request.arguments
        )

        return decision, result