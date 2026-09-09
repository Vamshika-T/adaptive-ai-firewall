from typing import Dict, Callable, Any


class ToolRegistry:

    def __init__(self):
        self.tools: Dict[str, Callable] = {}

    def register(self, name: str, function: Callable):
        self.tools[name] = function

    def get_tool(self, name: str):
        return self.tools.get(name)

    def execute(self, name: str, arguments: Dict[str, Any]):
        tool = self.get_tool(name)

        if tool is None:
            raise ValueError("Tool not found: " + name)

        return tool(**arguments)

    def list_tools(self):
        return list(self.tools.keys())