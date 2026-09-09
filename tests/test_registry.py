from tools.registry import TOOL_REGISTRY, execute_tool


print("AVAILABLE TOOLS:")

for tool in TOOL_REGISTRY:
    print(tool)


print("\nTESTING search_employee:")

result = execute_tool(
    "search_employee",
    {
        "employee_id": "U001"
    }
)

print(result)