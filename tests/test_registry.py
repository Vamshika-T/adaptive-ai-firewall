from tools.registry import ToolRegistry


def get_employee(name):
    return "Employee found: " + name


def send_email(to, message):
    return "Email sent to " + to


registry = ToolRegistry()

registry.register("get_employee", get_employee)
registry.register("send_email", send_email)


print("Available tools:")
print(registry.list_tools())

print("\nExecuting get_employee:")
print(
    registry.execute(
        "get_employee",
        {
            "name": "Alice"
        }
    )
)

print("\nExecuting send_email:")
print(
    registry.execute(
        "send_email",
        {
            "to": "bob@company.com",
            "message": "Hello"
        }
    )
)