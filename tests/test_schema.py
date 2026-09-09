from models.schemas import ToolRequest


request = ToolRequest(
    request_id="REQ001",
    session_id="SESSION001",
    user_id="U001",
    tool="query_database",
    arguments={
        "table": "employees"
    }
)

print(request)