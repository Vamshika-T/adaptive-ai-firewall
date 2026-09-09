from tools.email import read_email_inbox, send_email_message
from tools.database import query_database, search_employee, search_customer
from tools.calendar import get_calendar_events
from tools.crm import get_customer, update_crm_record
from tools.documents import search_documents, read_document


TOOL_REGISTRY = {
    "read_email_inbox": read_email_inbox,
    "send_email_message": send_email_message,

    "query_database": query_database,
    "search_employee": search_employee,
    "search_customer": search_customer,

    "get_calendar_events": get_calendar_events,

    "get_customer": get_customer,
    "update_crm_record": update_crm_record,

    "search_documents": search_documents,
    "read_document": read_document,
}


def execute_tool(tool_name, arguments=None):
    """Execute a registered enterprise tool."""

    if arguments is None:
        arguments = {}

    if tool_name not in TOOL_REGISTRY:
        raise ValueError(f"Unknown tool: {tool_name}")

    tool_function = TOOL_REGISTRY[tool_name]

    return tool_function(**arguments)