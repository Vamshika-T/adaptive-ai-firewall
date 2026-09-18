import json
from pathlib import Path


DATA_FILE = (
    Path(__file__).parent.parent
    / "data"
    / "employees.json"
)


ROLE_PERMISSIONS = {

    "employee": {
        "calendar.read",
        "email.read",
        "email.send",
        "customer.read",
        "document.read",
        "document.search"
    },

    "hr_manager": {
        "calendar.read",
        "email.read",
        "email.send",
        "employee.read",
        "payroll.read",
        "document.read",
        "document.search"
    },

    "sales_manager": {
        "calendar.read",
        "email.read",
        "email.send",
        "customer.read",
        "customer.update",
        "document.read",
        "document.search"
    },

    "engineering_manager": {
        "calendar.read",
        "email.read",
        "email.send",
        "employee.read",
        "document.read",
        "document.search"
    },

    "finance_manager": {
        "calendar.read",
        "email.read",
        "email.send",
        "employee.read",
        "payroll.read",
        "customer.read",
        "document.read",
        "document.search"
    },

    "executive": {
        "calendar.read",
        "email.read",
        "email.send",
        "employee.read",
        "payroll.read",
        "customer.read",
        "customer.update",
        "document.read",
        "document.search"
    }
}


TOOL_PERMISSIONS = {

    "read_email_inbox": "email.read",

    "send_email_message": "email.send",

    "query_database": "database.read",

    "search_employee": "employee.read",

    "search_customer": "customer.read",

    "get_calendar_events": "calendar.read",

    "get_customer": "customer.read",

    "update_crm_record": "customer.update",

    "search_documents": "document.search",

    "read_document": "document.read"
}


def load_users():
    with open(DATA_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def get_user(user_id):
    users = load_users()

    for user in users:
        if user["user_id"] == user_id:
            return user

    return None


def get_user_role(user_id):
    user = get_user(user_id)

    if user is None:
        return None

    return user["role"]


def get_user_department(user_id):
    user = get_user(user_id)

    if user is None:
        return None

    return user["department"]


def get_required_permission(tool_name):
    return TOOL_PERMISSIONS.get(tool_name)


def is_authorized(user_id, tool_name):
    user = get_user(user_id)

    if user is None:
        return False, "Unknown user identity"

    role = user["role"]

    required_permission = get_required_permission(tool_name)

    if required_permission is None:
        return False, "Tool has no defined permission"

    permissions = ROLE_PERMISSIONS.get(role, set())

    if required_permission not in permissions:
        return (
            False,
            f"Role '{role}' does not have "
            f"permission '{required_permission}'"
        )

    return True, "Authorization successful"