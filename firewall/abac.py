import json
from pathlib import Path


DATA_DIR = (
    Path(__file__).parent.parent
    / "data"
)


# ---------------------------------------------------------
# DATA LOADERS
# ---------------------------------------------------------

def load_json(filename):

    with open(
        DATA_DIR / filename,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


def get_user(user_id):

    employees = load_json(
        "employees.json"
    )

    for employee in employees:

        if employee["employee_id"] == user_id:

            return employee

    return None


# ---------------------------------------------------------
# EMPLOYEE ACCESS
# ---------------------------------------------------------

def check_employee_access(
    user,
    employee_id
):

    if employee_id is None:

        return (
            False,
            "Employee ID is required"
        )

    role = user["role"]
    user_id = user["employee_id"]

    employees = load_json(
        "employees.json"
    )

    target = None

    for employee in employees:

        if employee["employee_id"] == employee_id:

            target = employee
            break

    if target is None:

        return (
            False,
            "Target employee does not exist"
        )

    # Users may always access their own record.
    if employee_id == user_id:

        return (
            True,
            "User may access their own employee record"
        )

    # HR managers can access employee records.
    if role == "hr_manager":

        return (
            True,
            "HR manager may access employee records"
        )

    # Executives can access employee records.
    if role == "executive":

        return (
            True,
            "Executive may access employee records"
        )

    # Engineering and finance managers may
    # access their direct reports.
    if role in {
        "engineering_manager",
        "finance_manager"
    }:

        if target["manager_id"] == user_id:

            return (
                True,
                "Manager may access direct-report record"
            )

        return (
            False,
            "Manager may only access direct-report records"
        )

    return (
        False,
        "Employee access is outside the user's permitted scope"
    )


# ---------------------------------------------------------
# CUSTOMER ACCESS
# ---------------------------------------------------------

def check_customer_access(
    user,
    customer_id
):

    if customer_id is None:

        return (
            False,
            "Customer ID is required"
        )

    customers = load_json(
        "customers.json"
    )

    customer = None

    for item in customers:

        if item["customer_id"] == customer_id:

            customer = item
            break

    if customer is None:

        return (
            False,
            "Target customer does not exist"
        )

    role = user["role"]
    user_id = user["employee_id"]

    # Executives have organization-wide customer access.
    if role == "executive":

        return (
            True,
            "Executive may access customer records"
        )

    # Finance manager has customer-read permission.
    if role == "finance_manager":

        return (
            True,
            "Finance manager may read customer records"
        )

    # Sales manager has organization-wide sales access.
    if role == "sales_manager":

        return (
            True,
            "Sales manager may access customer records"
        )

    # Sales employees can only access customers
    # assigned to them.
    if role == "employee":

        if customer["account_manager"] == user_id:

            return (
                True,
                "User is the assigned customer account manager"
            )

        return (
            False,
            "User is not the assigned customer account manager"
        )

    return (
        False,
        "Customer access is outside the user's permitted scope"
    )


# ---------------------------------------------------------
# DOCUMENT ACCESS
# ---------------------------------------------------------

def get_document(document_id):

    documents = load_json(
        "documents.json"
    )

    for document in documents:

        if document["document_id"] == document_id:

            return document

    return None


def check_document_access(
    user,
    document_id
):

    document = get_document(
        document_id
    )

    if document is None:

        return (
            False,
            "Target document does not exist"
        )

    role = user["role"]
    user_id = user["employee_id"]

    allowed_roles = document.get(
        "allowed_roles",
        []
    )

    # Role must be explicitly permitted.
    if role not in allowed_roles:

        return (
            False,
            (
                f"Role '{role}' is not allowed "
                f"to access document '{document_id}'"
            )
        )

    # Owner is always permitted if their role is
    # also listed in allowed_roles.
    if document.get("owner_id") == user_id:

        return (
            True,
            "User is the document owner"
        )

    return (
        True,
        "Document access permitted by role policy"
    )


# ---------------------------------------------------------
# EMAIL ACCESS
# ---------------------------------------------------------

def check_email_access(
    user,
    tool_name,
    arguments
):

    user_email = user["email"]

    if tool_name == "read_email_inbox":

        requested_email = arguments.get(
            "user_email"
        )

        if requested_email is None:

            return (
                False,
                "Email identity is required"
            )

        if requested_email.lower() != user_email.lower():

            return (
                False,
                "User may only read their own email inbox"
            )

        return (
            True,
            "Email inbox belongs to authenticated user"
        )

    if tool_name == "send_email_message":

        sender = arguments.get(
            "sender"
        )

        if sender is None:

            return (
                False,
                "Sender identity is required"
            )

        if sender.lower() != user_email.lower():

            return (
                False,
                "Sender must match authenticated user identity"
            )

        return (
            True,
            "Email sender matches authenticated user"
        )

    return (
        True,
        "Email access permitted"
    )


# ---------------------------------------------------------
# CALENDAR ACCESS
# ---------------------------------------------------------

def check_calendar_access(
    user,
    arguments
):

    requested_email = arguments.get(
        "user_email"
    )

    if requested_email is None:

        return (
            False,
            "Calendar identity is required"
        )

    if requested_email.lower() != user["email"].lower():

        return (
            False,
            "User may only access their own calendar"
        )

    return (
        True,
        "Calendar belongs to authenticated user"
    )


# ---------------------------------------------------------
# DATABASE ACCESS
# ---------------------------------------------------------

def check_database_access(user, table):
    role = user["role"]

    if table == "payroll":
        if role in {"hr_manager", "finance_manager", "executive"}:
            return True, "Role is permitted to access payroll"
        return False, "Role is not permitted to access payroll"

    if table == "employees":
        if role in {"hr_manager", "executive"}:
            return True, "Role is permitted to query the employee table"
        return (
            False,
            "Full employee-table queries are restricted; "
            "use scoped employee lookup"
        )

    if table == "customers":
        if role in {"sales_manager", "finance_manager", "executive"}:
            return True, "Role is permitted to query the customer table"
        return (
            False,
            "Full customer-table queries are restricted; "
            "use scoped customer lookup"
        )

    return False, f"Database table '{table}' is outside the access policy"


# ---------------------------------------------------------
# MAIN ABAC CHECK
# ---------------------------------------------------------

def check_abac(
    user_id,
    tool_name,
    arguments=None
):

    arguments = arguments or {}

    user = get_user(
        user_id
    )

    if user is None:

        return (
            False,
            "Unknown user identity"
        )

    # -------------------------
    # Email
    # -------------------------

    if tool_name in {
        "read_email_inbox",
        "send_email_message"
    }:

        return check_email_access(
            user,
            tool_name,
            arguments
        )

    # -------------------------
    # Calendar
    # -------------------------

    if tool_name == "get_calendar_events":

        return check_calendar_access(
            user,
            arguments
        )

    # -------------------------
    # Employee
    # -------------------------

    if tool_name == "search_employee":

        return check_employee_access(
            user,
            arguments.get("employee_id")
        )

    # -------------------------
    # Database
    # -------------------------

    if tool_name == "query_database":

        return check_database_access(
            user,
            arguments.get("table")
        )

    # -------------------------
    # Customer
    # -------------------------

    if tool_name in {
        "search_customer",
        "get_customer"
    }:

        return check_customer_access(
            user,
            arguments.get("customer_id")
        )

    # -------------------------
    # CRM update
    # -------------------------

    if tool_name == "update_crm_record":

        return check_customer_access(
            user,
            arguments.get("customer_id")
        )

    # -------------------------
    # Document read
    # -------------------------

    if tool_name == "read_document":

        return check_document_access(
            user,
            arguments.get("document_id")
        )

    # -------------------------
    # Document search
    # -------------------------

    if tool_name == "search_documents":

        # Search itself is allowed through RBAC.
        # Individual returned documents are filtered
        # by the firewall before being exposed.
        return (
            True,
            "Document search permitted; results require filtering"
        )

    return (
        True,
        "No additional ABAC restriction defined"
    )


# ---------------------------------------------------------
# FILTER SEARCH RESULTS
# ---------------------------------------------------------

def filter_document_results(
    user_id,
    results
):

    user = get_user(
        user_id
    )

    if user is None:

        return []

    filtered = []

    for document in results:

        allowed_roles = document.get(
            "allowed_roles",
            []
        )

        if user["role"] in allowed_roles:

            filtered.append(
                document
            )

    return filtered