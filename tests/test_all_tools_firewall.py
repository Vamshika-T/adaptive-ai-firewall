from models.schemas import ToolRequest
from firewall.interceptor import FirewallInterceptor


def make_request(
    request_id,
    session_id,
    user_id,
    tool,
    arguments,
    intent=""
):
    return ToolRequest(
        request_id=request_id,
        session_id=session_id,
        user_id=user_id,
        tool=tool,
        arguments=arguments,
        intent=intent
    )


def run_case(
    firewall,
    name,
    request,
    expected_action
):
    print("\n" + "=" * 70)
    print(name)
    print("=" * 70)

    decision, result = firewall.execute(request)

    print("TOOL:", request.tool)
    print("USER:", request.user_id)
    print("ARGUMENTS:", request.arguments)
    print("DECISION:", decision.action)
    print("RISK:", decision.risk_score)
    print("INSPECTION:", decision.inspection_level)
    print("REASONS:", decision.reasons)
    print("EXECUTED:", result is not None)

    assert decision.action == expected_action

    return decision, result


# =========================================================
# 1. CALENDAR — authorized
# =========================================================

firewall = FirewallInterceptor()

request = make_request(
    "ALLTOOLS-001",
    "ALLTOOLS-SESSION-001",
    "U001",
    "get_calendar_events",
    {
        "user_email": "alice@company.com",
        "date": "2026-09-23"
    },
    "Retrieve my calendar events for the requested date."
)

run_case(
    firewall,
    "1. Authorized calendar access",
    request,
    "ALLOW"
)


# =========================================================
# 2. EMAIL READ — authorized
# =========================================================

request = make_request(
    "ALLTOOLS-002",
    "ALLTOOLS-SESSION-002",
    "U001",
    "read_email_inbox",
    {
        "user_email": "alice@company.com"
    },
    "Read my email inbox."
)

run_case(
    firewall,
    "2. Authorized email read",
    request,
    "ALLOW"
)


# =========================================================
# 3. EMAIL SEND — authorized
# =========================================================

request = make_request(
    "ALLTOOLS-003",
    "ALLTOOLS-SESSION-003",
    "U001",
    "send_email_message",
    {
        "sender": "alice@company.com",
        "recipient": "bob@company.com",
        "subject": "Project update",
        "body": "Please review the project update."
    },
    "Send an email to Bob."
)

run_case(
    firewall,
    "3. Authorized email send",
    request,
    "ALLOW"
)


# =========================================================
# 4. DATABASE — authorized payroll
# =========================================================

request = make_request(
    "ALLTOOLS-004",
    "ALLTOOLS-SESSION-004",
    "U002",
    "query_database",
    {
        "table": "payroll"
    },
    "Retrieve payroll records for authorized HR work."
)

run_case(
    firewall,
    "4. Authorized payroll database access",
    request,
    "ALLOW"
)


# =========================================================
# 5. EMPLOYEE SEARCH — own record
# =========================================================

request = make_request(
    "ALLTOOLS-005",
    "ALLTOOLS-SESSION-005",
    "U001",
    "search_employee",
    {
        "employee_id": "U001"
    },
    "Retrieve my employee record."
)

run_case(
    firewall,
    "5. Authorized employee search",
    request,
    "ALLOW"
)


# =========================================================
# 6. CUSTOMER SEARCH — authorized account manager
# =========================================================

request = make_request(
    "ALLTOOLS-006",
    "ALLTOOLS-SESSION-006",
    "U003",
    "search_customer",
    {
        "customer_id": "C001"
    },
    "Retrieve information about my assigned customer."
)

run_case(
    firewall,
    "6. Authorized customer search",
    request,
    "ALLOW"
)


# =========================================================
# 7. CRM GET — authorized account manager
# =========================================================

request = make_request(
    "ALLTOOLS-007",
    "ALLTOOLS-SESSION-007",
    "U003",
    "get_customer",
    {
        "customer_id": "C001"
    },
    "Retrieve my assigned customer's CRM record."
)

run_case(
    firewall,
    "7. Authorized CRM read",
    request,
    "ALLOW"
)


# =========================================================
# 8. CRM UPDATE — authorized account manager
# =========================================================

request = make_request(
    "ALLTOOLS-008",
    "ALLTOOLS-SESSION-008",
    "U003",
    "update_crm_record",
    {
        "customer_id": "C001",
        "field": "status",
        "value": "active"
    },
    "Update the status of my assigned customer."
)

run_case(
    firewall,
    "8. Authorized CRM update",
    request,
    "ALLOW"
)


# =========================================================
# 9. DOCUMENT SEARCH — authorized
# =========================================================

request = make_request(
    "ALLTOOLS-009",
    "ALLTOOLS-SESSION-009",
    "U001",
    "search_documents",
    {
        "keyword": "Engineering"
    },
    "Search enterprise engineering documents."
)

run_case(
    firewall,
    "9. Authorized document search",
    request,
    "ALLOW"
)


# =========================================================
# 10. DOCUMENT READ — authorized
# =========================================================

request = make_request(
    "ALLTOOLS-010",
    "ALLTOOLS-SESSION-010",
    "U001",
    "read_document",
    {
        "document_id": "DOC001"
    },
    "Read the engineering API guide."
)

run_case(
    firewall,
    "10. Authorized document read",
    request,
    "ALLOW"
)


print("\n" + "=" * 70)
print("ALL 10 TOOLS PASSED THROUGH FIREWALL")
print("=" * 70)