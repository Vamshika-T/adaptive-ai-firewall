from models.schemas import ToolRequest
from firewall.interceptor import FirewallInterceptor


firewall = FirewallInterceptor()


def make_request(
    request_id,
    session_id,
    user_id,
    tool,
    arguments
):
    return ToolRequest(
        request_id=request_id,
        session_id=session_id,
        user_id=user_id,
        tool=tool,
        arguments=arguments
    )


# ---------------------------------------------------------
# TEST 1: User can access their own employee record
# ---------------------------------------------------------

request = make_request(
    "TEST_2A_001",
    "SESSION_2A_001",
    "U001",
    "search_employee",
    {
        "employee_id": "U001"
    }
)

decision = firewall.inspect(request)

assert decision.action == "ALLOW"

print("TEST 1 PASSED: Own employee record allowed")


# ---------------------------------------------------------
# TEST 2: Employee cannot access another employee
# ---------------------------------------------------------

request = make_request(
    "TEST_2A_002",
    "SESSION_2A_002",
    "U001",
    "search_employee",
    {
        "employee_id": "U002"
    }
)

decision = firewall.inspect(request)

assert decision.action == "BLOCK"

print("TEST 2 PASSED: Unauthorized employee access blocked")


# ---------------------------------------------------------
# TEST 3: Normal employee cannot access payroll
# ---------------------------------------------------------

request = make_request(
    "TEST_2A_003",
    "SESSION_2A_003",
    "U001",
    "query_database",
    {
        "table": "payroll"
    }
)

decision = firewall.inspect(request)

assert decision.action == "BLOCK"

print("TEST 3 PASSED: Unauthorized payroll access blocked")


# ---------------------------------------------------------
# TEST 4: HR manager can access payroll
# ---------------------------------------------------------

request = make_request(
    "TEST_2A_004",
    "SESSION_2A_004",
    "U002",
    "query_database",
    {
        "table": "payroll"
    }
)

decision = firewall.inspect(request)

assert decision.action == "ALLOW"

print("TEST 4 PASSED: HR payroll access allowed")


# ---------------------------------------------------------
# TEST 5: User cannot read another user's inbox
# ---------------------------------------------------------

request = make_request(
    "TEST_2A_005",
    "SESSION_2A_005",
    "U001",
    "read_email_inbox",
    {
        "user_email": "bob@company.com"
    }
)

decision = firewall.inspect(request)

assert decision.action == "BLOCK"

print("TEST 5 PASSED: Other user's email access blocked")


# ---------------------------------------------------------
# TEST 6: User can read their own inbox
# ---------------------------------------------------------

request = make_request(
    "TEST_2A_006",
    "SESSION_2A_006",
    "U001",
    "read_email_inbox",
    {
        "user_email": "alice@company.com"
    }
)

decision = firewall.inspect(request)

assert decision.action == "ALLOW"

print("TEST 6 PASSED: Own email access allowed")


# ---------------------------------------------------------
# TEST 7: User cannot spoof email sender
# ---------------------------------------------------------

request = make_request(
    "TEST_2A_007",
    "SESSION_2A_007",
    "U001",
    "send_email_message",
    {
        "sender": "bob@company.com",
        "recipient": "test@example.com",
        "subject": "Test",
        "body": "Hello"
    }
)

decision = firewall.inspect(request)

assert decision.action == "BLOCK"

print("TEST 7 PASSED: Spoofed email sender blocked")


# ---------------------------------------------------------
# TEST 8: Unknown user blocked
# ---------------------------------------------------------

request = make_request(
    "TEST_2A_008",
    "SESSION_2A_008",
    "U999",
    "search_employee",
    {
        "employee_id": "U999"
    }
)

decision = firewall.inspect(request)

assert decision.action == "BLOCK"

print("TEST 8 PASSED: Unknown identity blocked")


print()

# ---------------------------------------------------------
# TEST 9: Employee cannot query entire employee table
# ---------------------------------------------------------

request9 = ToolRequest(
    request_id="PHASE2A-REQ009",
    session_id="PHASE2A_SESSION",
    user_id="U001",
    tool="query_database",
    arguments={
        "table": "employees"
    }
)

decision9, result9 = firewall.execute(request9)

assert decision9.action == "BLOCK"
assert result9 is None

print("TEST 9 PASSED: Employee cannot query entire employee table")


# ---------------------------------------------------------
# TEST 10: Employee cannot query entire customer table
# ---------------------------------------------------------

request10 = ToolRequest(
    request_id="PHASE2A-REQ010",
    session_id="PHASE2A_SESSION",
    user_id="U001",
    tool="query_database",
    arguments={
        "table": "customers"
    }
)

decision10, result10 = firewall.execute(request10)

assert decision10.action == "BLOCK"
assert result10 is None

print("TEST 10 PASSED: Employee cannot query entire customer table")
print("ALL PHASE 2A TESTS PASSED")