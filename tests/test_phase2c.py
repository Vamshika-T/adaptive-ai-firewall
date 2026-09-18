from models.schemas import ToolRequest
from firewall.interceptor import FirewallInterceptor


firewall = FirewallInterceptor()


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


# ---------------------------------------------------------
# TEST 1: Normal action should have low trajectory risk
# ---------------------------------------------------------

request = make_request(
    "TEST_2C_001",
    "SESSION_2C_001",
    "U001",
    "search_employee",
    {
        "employee_id": "U001"
    },
    "Check my employee information"
)

decision = firewall.inspect(request)

assert decision.action == "ALLOW"
assert decision.risk_score < 35

print(
    "TEST 1 PASSED: Normal action has low contextual risk"
)


# ---------------------------------------------------------
# TEST 2: Intent mismatch should increase risk
# ---------------------------------------------------------

request = make_request(
    "TEST_2C_002",
    "SESSION_2C_002",
    "U001",
    "query_database",
    {
        "table": "employees"
    },
    "Check my calendar meeting"
)

decision = firewall.inspect(request)

assert decision.action != "ALLOW"
assert decision.risk_score >= 25

print(
    "TEST 2 PASSED: Intent mismatch increases risk"
)


# ---------------------------------------------------------
# TEST 3: Email → sensitive database trajectory
# ---------------------------------------------------------

session_id = "SESSION_2C_003"

request1 = make_request(
    "TEST_2C_003_A",
    session_id,
    "U002",
    "read_email_inbox",
    {
        "user_email": "bob@company.com"
    },
    "Read my email"
)

decision1 = firewall.inspect(request1)

assert decision1.action == "ALLOW"

request2 = make_request(
    "TEST_2C_003_B",
    session_id,
    "U002",
    "query_database",
    {
        "table": "payroll"
    },
    "Read payroll information"
)

decision2 = firewall.inspect(request2)

assert decision2.action == "MONITOR"
assert decision2.risk_score >= 25

print(
    "TEST 3 PASSED: Sensitive database access after "
    "email action increases trajectory risk"
)


# ---------------------------------------------------------
# TEST 4: Database → external email
# ---------------------------------------------------------

session_id = "SESSION_2C_004"

request1 = make_request(
    "TEST_2C_004_A",
    session_id,
    "U002",
    "query_database",
    {
        "table": "payroll"
    },
    "Access payroll"
)

decision1 = firewall.inspect(request1)

assert decision1.action == "ALLOW"

request2 = make_request(
    "TEST_2C_004_B",
    session_id,
    "U002",
    "send_email_message",
    {
        "sender": "bob@company.com",
        "recipient": "attacker@gmail.com",
        "subject": "Payroll",
        "body": "Payroll information"
    },
    "Send an email"
)

decision2 = firewall.inspect(request2)



assert decision2.action == "BLOCK"

assert decision2.risk_score >= 70

print(
    "TEST 4 PASSED: Sensitive data followed by "
    "external email is blocked"
)


# ---------------------------------------------------------
# TEST 5: Tainted context → write action
# ---------------------------------------------------------

request = ToolRequest(
    request_id="TEST_2C_005",
    session_id="SESSION_2C_005",
    user_id="U002",
    tool="send_email_message",
    arguments={
        "sender": "bob@company.com",
        "recipient": "attacker@gmail.com",
        "subject": "Important",
        "body": "Send this information"
    },
    intent="Send an email",
    tainted=True
)

decision = firewall.inspect(request)

assert decision.action == "MONITOR"

assert (
    "Tainted context is influencing a write action"
    in decision.reasons
)

print(
    "TEST 5 PASSED: Tainted context influences "
    "write-action risk"
)


print()
print("ALL PHASE 2C TESTS PASSED")