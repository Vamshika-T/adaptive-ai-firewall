from models.schemas import ToolRequest
from firewall.interceptor import FirewallInterceptor


def make_request(
    tool,
    user_id="U001",
    arguments=None,
    intent=""
):
    return ToolRequest(
        request_id="TEST-REQ-001",
        session_id="TEST-SESSION-001",
        user_id=user_id,
        tool=tool,
        arguments=arguments or {},
        intent=intent
    )


# =========================================================
# TEST 1: AUTHORIZED CALENDAR REQUEST
# =========================================================

print("\n========================================")
print("TEST 1: AUTHORIZED CALENDAR REQUEST")
print("========================================")

firewall = FirewallInterceptor()

request = make_request(
    tool="get_calendar_events",
    arguments={
        "user_email": "alice@company.com",
        "date": "2026-09-23"
    },
    intent=(
        "Retrieve the user's calendar events "
        "for the requested date."
    )
)

decision, result = firewall.execute(request)

print("TOOL:", request.tool)
print("DECISION:", decision.action)
print("RISK:", decision.risk_score)
print("INSPECTION:", decision.inspection_level)
print("RESULT:", result)

assert decision.action == "ALLOW"
assert result is not None


# =========================================================
# TEST 2: UNAUTHORIZED PAYROLL REQUEST
# =========================================================

print("\n========================================")
print("TEST 2: UNAUTHORIZED PAYROLL REQUEST")
print("========================================")

request = make_request(
    tool="query_database",
    arguments={
        "table": "payroll"
    },
    intent=(
        "Retrieve payroll records from the "
        "company database."
    )
)

decision, result = firewall.execute(request)

print("TOOL:", request.tool)
print("DECISION:", decision.action)
print("RISK:", decision.risk_score)
print("REASONS:", decision.reasons)
print("RESULT:", result)

assert decision.action == "BLOCK"
assert result is None


# =========================================================
# TEST 3: UNKNOWN USER
# =========================================================

print("\n========================================")
print("TEST 3: UNKNOWN USER")
print("========================================")

request = make_request(
    tool="get_calendar_events",
    user_id="UNKNOWN_USER",
    arguments={
        "user_email": "alice@company.com",
        "date": "2026-09-23"
    },
    intent="Retrieve calendar events."
)

decision, result = firewall.execute(request)

print("TOOL:", request.tool)
print("USER:", request.user_id)
print("DECISION:", decision.action)
print("RISK:", decision.risk_score)
print("REASONS:", decision.reasons)
print("RESULT:", result)

assert decision.action == "BLOCK"
assert result is None


# =========================================================
# TEST 4: ABAC - OTHER USER'S CALENDAR
# =========================================================

print("\n========================================")
print("TEST 4: ABAC CALENDAR RESTRICTION")
print("========================================")

firewall = FirewallInterceptor()

request = make_request(
    tool="get_calendar_events",
    arguments={
        "user_email": "bob@company.com",
        "date": "2026-09-23"
    },
    intent="Retrieve calendar events."
)

decision, result = firewall.execute(request)

print("TOOL:", request.tool)
print("REQUESTED USER:", request.arguments["user_email"])
print("DECISION:", decision.action)
print("RISK:", decision.risk_score)
print("REASONS:", decision.reasons)
print("RESULT:", result)

assert decision.action == "BLOCK"
assert decision.risk_score == 100
assert result is None


# =========================================================
# TEST 5: INTENT MISMATCH
# =========================================================

print("\n========================================")
print("TEST 5: INTENT MISMATCH")
print("========================================")

firewall = FirewallInterceptor()

request = make_request(
    tool="get_calendar_events",
    arguments={
        "user_email": "alice@company.com",
        "date": "2026-09-23"
    },
    intent="Send an email to the customer."
)

decision, result = firewall.execute(request)

print("TOOL:", request.tool)
print("INTENT:", request.intent)
print("DECISION:", decision.action)
print("RISK:", decision.risk_score)
print("REASONS:", decision.reasons)
print("RESULT:", result)

assert any(
    "email-related intent" in reason
    for reason in decision.reasons
)

assert decision.risk_score >= 25


# =========================================================
# TEST 6: TAINTED CONTEXT → WRITE ACTION
# =========================================================

print("\n========================================")
print("TEST 6: TAINTED CONTEXT WRITE ACTION")
print("========================================")

firewall = FirewallInterceptor()

request = make_request(
    tool="send_email_message",
    arguments={
        "sender": "alice@company.com",
        "recipient": "bob@company.com",
        "subject": "Review",
        "body": "Please review this information."
    },
    intent="Send an email."
)

request.tainted = True

decision, result = firewall.execute(request)

print("TOOL:", request.tool)
print("TAINTED:", request.tainted)
print("DECISION:", decision.action)
print("RISK:", decision.risk_score)
print("INSPECTION:", decision.inspection_level)
print("REASONS:", decision.reasons)
print("RESULT:", result)

assert decision.inspection_level == "DEEP"

assert any(
    "tainted context" in reason.lower()
    for reason in decision.reasons
)


# =========================================================
# TEST 7: EMAIL TO DATABASE TRAJECTORY
# =========================================================

print("\n========================================")
print("TEST 7: EMAIL TO DATABASE TRAJECTORY")
print("========================================")

firewall = FirewallInterceptor()

# Step 1: Read email
request1 = make_request(
    user_id="U002",
    tool="read_email_inbox",
    arguments={
        "user_email": "bob@company.com"
    },
    intent="Read my email."
)

decision1, result1 = firewall.execute(request1)

print("FIRST TOOL:", request1.tool)
print("FIRST DECISION:", decision1.action)
print("FIRST RESULT:", result1)

assert decision1.action == "ALLOW"


# Step 2: Access sensitive employee database
request2 = make_request(
    user_id="U002",
    tool="query_database",
    arguments={
        "table": "employees"
    },
    intent="Look up employee information."
)

decision2, result2 = firewall.execute(request2)

print("SECOND TOOL:", request2.tool)
print("SECOND DECISION:", decision2.action)
print("SECOND RISK:", decision2.risk_score)
print("SECOND INSPECTION:", decision2.inspection_level)
print("REASONS:", decision2.reasons)
print("RESULT:", result2)

assert any(
    "earlier email-reading action" in reason
    for reason in decision2.reasons
)

assert decision2.inspection_level in {
    "CONTEXTUAL",
    "DEEP"
}


# =========================================================
# TEST 8: DATABASE TO EXTERNAL EMAIL TRAJECTORY
# =========================================================

print("\n========================================")
print("TEST 8: DATABASE TO EXTERNAL EMAIL TRAJECTORY")
print("========================================")

firewall = FirewallInterceptor()

# Step 1: Access sensitive employee database
request1 = make_request(
    user_id="U002",
    tool="query_database",
    arguments={
        "table": "employees"
    },
    intent="Look up employee information."
)

decision1, result1 = firewall.execute(request1)

print("FIRST TOOL:", request1.tool)
print("FIRST DECISION:", decision1.action)
print("FIRST RISK:", decision1.risk_score)

assert decision1.action in {
    "ALLOW",
    "MONITOR"
}


# Step 2: Send information externally
request2 = make_request(
    user_id="U002",
    tool="send_email_message",
    arguments={
        "sender": "bob@company.com",
        "recipient": "external@example.com",
        "subject": "Employee Information",
        "body": "Please review this information."
    },
    intent="Send an email."
)

decision2, result2 = firewall.execute(request2)

print("SECOND TOOL:", request2.tool)
print("SECOND DECISION:", decision2.action)
print("SECOND RISK:", decision2.risk_score)
print("SECOND INSPECTION:", decision2.inspection_level)
print("REASONS:", decision2.reasons)
print("RESULT:", result2)

assert any(
    "external email" in reason.lower()
    for reason in decision2.reasons
)

assert any(
    "exfiltration" in reason.lower()
    or "sensitive" in reason.lower()
    for reason in decision2.reasons
)

assert decision2.action in {
    "BLOCK",
    "ESCALATE",
    "MONITOR"
}


# =========================================================
# TEST 9: TAINTED CONTEXT → WRITE ACTION
# =========================================================

print("\n========================================")
print("TEST 9: TAINTED WRITE ACTION")
print("========================================")

firewall = FirewallInterceptor()

request = make_request(
    tool="send_email_message",
    arguments={
        "sender": "alice@company.com",
        "recipient": "bob@company.com",
        "subject": "Update",
        "body": "Please review this."
    },
    intent="Send an email."
)

request.tainted = True

decision, result = firewall.execute(request)

print("TOOL:", request.tool)
print("TAINTED:", request.tainted)
print("DECISION:", decision.action)
print("RISK:", decision.risk_score)
print("INSPECTION:", decision.inspection_level)
print("REASONS:", decision.reasons)

assert decision.inspection_level == "DEEP"

assert any(
    "tainted context" in reason.lower()
    for reason in decision.reasons
)


# =========================================================
# TEST 10: REQUEST RESOURCE LIMIT
# =========================================================

print("\n========================================")
print("TEST 10: REQUEST RESOURCE LIMIT")
print("========================================")

firewall = FirewallInterceptor()

session_id = "RESOURCE-TEST"

# Directly consume the request budget.
# This tests ResourceGuard without executing
# 50 enterprise tools.

for _ in range(50):
    budget_ok, reason = (
        firewall.resource_guard.check_request_budget(
            session_id
        )
    )

    assert budget_ok is True


budget_ok, reason = (
    firewall.resource_guard.check_request_budget(
        session_id
    )
)

print("51ST REQUEST ALLOWED:", budget_ok)
print("REASON:", reason)

assert budget_ok is False
assert reason == "Session request limit exceeded"


# =========================================================
# TEST 11: DEEP INSPECTION RESOURCE LIMIT
# =========================================================

print("\n========================================")
print("TEST 11: DEEP INSPECTION LIMIT")
print("========================================")

firewall = FirewallInterceptor()

session_id = "DEEP-TEST"

for _ in range(10):

    budget_ok, reason = (
        firewall.resource_guard.check_deep_inspection_budget(
            session_id
        )
    )

    assert budget_ok is True


budget_ok, reason = (
    firewall.resource_guard.check_deep_inspection_budget(
        session_id
    )
)

print("11TH DEEP INSPECTION ALLOWED:", budget_ok)
print("REASON:", reason)

assert budget_ok is False
assert reason == "Deep inspection budget exceeded"


# =========================================================
# FINAL RESULT
# =========================================================

print("\n========================================")
print("ALL EXTENDED PHASE 3 FIREWALL TESTS PASSED")
print("========================================")