from models.schemas import ToolRequest
from firewall.interceptor import FirewallInterceptor


def make_request(
    request_id,
    session_id,
    user_id="U001",
    tool="get_calendar_events",
    arguments=None
):
    return ToolRequest(
        request_id=request_id,
        session_id=session_id,
        user_id=user_id,
        tool=tool,
        arguments=arguments or {
            "user_email": "alice@company.com",
            "date": "2026-09-23"
        },
        intent="Retrieve my calendar."
    )


# =========================================================
# TEST 1 — REQUEST LIMIT THROUGH FIREWALL
# =========================================================

firewall = FirewallInterceptor()

session_id = "GDOS-REQUEST-SESSION"

successful = 0
blocked = 0

for i in range(50):
    req = make_request(
        f"GDOS-{i:03d}",
        session_id
    )

    decision, result = firewall.execute(req)

    if decision.action == "ALLOW":
        successful += 1

print("\nREQUEST BUDGET")
print("Successful requests before exhaustion:", successful)

# 51st request
req = make_request(
    "GDOS-051",
    session_id
)

decision, result = firewall.execute(req)

print("51st decision:", decision.action)
print("51st risk:", decision.risk_score)
print("51st reasons:", decision.reasons)
print("51st executed:", result is not None)

assert decision.action == "BLOCK"
assert result is None

assert any(
    "request limit" in reason.lower()
    for reason in decision.reasons
)


# =========================================================
# TEST 2 — DEEP INSPECTION LIMIT THROUGH FIREWALL
# =========================================================

firewall = FirewallInterceptor()

session_id = "GDOS-DEEP-SESSION"

deep_count = 0

for i in range(10):

    req = make_request(
        f"DEEP-{i:03d}",
        session_id,
        tool="send_email_message",
        arguments={
            "sender": "alice@company.com",
            "recipient": "bob@company.com",
            "subject": "Review",
            "body": "Review this."
        }
    )

    req.tainted = True

    decision, result = firewall.execute(req)

    print(
        f"Deep request {i + 1}:",
        decision.action,
        decision.inspection_level
    )

    if decision.inspection_level == "DEEP":
        deep_count += 1


# 11th deep request
req = make_request(
    "DEEP-011",
    session_id,
    tool="send_email_message",
    arguments={
        "sender": "alice@company.com",
        "recipient": "bob@company.com",
        "subject": "Review",
        "body": "Review this."
    }
)

req.tainted = True

decision, result = firewall.execute(req)

print("\n11th deep request:")
print("Decision:", decision.action)
print("Risk:", decision.risk_score)
print("Inspection:", decision.inspection_level)
print("Reasons:", decision.reasons)

assert decision.action == "BLOCK"
assert result is None

assert any(
    "deep inspection budget" in reason.lower()
    for reason in decision.reasons
)


# =========================================================
# TEST 3 — SESSION ISOLATION
# =========================================================

firewall = FirewallInterceptor()

for i in range(50):
    req = make_request(
        f"SESSION-A-{i}",
        "SESSION-A"
    )

    firewall.execute(req)


# Session B must still have budget.
req = make_request(
    "SESSION-B-001",
    "SESSION-B"
)

decision, result = firewall.execute(req)

print("\nSESSION ISOLATION")
print("Session B decision:", decision.action)

assert decision.action == "ALLOW"


# =========================================================
# TEST 4 — RESET
# =========================================================

firewall.resource_guard.reset_session(
    "SESSION-A"
)

req = make_request(
    "SESSION-A-RESET",
    "SESSION-A"
)

decision, result = firewall.execute(req)

print("\nAFTER RESET")
print("Decision:", decision.action)

assert decision.action == "ALLOW"


print("\n" + "=" * 70)
print("GDoS / RESOURCE PROTECTION PASSED")
print("=" * 70)