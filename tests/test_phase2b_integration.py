from models.schemas import ToolRequest
from firewall.interceptor import FirewallInterceptor


def make_request(
    request_id,
    session_id,
    tool,
    arguments=None,
    context_sources=None,
    tainted=False
):
    return ToolRequest(
        request_id=request_id,
        session_id=session_id,
        user_id="U001",
        tool=tool,
        arguments=arguments or {},
        intent="",
        context_sources=context_sources or [],
        tainted=tainted
    )


firewall = FirewallInterceptor()


# ---------------------------------------------------------
# TEST 1: Trusted source should not taint the session
# ---------------------------------------------------------

request = make_request(
    "REQ001",
    "SESSION001",
    "read_email_inbox",
    {"user_email": "alice@company.com"},
    ["email:E001"]
)

decision = firewall.inspect(request)

assert firewall.provenance_tracker.is_tainted(
    "SESSION001"
) is False

print("TEST 1 PASSED: Trusted source does not taint session")


# ---------------------------------------------------------
# TEST 2: Untrusted source should taint the session
# ---------------------------------------------------------

request = make_request(
    "REQ002",
    "SESSION002",
    "read_email_inbox",
    {"user_email": "alice@company.com"},
    ["email:E003"]
)

decision = firewall.inspect(request)

assert firewall.provenance_tracker.is_tainted(
    "SESSION002"
) is True

print("TEST 2 PASSED: Untrusted source automatically taints session")


# ---------------------------------------------------------
# TEST 3: Taint propagates to later request
# ---------------------------------------------------------

request = make_request(
    "REQ003",
    "SESSION003",
    "read_email_inbox",
    {"user_email": "alice@company.com"},
    ["email:E003"]
)

firewall.inspect(request)


# No tainted=True here!
request = make_request(
    "REQ004",
    "SESSION003",
    "send_email_message",
    {
        "sender": "alice@company.com",
        "recipient": "external@example.com",
        "subject": "Data",
        "body": "Sensitive information"
    }
)

decision = firewall.inspect(request)

assert decision.action in [
    "MONITOR",
    "ESCALATE",
    "BLOCK"
]

history = firewall.get_history("SESSION003")

assert history[-1]["tainted"] is True

print(
    "TEST 3 PASSED: Taint propagated to later request automatically"
)


# ---------------------------------------------------------
# TEST 4: Trusted external source must remain trusted
# ---------------------------------------------------------

request = make_request(
    "REQ005",
    "SESSION004",
    "read_email_inbox",
    {"user_email": "alice@company.com"},
    ["email:E005"]
)

firewall.inspect(request)

assert firewall.provenance_tracker.is_tainted(
    "SESSION004"
) is False

print(
    "TEST 4 PASSED: Trusted external source does not create taint"
)


# ---------------------------------------------------------
# TEST 5: Unknown source is treated conservatively
# ---------------------------------------------------------

request = make_request(
    "REQ006",
    "SESSION005",
    "read_email_inbox",
    {"user_email": "alice@company.com"},
    ["email:UNKNOWN"]
)

firewall.inspect(request)

assert firewall.provenance_tracker.is_tainted(
    "SESSION005"
) is True

print(
    "TEST 5 PASSED: Unknown provenance is treated conservatively"
)


print("\nALL PHASE 2B INTEGRATION TESTS PASSED")