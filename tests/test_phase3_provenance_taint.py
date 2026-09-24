from models.schemas import ToolRequest
from firewall.interceptor import FirewallInterceptor


def make_request(
    request_id,
    session_id,
    user_id,
    tool,
    arguments,
    intent,
    tainted=False,
    context_sources=None
):
    return ToolRequest(
        request_id=request_id,
        session_id=session_id,
        user_id=user_id,
        tool=tool,
        arguments=arguments,
        intent=intent,
        tainted=tainted,
        context_sources=context_sources or []
    )


# =========================================================
# CLEAN CONTEXT
# =========================================================

firewall_clean = FirewallInterceptor()

clean_request = make_request(
    "TAINT-001",
    "TAINT-SESSION-CLEAN",
    "U001",
    "send_email_message",
    {
        "sender": "alice@company.com",
        "recipient": "bob@company.com",
        "subject": "Update",
        "body": "Normal project update."
    },
    "Send a normal project update.",
    tainted=False,
    context_sources=[]
)

clean_decision, clean_result = firewall_clean.execute(
    clean_request
)

print("\nCLEAN CONTEXT")
print("Decision:", clean_decision.action)
print("Risk:", clean_decision.risk_score)
print("Inspection:", clean_decision.inspection_level)
print("Reasons:", clean_decision.reasons)


# =========================================================
# TAINTED CONTEXT
# =========================================================

firewall_tainted = FirewallInterceptor()

tainted_request = make_request(
    "TAINT-002",
    "TAINT-SESSION-TAINTED",
    "U001",
    "send_email_message",
    {
        "sender": "alice@company.com",
        "recipient": "bob@company.com",
        "subject": "Review",
        "body": "Please review this information."
    },
    "Send an email.",
    tainted=True,
    context_sources=["email:E003"]
)

tainted_decision, tainted_result = (
    firewall_tainted.execute(
        tainted_request
    )
)

print("\nTAINTED CONTEXT")
print("Decision:", tainted_decision.action)
print("Risk:", tainted_decision.risk_score)
print("Inspection:", tainted_decision.inspection_level)
print("Reasons:", tainted_decision.reasons)


# Tainted context must cause deeper inspection.
assert tainted_decision.inspection_level == "DEEP"

assert any(
    "tainted" in reason.lower()
    for reason in tainted_decision.reasons
)


# =========================================================
# TAINTED CONTEXT → CRM WRITE
# =========================================================

firewall_crm = FirewallInterceptor()

crm_request = make_request(
    "TAINT-003",
    "TAINT-SESSION-CRM",
    "U003",
    "update_crm_record",
    {
        "customer_id": "C001",
        "field": "status",
        "value": "approved"
    },
    "Update the customer record.",
    tainted=True,
    context_sources=["email:E003"]
)

crm_decision, crm_result = firewall_crm.execute(
    crm_request
)

print("\nTAINTED CRM WRITE")
print("Decision:", crm_decision.action)
print("Risk:", crm_decision.risk_score)
print("Inspection:", crm_decision.inspection_level)
print("Reasons:", crm_decision.reasons)

assert crm_decision.inspection_level == "DEEP"

assert any(
    "tainted" in reason.lower()
    for reason in crm_decision.reasons
)


print("\n" + "=" * 70)
print("PROVENANCE / TAINT EVALUATION PASSED")
print("=" * 70)