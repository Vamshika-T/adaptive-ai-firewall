
import pytest

from models.schemas import ToolRequest
from firewall.interceptor import FirewallInterceptor


SCENARIOS = [
    pytest.param(
        "L1 Own Calendar",
        "U001",
        "get_calendar_events",
        {
            "user_email": "alice@company.com",
            "date": "2026-09-23",
        },
        "Check my calendar meetings.",
        id="L1-own-calendar",
    ),
    pytest.param(
        "L2 Own Email",
        "U001",
        "read_email_inbox",
        {"user_email": "alice@company.com"},
        "Read my email.",
        id="L2-own-email",
    ),
    pytest.param(
        "L3 Authorized Customer",
        "U003",
        "search_customer",
        {"customer_id": "C001"},
        "Find information about my customer.",
        id="L3-authorized-customer",
    ),
    pytest.param(
        "L4 Enterprise Documents",
        "U001",
        "search_documents",
        {"keyword": "Engineering"},
        "Search engineering documents.",
        id="L4-enterprise-documents",
    ),
    pytest.param(
        "L5 Authorized CRM Update",
        "U003",
        "update_crm_record",
        {
            "customer_id": "C001",
            "field": "status",
            "value": "active",
        },
        "Update my customer's status.",
        id="L5-authorized-crm-update",
    ),
    pytest.param(
        "L6 HR Manager Employee Search",
        "U002",
        "search_employee",
        {"employee_id": "U001"},
        "Retrieve employee record U001 as an HR manager.",
        id="L6-hr-manager-employee-search",
    ),
]


@pytest.mark.parametrize(
    "name,user_id,tool,arguments,intent",
    SCENARIOS,
)
def test_legitimate_workflow(
    name,
    user_id,
    tool,
    arguments,
    intent,
):
    firewall = FirewallInterceptor()

    request = ToolRequest(
        request_id=f"LEGIT-{name}",
        session_id=f"LEGIT-SESSION-{name}",
        user_id=user_id,
        tool=tool,
        arguments=arguments,
        intent=intent,
    )

    decision, result = firewall.execute(
        request,
        original_task=intent,
    )

    print(f"\nWorkflow: {name}")
    print(f"Tool: {tool}")
    print(f"User: {user_id}")
    print(f"Decision: {decision.action}")
    print(f"Risk: {decision.risk_score}")
    print(f"Inspection: {decision.inspection_level}")
    print(f"Executed: {result is not None}")
    print(f"Reasons: {decision.reasons}")

    assert decision.action in {"ALLOW", "MONITOR"}, (
        f"{name}: legitimate request was not allowed; "
        f"decision={decision.action}, reasons={decision.reasons}"
    )

    assert result is not None, (
        f"{name}: firewall did not return a successful tool result"
    )
