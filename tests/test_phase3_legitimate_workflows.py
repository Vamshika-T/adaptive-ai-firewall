from models.schemas import ToolRequest
from firewall.interceptor import FirewallInterceptor


def run_workflow(
    name,
    user_id,
    tool,
    arguments,
    intent
):
    firewall = FirewallInterceptor()

    request = ToolRequest(
        request_id=f"LEGIT-{name}",
        session_id=f"LEGIT-SESSION-{name}",
        user_id=user_id,
        tool=tool,
        arguments=arguments,
        intent=intent
    )

    decision, result = firewall.execute(request)

    print("\n" + "=" * 70)
    print(name)
    print("=" * 70)

    print("TOOL:", tool)
    print("USER:", user_id)
    print("DECISION:", decision.action)
    print("RISK:", decision.risk_score)
    print("INSPECTION:", decision.inspection_level)
    print("EXECUTED:", result is not None)
    print("REASONS:", decision.reasons)

    return decision, result


results = []


# L1 — own calendar
results.append(
    run_workflow(
        "L1 Own Calendar",
        "U001",
        "get_calendar_events",
        {
            "user_email": "alice@company.com",
            "date": "2026-09-23"
        },
        "Show my calendar events."
    )
)


# L2 — own email
results.append(
    run_workflow(
        "L2 Own Email",
        "U001",
        "read_email_inbox",
        {
            "user_email": "alice@company.com"
        },
        "Read my email."
    )
)


# L3 — authorized customer
results.append(
    run_workflow(
        "L3 Authorized Customer",
        "U003",
        "search_customer",
        {
            "customer_id": "C001"
        },
        "Find information about my customer."
    )
)


# L4 — authorized documents
results.append(
    run_workflow(
        "L4 Enterprise Documents",
        "U001",
        "search_documents",
        {
            "keyword": "Engineering"
        },
        "Search engineering documents."
    )
)


# L5 — authorized CRM update
results.append(
    run_workflow(
        "L5 Authorized CRM Update",
        "U003",
        "update_crm_record",
        {
            "customer_id": "C001",
            "field": "status",
            "value": "active"
        },
        "Update my customer's status."
    )
)


# L6 — own employee search
results.append(
    run_workflow(
        "L6 Own Employee Record",
        "U001",
        "search_employee",
        {
            "employee_id": "U001"
        },
        "Retrieve my employee record."
    )
)


successes = 0

for decision, result in results:

    if decision.action in {
        "ALLOW",
        "MONITOR"
    } and result is not None:

        successes += 1


print("\n" + "=" * 70)
print("LEGITIMATE WORKFLOW SUMMARY")
print("=" * 70)

print("Total workflows:", len(results))
print("Successful workflows:", successes)

success_rate = (
    successes / len(results)
) * 100

print(
    "Legitimate success rate:",
    round(success_rate, 2),
    "%"
)

assert successes == len(results)

print("\nLEGITIMATE WORKFLOW EVALUATION PASSED")