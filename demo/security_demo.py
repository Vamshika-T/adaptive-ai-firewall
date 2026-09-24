"""
Final offline security demonstration.

This is intended for:
- project demonstration
- viva
- screenshots
- recording the firewall behavior

It uses the actual FirewallInterceptor.
"""


from firewall.interceptor import FirewallInterceptor

from models.schemas import ToolRequest


def show_result(
    title,
    request,
    decision,
    result
):

    print("\n")

    print("=" * 80)

    print(title)

    print("=" * 80)

    print(
        "USER:",
        request.user_id
    )

    print(
        "TOOL:",
        request.tool
    )

    print(
        "ARGUMENTS:",
        request.arguments
    )

    print(
        "DECISION:",
        decision.action
    )

    print(
        "RISK:",
        decision.risk_score
    )

    print(
        "INSPECTION:",
        decision.inspection_level
    )

    print(
        "TOOL EXECUTED:",
        result is not None
    )

    print(
        "REASONS:"
    )

    for reason in decision.reasons:

        print(
            "  -",
            reason
        )


def main():

    # ========================================================
    # 1. LEGITIMATE CALENDAR
    # ========================================================

    firewall = FirewallInterceptor()

    request = ToolRequest(

        request_id="DEMO-001",

        session_id="DEMO-LEGIT",

        user_id="U001",

        tool="get_calendar_events",

        arguments={

            "user_email":
                "alice@company.com",

            "date":
                "2026-09-23",
        },

        intent=(
            "Check my calendar meetings."
        ),
    )

    decision, result = (
        firewall.execute(
            request
        )
    )

    show_result(

        "1. LEGITIMATE REQUEST",

        request,

        decision,

        result
    )

    # ========================================================
    # 2. UNAUTHORIZED PAYROLL
    # ========================================================

    request = ToolRequest(

        request_id="DEMO-002",

        session_id="DEMO-PAYROLL",

        user_id="U001",

        tool="query_database",

        arguments={
            "table": "payroll"
        },

        intent=(
            "Access the payroll database."
        ),
    )

    decision, result = (
        firewall.execute(
            request
        )
    )

    show_result(

        "2. UNAUTHORIZED PAYROLL ACCESS",

        request,

        decision,

        result
    )

    # ========================================================
    # 3. CROSS USER CALENDAR
    # ========================================================

    request = ToolRequest(

        request_id="DEMO-003",

        session_id="DEMO-CROSS-USER",

        user_id="U001",

        tool="get_calendar_events",

        arguments={

            "user_email":
                "bob@company.com",

            "date":
                "2026-09-23",
        },

        intent=(
            "Retrieve Bob's calendar."
        ),
    )

    decision, result = (
        firewall.execute(
            request
        )
    )

    show_result(

        "3. CROSS-USER CALENDAR ACCESS",

        request,

        decision,

        result
    )

    # ========================================================
    # 4. DATABASE -> EXTERNAL EMAIL
    # ========================================================

    trajectory_firewall = (
        FirewallInterceptor()
    )

    session_id = (
        "DEMO-TRAJECTORY"
    )

    database_request = ToolRequest(

        request_id=(
            "DEMO-TRAJECTORY-001"
        ),

        session_id=session_id,

        user_id="U002",

        tool="query_database",

        arguments={
            "table": "employees"
        },

        intent=(
            "Look up employee information."
        ),
    )

    first_decision, first_result = (
        trajectory_firewall.execute(
            database_request
        )
    )

    print("\n")

    print("=" * 80)

    print(
        "4. MULTI-STEP DATABASE -> "
        "EXTERNAL EMAIL ATTACK"
    )

    print("=" * 80)

    print(
        "STEP 1:",
        database_request.tool
    )

    print(
        "STEP 1 DECISION:",
        first_decision.action
    )

    email_request = ToolRequest(

        request_id=(
            "DEMO-TRAJECTORY-002"
        ),

        session_id=session_id,

        user_id="U002",

        tool="send_email_message",

        arguments={

            "sender":
                "bob@company.com",

            "recipient":
                "external@example.com",

            "subject":
                "Employee Information",

            "body":
                (
                    "Employee information from "
                    "the previous database operation."
                ),
        },

        intent=(
            "Send employee information externally."
        ),
    )

    second_decision, second_result = (
        trajectory_firewall.execute(
            email_request
        )
    )

    print(
        "STEP 2:",
        email_request.tool
    )

    print(
        "STEP 2 DECISION:",
        second_decision.action
    )

    print(
        "STEP 2 RISK:",
        second_decision.risk_score
    )

    print(
        "STEP 2 INSPECTION:",
        second_decision.inspection_level
    )

    print(
        "STEP 2 TOOL EXECUTED:",
        second_result is not None
    )

    print(
        "STEP 2 REASONS:"
    )

    for reason in (
        second_decision.reasons
    ):

        print(
            "  -",
            reason
        )

    # ========================================================
    # 5. GDoS
    # ========================================================

    gdos_firewall = (
        FirewallInterceptor()
    )

    gdos_session = (
        "DEMO-GDOS"
    )

    final_decision = None

    final_result = None

    for index in range(51):

        request = ToolRequest(

            request_id=(
                f"DEMO-GDOS-"
                f"{index + 1:03d}"
            ),

            session_id=gdos_session,

            user_id="U001",

            tool="get_calendar_events",

            arguments={

                "user_email":
                    "alice@company.com",

                "date":
                    "2026-09-23",
            },

            intent=(
                "Check my calendar."
            ),
        )

        final_decision, final_result = (
            gdos_firewall.execute(
                request
            )
        )

    print("\n")

    print("=" * 80)

    print(
        "5. GDoS REQUEST LIMIT"
    )

    print("=" * 80)

    print(
        "REQUEST NUMBER: 51"
    )

    print(
        "DECISION:",
        final_decision.action
    )

    print(
        "RISK:",
        final_decision.risk_score
    )

    print(
        "TOOL EXECUTED:",
        final_result is not None
    )

    print(
        "REASONS:",
        final_decision.reasons
    )

    print("\n")

    print("=" * 80)

    print(
        "SECURITY DEMO COMPLETE"
    )

    print("=" * 80)


if __name__ == "__main__":

    main()