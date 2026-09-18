def analyze_trajectory(
    history,
    request,
    resource,
    tainted
):

    score = 0
    reasons = []
    critical = False

    previous_tools = []

    for action in history:

        previous_tools.append(
            action.get(
                "tool",
                ""
            )
        )

    current_tool = request.tool

    # -----------------------------------------------------
    # Pattern 1:
    # Sensitive database access after tainted context
    # -----------------------------------------------------

    if (
        current_tool == "query_database"
        and tainted
        and request.arguments.get("table")
        in {
            "payroll",
            "employees"
        }
    ):

        score += 30

        reasons.append(
            "Sensitive database access is influenced "
            "by tainted context"
        )

    # -----------------------------------------------------
    # Pattern 2:
    # Email → sensitive database
    # -----------------------------------------------------

    if (
        "read_email_inbox" in previous_tools
        and current_tool == "query_database"
        and request.arguments.get("table")
        in {
            "payroll",
            "employees"
        }
    ):

        score += 20

        reasons.append(
            "Sensitive database access follows "
            "an earlier email-reading action"
        )

    # -----------------------------------------------------
    # Pattern 3:
    # Database → external email
    #
    # This is a critical exfiltration trajectory.
    # -----------------------------------------------------

    if (
        "query_database" in previous_tools
        and current_tool == "send_email_message"
    ):

        recipient = request.arguments.get(
            "recipient",
            ""
        )

        if (
            "@" in recipient
            and not recipient.lower().endswith(
                "@company.com"
            )
        ):

            score += 50

            critical = True

            reasons.append(
                "External email follows database access"
            )

            reasons.append(
                "Potential sensitive-data exfiltration trajectory"
            )

    # -----------------------------------------------------
    # Pattern 4:
    # Sensitive data → write action
    # -----------------------------------------------------

    if (
        "query_database" in previous_tools
        and current_tool in {
            "send_email_message",
            "update_crm_record"
        }
    ):

        score += 20

        reasons.append(
            "Write action follows sensitive database access"
        )

    # -----------------------------------------------------
    # Pattern 5:
    # Tainted context → write action
    # -----------------------------------------------------

    if (
        tainted
        and current_tool in {
            "send_email_message",
            "update_crm_record"
        }
    ):

        score += 25

        reasons.append(
            "Tainted context is influencing a write action"
        )

    # -----------------------------------------------------
    # Cap
    # -----------------------------------------------------

    score = min(
        score,
        100
    )

    return {
        "score": score,
        "critical": critical,
        "reasons": reasons
    }