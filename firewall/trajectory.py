def analyze_trajectory(history, request, resource, tainted):
    """
    Analyze the current action together with previous
    actions in the same session.
    """

    score = 0
    reasons = []

    previous_tools = []

    for action in history:
        previous_tools.append(
            action.get("tool", "")
        )

    current_tool = request.tool

    # Untrusted email followed by sensitive access.
    if (
        "read_email_inbox" in previous_tools
        and current_tool == "query_database"
        and tainted
    ):
        score += 30
        reasons.append(
            "Sensitive database access follows tainted email context"
        )

    # Database followed by external email.
    if (
        "query_database" in previous_tools
        and current_tool == "send_email_message"
    ):
        recipient = request.arguments.get(
            "recipient",
            ""
        )

        if "@" in recipient and not recipient.endswith(
            "@company.com"
        ):
            score += 35
            reasons.append(
                "External email follows database access"
            )

    # Tainted context + write operation.
    if tainted and current_tool in {
        "send_email_message",
        "update_crm_record"
    }:
        score += 25
        reasons.append(
            "Tainted context is influencing a write action"
        )

    return {
        "score": min(score, 100),
        "reasons": reasons
    }