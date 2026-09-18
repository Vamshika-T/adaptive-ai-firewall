READ_TOOLS = {
    "read_email_inbox",
    "search_employee",
    "search_customer",
    "get_customer",
    "get_calendar_events",
    "search_documents",
    "read_document"
}


DATABASE_TOOLS = {
    "query_database"
}


WRITE_TOOLS = {
    "send_email_message",
    "update_crm_record"
}


def analyze_intent(request):
    """
    Lightweight intent consistency analysis.

    This is deliberately transparent and deterministic.
    A future LLM-based semantic component can be integrated
    without changing the firewall interface.
    """

    intent = request.intent.lower()

    tool = request.tool

    if not intent:
        return {
            "consistent": True,
            "reason": "No explicit intent supplied"
        }

    if any(
        word in intent
        for word in [
            "meeting",
            "calendar",
            "schedule"
        ]
    ):
        if tool == "get_calendar_events":
            return {
                "consistent": True,
                "reason": "Calendar action matches intent"
            }

        return {
            "consistent": False,
            "reason": "Tool does not match calendar intent"
        }

    if any(
        word in intent
        for word in [
            "email",
            "mail"
        ]
    ):
        if tool in {
            "read_email_inbox",
            "send_email_message"
        }:
            return {
                "consistent": True,
                "reason": "Email action matches intent"
            }

    if any(
        word in intent
        for word in [
            "customer",
            "client"
        ]
    ):
        if tool in {
            "search_customer",
            "get_customer",
            "update_crm_record"
        }:
            return {
                "consistent": True,
                "reason": "Customer action matches intent"
            }

    if any(
        word in intent
        for word in [
            "document",
            "file"
        ]
    ):
        if tool in {
            "search_documents",
            "read_document"
        }:
            return {
                "consistent": True,
                "reason": "Document action matches intent"
            }

    if any(
        word in intent
        for word in [
            "payroll",
            "salary"
        ]
    ):
        if tool == "query_database":
            return {
                "consistent": True,
                "reason": "Payroll database action matches intent"
            }

    return {
        "consistent": False,
        "reason": "Tool is not clearly consistent with stated intent"
    }