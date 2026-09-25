def analyze_intent(
    request
):

    intent = (
        request.intent
        or ""
    ).lower()

    tool = request.tool

    # No explicit intent means we cannot establish
    # a mismatch. Do not manufacture one.
    if not intent:

        return {
            "consistent": True,
            "reason": "No explicit intent supplied"
        }

    # -----------------------------------------------------
    # Multi-step database -> email
    # -----------------------------------------------------

    if (
        tool == "query_database"
        and any(
            word in intent
            for word in [
                "database",
                "employees database",
                "employee information"
            ]
        )
        and any(
            word in intent
            for word in [
                "email",
                "send",
                "external recipient"
            ]
        )
    ):

        return {
            "consistent": True,
            "reason": (
                "Database action matches the first step "
                "of the stated multi-step intent"
            )
        }

    # -----------------------------------------------------
    # Calendar
    # -----------------------------------------------------

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
                "reason": "Calendar action matches stated intent"
            }

        return {
            "consistent": False,
            "reason": (
                "Tool does not match the stated "
                "calendar-related intent"
            )
        }

    # -----------------------------------------------------
    # Email
    # -----------------------------------------------------

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
                "reason": "Email action matches stated intent"
            }

        return {
            "consistent": False,
            "reason": (
                "Tool does not match the stated "
                "email-related intent"
            )
        }

    # -----------------------------------------------------
    # Customer
    # -----------------------------------------------------

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
                "reason": (
                    "Customer action matches stated intent"
                )
            }

        return {
            "consistent": False,
            "reason": (
                "Tool does not match the stated "
                "customer-related intent"
            )
        }

    # -----------------------------------------------------
    # Document
    # -----------------------------------------------------

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
                "reason": (
                    "Document action matches stated intent"
                )
            }

        return {
            "consistent": False,
            "reason": (
                "Tool does not match the stated "
                "document-related intent"
            )
        }

    # -----------------------------------------------------
    # Payroll
    # -----------------------------------------------------

    if any(
        word in intent
        for word in [
            "payroll",
            "salary",
            "compensation"
        ]
    ):

        if (
            tool == "query_database"
            and request.arguments.get("table")
            == "payroll"
        ):

            return {
                "consistent": True,
                "reason": (
                    "Payroll database action matches "
                    "stated intent"
                )
            }

        return {
            "consistent": False,
            "reason": (
                "Tool does not match the stated "
                "payroll-related intent"
            )
        }

    # -----------------------------------------------------
    # Unknown intent category
    # -----------------------------------------------------

    return {
        "consistent": True,
        "reason": (
            "Intent category is not explicitly modeled"
        )
    }