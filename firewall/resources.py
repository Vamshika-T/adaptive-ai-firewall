RESOURCE_POLICIES = {

    "email": {
        "sensitivity": "INTERNAL"
    },

    "calendar": {
        "sensitivity": "INTERNAL"
    },

    "employees": {
        "sensitivity": "RESTRICTED"
    },

    "customers": {
        "sensitivity": "CONFIDENTIAL"
    },

    "payroll": {
        "sensitivity": "RESTRICTED"
    },

    "documents": {
        "sensitivity": "INTERNAL"
    },

    "unknown": {
        "sensitivity": "RESTRICTED"
    }
}


SENSITIVITY_LEVELS = {

    "PUBLIC": 0,

    "INTERNAL": 25,

    "CONFIDENTIAL": 50,

    "RESTRICTED": 75
}


def get_resource(
    tool_name,
    arguments
):

    arguments = arguments or {}

    if tool_name == "query_database":

        return arguments.get(
            "table",
            "unknown"
        )

    if tool_name == "search_employee":

        return "employees"

    if tool_name in {
        "search_customer",
        "get_customer",
        "update_crm_record"
    }:

        return "customers"

    if tool_name in {
        "read_email_inbox",
        "send_email_message"
    }:

        return "email"

    if tool_name == "get_calendar_events":

        return "calendar"

    if tool_name in {
        "search_documents",
        "read_document"
    }:

        return "documents"

    return "unknown"


def get_sensitivity(
    resource
):

    policy = RESOURCE_POLICIES.get(
        resource
    )

    if policy is None:

        return "RESTRICTED"

    return policy["sensitivity"]


def get_sensitivity_score(
    resource
):

    sensitivity = get_sensitivity(
        resource
    )

    return SENSITIVITY_LEVELS.get(
        sensitivity,
        75
    )