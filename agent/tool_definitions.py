TOOLS = [

    {
        "name": "get_calendar_events",
        "description": (
            "Retrieve calendar events for a user's "
            "email address on a specific date."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "user_email": {
                    "type": "string",
                    "description": (
                        "The user's company email address."
                    )
                },
                "date": {
                    "type": "string",
                    "description": (
                        "Date in YYYY-MM-DD format."
                    )
                }
            },
            "required": [
                "user_email",
                "date"
            ]
        }
    },

    {
        "name": "search_employee",
        "description": (
            "Search enterprise employee records "
            "using an employee identifier."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "employee_id": {
                    "type": "string",
                    "description": (
                        "The employee identifier."
                    )
                }
            },
            "required": [
                "employee_id"
            ]
        }
    },

    {
        "name": "read_email_inbox",
        "description": (
            "Read emails available in the user's "
            "enterprise inbox."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "user_email": {
                    "type": "string",
                    "description": (
                        "The user's company email address."
                    )
                }
            },
            "required": [
                "user_email"
            ]
        }
    }
]