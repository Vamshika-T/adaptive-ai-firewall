from google.genai import types


TOOLS = [
    types.FunctionDeclaration(
        name="get_calendar_events",
        description=(
            "Retrieve calendar events or meetings for a specific enterprise "
            "user on a specific date. Use this tool when the user asks about "
            "their meetings, appointments, schedule, or calendar events. "
            "Do NOT use query_database for calendar questions."
        ),
        parameters_json_schema={
            "type": "object",
            "properties": {
                "user_email": {
                    "type": "string",
                    "description": (
                        "Email address of the enterprise user whose calendar "
                        "should be retrieved."
                    )
                },
                "date": {
                    "type": "string",
                    "description": (
                        "Calendar date in YYYY-MM-DD format."
                    )
                }
            },
            "required": [
                "user_email",
                "date"
            ]
        }
    ),

    types.FunctionDeclaration(
        name="read_email_inbox",
        description=(
            "Read the email inbox of a specific enterprise user. Use this "
            "tool when the user asks to read, inspect, check, or summarize "
            "their emails or inbox. Do NOT use query_database for email "
            "questions."
        ),
        parameters_json_schema={
            "type": "object",
            "properties": {
                "user_email": {
                    "type": "string",
                    "description": (
                        "Email address of the enterprise user's inbox."
                    )
                }
            },
            "required": [
                "user_email"
            ]
        }
    ),

    types.FunctionDeclaration(
        name="send_email_message",
        description=(
            "Send an email from an enterprise user's account to another "
            "recipient. Use this tool only when the user explicitly asks "
            "to send, compose, or forward an email. This is an external "
            "write action and may be restricted by the security firewall."
        ),
        parameters_json_schema={
            "type": "object",
            "properties": {
                "sender": {
                    "type": "string",
                    "description": (
                        "Email address of the authenticated enterprise "
                        "user sending the message."
                    )
                },
                "recipient": {
                    "type": "string",
                    "description": (
                        "Email address of the intended recipient."
                    )
                },
                "subject": {
                    "type": "string",
                    "description": "Subject of the email."
                },
                "body": {
                    "type": "string",
                    "description": "Body/content of the email."
                }
            },
            "required": [
                "sender",
                "recipient",
                "subject",
                "body"
            ]
        }
    ),

    types.FunctionDeclaration(
        name="query_database",
        description=(
            "Query a structured enterprise database table. Use this tool "
            "only when the user explicitly asks for information stored in "
            "a database table such as employees, customers, or payroll. "
            "Do NOT use this tool for calendar, email, document, or CRM "
            "requests. The payroll table contains sensitive employee "
            "compensation information and is subject to strict firewall "
            "authorization and security checks."
        ),
        parameters_json_schema={
            "type": "object",
            "properties": {
                "table": {
                    "type": "string",
                    "enum": [
                        "employees",
                        "customers",
                        "payroll"
                    ],
                    "description": (
                        "Enterprise database table to query. "
                        "employees contains employee records, "
                        "customers contains customer records, and "
                        "payroll contains sensitive compensation data."
                    )
                }
            },
            "required": [
                "table"
            ]
        }
    ),

    types.FunctionDeclaration(
        name="search_employee",
        description=(
            "Search for a specific employee using their employee ID. "
            "Use this when the user asks to find or look up an employee "
            "record by employee ID."
        ),
        parameters_json_schema={
            "type": "object",
            "properties": {
                "employee_id": {
                    "type": "string",
                    "description": (
                        "Employee identifier, for example U001."
                    )
                }
            },
            "required": [
                "employee_id"
            ]
        }
    ),

    types.FunctionDeclaration(
        name="search_customer",
        description=(
            "Search for a customer using a customer ID. Use this when "
            "the user asks to find a customer by customer identifier."
        ),
        parameters_json_schema={
            "type": "object",
            "properties": {
                "customer_id": {
                    "type": "string",
                    "description": (
                        "Customer identifier, for example C001."
                    )
                }
            },
            "required": [
                "customer_id"
            ]
        }
    ),

    types.FunctionDeclaration(
        name="get_customer",
        description=(
            "Retrieve a specific customer CRM record using a customer ID. "
            "Use this when the user asks for details about a customer's "
            "CRM record."
        ),
        parameters_json_schema={
            "type": "object",
            "properties": {
                "customer_id": {
                    "type": "string",
                    "description": (
                        "Customer identifier, for example C001."
                    )
                }
            },
            "required": [
                "customer_id"
            ]
        }
    ),

    types.FunctionDeclaration(
        name="update_crm_record",
        description=(
            "Update a field in a customer's CRM record. Use this only when "
            "the user explicitly requests a CRM record modification. "
            "This is a write operation and is subject to firewall "
            "authorization, context, and risk checks."
        ),
        parameters_json_schema={
            "type": "object",
            "properties": {
                "customer_id": {
                    "type": "string",
                    "description": (
                        "Customer identifier, for example C001."
                    )
                },
                "field": {
                    "type": "string",
                    "description": (
                        "CRM field that should be modified."
                    )
                },
                "value": {
                    "type": "string",
                    "description": (
                        "New value for the CRM field."
                    )
                }
            },
            "required": [
                "customer_id",
                "field",
                "value"
            ]
        }
    ),

    types.FunctionDeclaration(
        name="search_documents",
        description=(
            "Search enterprise documents by keyword in document titles "
            "or content. Use this when the user asks to find, search, "
            "or locate enterprise documents."
        ),
        parameters_json_schema={
            "type": "object",
            "properties": {
                "keyword": {
                    "type": "string",
                    "description": (
                        "Keyword or phrase to search for in enterprise "
                        "documents."
                    )
                }
            },
            "required": [
                "keyword"
            ]
        }
    ),

    types.FunctionDeclaration(
        name="read_document",
        description=(
            "Read the contents of a specific enterprise document using "
            "its document ID. Use this only when the user asks to read "
            "or retrieve a known document."
        ),
        parameters_json_schema={
            "type": "object",
            "properties": {
                "document_id": {
                    "type": "string",
                    "description": (
                        "Enterprise document identifier, for example DOC001."
                    )
                }
            },
            "required": [
                "document_id"
            ]
        }
    )
]