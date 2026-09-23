from google.genai import types


TOOLS = [
    types.FunctionDeclaration(
        name="get_calendar_events",
        description=(
            "Retrieve calendar events for a specific user "
            "on a specific date."
        ),
        parameters_json_schema={
            "type": "object",
            "properties": {
                "user_email": {
                    "type": "string",
                    "description": "Email address of the user."
                },
                "date": {
                    "type": "string",
                    "description": (
                        "Date to retrieve calendar events for, "
                        "in YYYY-MM-DD format."
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
            "Read the email inbox of a specific enterprise user."
        ),
        parameters_json_schema={
            "type": "object",
            "properties": {
                "user_email": {
                    "type": "string",
                    "description": "Email address of the user."
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
            "Send an email message from an enterprise user's "
            "account to a recipient."
        ),
        parameters_json_schema={
            "type": "object",
            "properties": {
                "sender": {
                    "type": "string",
                    "description": (
                        "Email address of the authenticated sender."
                    )
                },
                "recipient": {
                    "type": "string",
                    "description": (
                        "Email address of the recipient."
                    )
                },
                "subject": {
                    "type": "string",
                    "description": "Email subject."
                },
                "body": {
                    "type": "string",
                    "description": "Email message body."
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
            "Query an enterprise database table. "
            "Access to sensitive tables such as payroll "
            "is controlled by the security firewall."
        ),
        parameters_json_schema={
            "type": "object",
            "properties": {
                "table": {
                    "type": "string",
                    "description": (
                        "Database table to query, such as "
                        "employees, customers, or payroll."
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
            "Search for an employee using the employee ID."
        ),
        parameters_json_schema={
            "type": "object",
            "properties": {
                "employee_id": {
                    "type": "string",
                    "description": "Employee ID to search for."
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
            "Search for a customer using the customer ID."
        ),
        parameters_json_schema={
            "type": "object",
            "properties": {
                "customer_id": {
                    "type": "string",
                    "description": "Customer ID to search for."
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
            "Retrieve a customer CRM record using the "
            "customer ID."
        ),
        parameters_json_schema={
            "type": "object",
            "properties": {
                "customer_id": {
                    "type": "string",
                    "description": "Customer ID to retrieve."
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
            "Update a field in a customer CRM record. "
            "This is a write operation and is subject to "
            "firewall authorization and security checks."
        ),
        parameters_json_schema={
            "type": "object",
            "properties": {
                "customer_id": {
                    "type": "string",
                    "description": "Customer ID to update."
                },
                "field": {
                    "type": "string",
                    "description": (
                        "Name of the customer field to update."
                    )
                },
                "value": {
                    "type": "string",
                    "description": (
                        "New value for the specified field."
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
            "Search enterprise documents by a keyword "
            "in the document title or content."
        ),
        parameters_json_schema={
            "type": "object",
            "properties": {
                "keyword": {
                    "type": "string",
                    "description": (
                        "Keyword to search for in document "
                        "titles or content."
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
            "Read an enterprise document using its "
            "document ID."
        ),
        parameters_json_schema={
            "type": "object",
            "properties": {
                "document_id": {
                    "type": "string",
                    "description": "Document ID to retrieve."
                }
            },
            "required": [
                "document_id"
            ]
        }
    )
]