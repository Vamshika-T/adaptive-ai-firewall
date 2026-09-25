import os

from google import genai
from google.genai import types, errors

from models.schemas import ToolRequest
from firewall.authorization import get_user


class GeminiAgent:
    def __init__(self, session_id, user_id, model="gemini-3.5-flash-lite"):
        self.session_id = session_id
        self.user_id = user_id
        self.model = model
        self.request_counter = 0

        api_key = os.getenv("GEMINI_API_KEY")

        if not api_key:
            raise RuntimeError(
                "GEMINI_API_KEY environment variable is not set."
            )

        self.client = genai.Client(api_key=api_key)

    def create_request(
        self,
        tool,
        arguments=None,
        intent="",
        function_call_id=None,
        tainted=False,
        context_sources=None
    ):
        self.request_counter += 1

        return ToolRequest(
            request_id=f"{self.session_id}-REQ{self.request_counter:03d}",
            session_id=self.session_id,
            user_id=self.user_id,
            tool=tool,
            arguments=dict(arguments or {}),
            intent=intent,
            context_sources=list(context_sources or []),
            tainted=tainted,
            source_type="gemini_agent",
            function_call_id=function_call_id
        )

    def generate(
        self,
        user_prompt,
        tools,
        system_instruction=None
    ):
        config = types.GenerateContentConfig(
            tools=[
                types.Tool(
                    function_declarations=tools
                )
            ],
            automatic_function_calling={
                "disable": True
            }
        )

        if system_instruction:
            config.system_instruction = system_instruction

        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=user_prompt,
                config=config
            )

            return response

        except errors.APIError as error:
            print(
                f"GEMINI API ERROR [{getattr(error, 'code', 'UNKNOWN')}]: "
                f"{getattr(error, 'message', str(error))}"
            )
            return None

        return response

    def extract_function_calls(self, response):
        calls = []

        if response is None:
            return calls

        for candidate in response.candidates:

            if not candidate.content:
                continue

            for part in candidate.content.parts:

                if not part.function_call:
                    continue

                function_call = part.function_call

                calls.append({
                    "id": function_call.id,
                    "name": function_call.name,
                    "arguments": dict(
                        function_call.args or {}
                    )
                })

        return calls

    def function_calls_to_requests(
        self,
        response,
        intent="",
        tainted=False,
        context_sources=None
    ):
        calls = self.extract_function_calls(response)

        requests = []

        for call in calls:

            request = self.create_request(
                tool=call["name"],
                arguments=call["arguments"],
                intent=intent,
                function_call_id=call["id"],
                tainted=tainted,
                context_sources=context_sources
            )

            requests.append(request)

        return requests

    def _get_allowed_tools(self, user_prompt):
        """
        Determine the semantic tool category of the current request.

        This only constrains Gemini's tool selection.
        It does NOT authorize the requested action.
        """

        text = user_prompt.lower()

        # ---------------------------------------------------------
        # MULTI-STEP DATABASE -> EXTERNAL EMAIL
        # ---------------------------------------------------------

        database_terms = {
            "database",
            "database table",
            "table",
            "payroll",
            "employee table",
            "customer table"
        }

        send_terms = {
            "send",
            "forward",
            "compose"
        }

        if (
            any(term in text for term in database_terms)
            and any(term in text for term in send_terms)
            and any(
                term in text
                for term in {
                    "email",
                    "mail",
                    "external",
                    "recipient"
                }
            )
        ):
            # Force the first Gemini round to retrieve the data.
            # After the approved database result is returned,
            # the normal AUTO mode can select the email tool.
            return ["query_database"]

        # ---------------------------------------------------------
        # CALENDAR
        # ---------------------------------------------------------

        calendar_terms = {
            "calendar",
            "meeting",
            "meetings",
            "appointment",
            "appointments",
            "schedule",
            "scheduled",
            "event",
            "events"
        }

        if any(term in text for term in calendar_terms):
            return ["get_calendar_events"]

        # ---------------------------------------------------------
        # EMAIL
        # ---------------------------------------------------------

        email_terms = {
            "email",
            "emails",
            "mail",
            "inbox",
            "message",
            "messages"
        }

        if any(term in text for term in email_terms):

            send_terms = {
                "send",
                "forward",
                "compose"
            }

            if any(term in text for term in send_terms):
                return ["send_email_message"]

            return ["read_email_inbox"]

        # ---------------------------------------------------------
        # EMPLOYEE LOOKUP
        # ---------------------------------------------------------

        employee_terms = {
            "employee",
            "employee id",
            "employee record",
            "employee details",
            "staff record"
        }

        lookup_terms = {
            "find",
            "lookup",
            "look up",
            "search",
            "retrieve"
        }

        if (
            any(term in text for term in employee_terms)
            and any(term in text for term in lookup_terms)
        ):
            return ["search_employee"]

        # ---------------------------------------------------------
        # CUSTOMER
        # ---------------------------------------------------------

        customer_terms = {
            "customer",
            "customer record",
            "customer details",
            "client"
        }

        if any(term in text for term in customer_terms):

            if any(
                term in text
                for term in {
                    "update",
                    "modify",
                    "change",
                    "edit"
                }
            ):
                return ["update_crm_record"]

            return [
                "search_customer",
                "get_customer"
            ]

        # ---------------------------------------------------------
        # CRM
        # ---------------------------------------------------------

        crm_terms = {
            "crm",
            "crm record"
        }

        if any(term in text for term in crm_terms):
            return ["update_crm_record"]

        # ---------------------------------------------------------
        # DOCUMENT SEARCH
        # ---------------------------------------------------------

        document_search_terms = {
            "search documents",
            "find documents",
            "locate documents",
            "document search",
            "search a document"
        }

        if any(term in text for term in document_search_terms):
            return ["search_documents"]

        # ---------------------------------------------------------
        # DOCUMENT READ
        # ---------------------------------------------------------

        document_read_terms = {
            "read document",
            "open document",
            "retrieve document",
            "document contents"
        }

        if any(term in text for term in document_read_terms):
            return ["read_document"]

        # ---------------------------------------------------------
        # DATABASE
        # ---------------------------------------------------------

        database_terms = {
            "database",
            "database table",
            "table",
            "payroll",
            "employee table",
            "customer table"
        }

        if any(term in text for term in database_terms):
            return ["query_database"]

        # Unknown or ambiguous request.
        # Let Gemini decide normally.
        return None

    def run_secured(
        self,
        user_prompt,
        tools,
        firewall,
        system_instruction=None,
        intent="",
        conversation_history=None,
        tainted=False,
        context_sources=None
    ):
        # ---------------------------------------------------------
        # AUTHENTICATED ENTERPRISE IDENTITY
        # ---------------------------------------------------------

        authenticated_user = get_user(self.user_id)

        if authenticated_user:
            authenticated_email = authenticated_user.get(
                "email",
                ""
            )
            authenticated_role = authenticated_user.get(
                "role",
                ""
            )
        else:
            authenticated_email = ""
            authenticated_role = ""

        # ---------------------------------------------------------
        # SYSTEM INSTRUCTIONS
        # ---------------------------------------------------------

        effective_intent = intent.strip() if intent else user_prompt

        default_system_instruction = f"""
You are an enterprise AI agent operating inside a
security-controlled enterprise environment.

AUTHENTICATED USER
- User ID: {self.user_id}
- Email: {authenticated_email}
- Role: {authenticated_role}

IDENTITY AND TARGET RULES

The authenticated user's identity is fixed:
- User ID: {self.user_id}
- Email: {authenticated_email}

However, the TARGET of a requested operation must come
from the user's explicit request.

IMPORTANT:
Never silently replace an explicitly requested target
with the authenticated user's identity.

Examples:

User: "Show me Bob's calendar."
Correct argument:
    user_email = bob@company.com

NOT:
    user_email = {authenticated_email}

User: "Show me my calendar."
Correct argument:
    user_email = {authenticated_email}

User: "Read Bob's emails."
Correct argument:
    user_email = bob@company.com

User: "Read my emails."
Correct argument:
    user_email = {authenticated_email}

The application firewall is responsible for deciding
whether the authenticated user is authorized to access
the requested target.

Therefore:

1. Extract the requested target faithfully.
2. Do not substitute the authenticated user for another
   explicitly requested person.
3. Do not bypass or pre-approve authorization.
4. Send the requested target to the firewall.
5. The firewall is the final authorization authority.

TOOL SELECTION

Calendar, meetings, appointments, schedule, or calendar events:
- get_calendar_events

Reading or checking email/inbox:
- read_email_inbox

Sending, composing, or forwarding email:
- send_email_message

Employee lookup by employee ID:
- search_employee

Customer lookup:
- search_customer or get_customer

CRM modification:
- update_crm_record

Searching enterprise documents:
- search_documents

Reading a known document:
- read_document

Explicit database/table requests:
- query_database

The user's requested ACTION determines the tool.

The presence of a person's name or ID does not determine
the tool.

Examples:

"Check Bob's calendar"
-> get_calendar_events
-> user_email = bob@company.com

"Check my calendar"
-> get_calendar_events
-> user_email = {authenticated_email}

"Read Bob's emails"
-> read_email_inbox
-> user_email = bob@company.com

"Read my emails"
-> read_email_inbox
-> user_email = {authenticated_email}

"Find employee U001"
-> search_employee
-> employee_id = U001

"Query the payroll table"
-> query_database
-> table = payroll

Do not use query_database for calendar, email, document,
or CRM requests when a dedicated tool exists.

SECURITY

You only select the appropriate tool and construct its
arguments.

The application security firewall is the final authority.

Every requested enterprise action must pass through the
firewall.

The firewall may:
- ALLOW
- MONITOR
- ESCALATE
- BLOCK

Never assume that a requested action is authorized.

Never modify an explicitly requested target merely because
the authenticated user is different.

Never claim an action is authorized before the firewall
evaluates it.
"""

        if system_instruction:
            effective_system_instruction = (
                default_system_instruction
                + "\n\nADDITIONAL SYSTEM INSTRUCTIONS:\n"
                + system_instruction
            )
        else:
            effective_system_instruction = default_system_instruction

        # ---------------------------------------------------------
        # DETERMINE SEMANTIC TOOL CATEGORY
        # ---------------------------------------------------------

        allowed_tools = self._get_allowed_tools(user_prompt)

        # ---------------------------------------------------------
        # BUILD CONVERSATION CONTENT
        # ---------------------------------------------------------

        contents = []

        for message in conversation_history or []:

            role = (
                "model"
                if message.get("role") == "assistant"
                else "user"
            )

            text = str(
                message.get(
                    "content",
                    ""
                )
            )

            if not text.strip():
                continue

            contents.append(
                types.Content(
                    role=role,
                    parts=[
                        types.Part.from_text(
                            text=text
                        )
                    ]
                )
            )

        # Current user request MUST be outside the history loop.

        contents.append(
            types.Content(
                role="user",
                parts=[
                    types.Part.from_text(
                        text=user_prompt
                    )
                ]
            )
        )

        # ---------------------------------------------------------
        # TOOL-CALLING LOOP
        # ---------------------------------------------------------

        tool_results = []

        max_rounds = 5

        first_round = True

        for _ in range(max_rounds):

            # -----------------------------------------------------
            # FIRST ROUND:
            #   If we know the semantic category, constrain Gemini
            #   to the appropriate function.
            #
            # FOLLOW-UP ROUNDS:
            #   Return to AUTO so Gemini can provide a normal answer
            #   after receiving the tool result.
            # -----------------------------------------------------

            config_kwargs = {
                "tools": [
                    types.Tool(
                        function_declarations=tools
                    )
                ],
                "automatic_function_calling": {
                    "disable": True
                },
                "system_instruction": effective_system_instruction
            }

            if first_round and allowed_tools:

                config_kwargs["tool_config"] = types.ToolConfig(
                    function_calling_config=types.FunctionCallingConfig(
                        mode="ANY",
                        allowed_function_names=allowed_tools
                    )
                )

            else:

                config_kwargs["tool_config"] = types.ToolConfig(
                    function_calling_config=types.FunctionCallingConfig(
                        mode="AUTO"
                    )
                )

            config = types.GenerateContentConfig(
                **config_kwargs
            )

            try:
                response = self.client.models.generate_content(
                    model=self.model,
                    contents=contents,
                    config=config
                )

            except errors.APIError as error:
                return self._model_error_result(
                    error,
                    tool_results
                )

            requests = self.function_calls_to_requests(
                response,
                intent=effective_intent,
                tainted=tainted,
                context_sources=context_sources
            )

            # -----------------------------------------------------
            # NORMAL GEMINI RESPONSE
            # -----------------------------------------------------

            if not requests:

                return {
                    "status": "COMPLETED",
                    "response": response,
                    "text": response.text,
                    "tool_results": tool_results
                }

            # -----------------------------------------------------
            # PRESERVE GEMINI FUNCTION-CALL CONTENT
            # -----------------------------------------------------

            model_content = response.candidates[0].content

            contents.append(model_content)

            function_response_parts = []

            for request in requests:

                # -------------------------------------------------
                # SECURITY BOUNDARY
                # -------------------------------------------------

                decision, result = firewall.execute(
                    request
                )

                tool_results.append({
                    "request": request,
                    "decision": decision,
                    "result": result
                })

                # -------------------------------------------------
                # FIREWALL ENFORCEMENT
                # -------------------------------------------------

                if decision.action in {
                    "BLOCK",
                    "ESCALATE"
                }:

                    return {
                        "status": decision.action,
                        "response": None,
                        "text": (
                            "The requested action was blocked "
                            "by the security firewall."
                        ),
                        "tool_results": tool_results
                    }

                # -------------------------------------------------
                # RETURN APPROVED TOOL RESULT TO GEMINI
                # -------------------------------------------------

                function_response_parts.append(
                    types.Part.from_function_response(
                        name=request.tool,
                        response={
                            "output": result
                        }
                    )
                )

            contents.append(
                types.Content(
                    role="user",
                    parts=function_response_parts
                )
            )

            # From this point onward Gemini is responding to the
            # firewall-approved tool result.
            first_round = False

        # ---------------------------------------------------------
        # MAXIMUM ROUNDS
        # ---------------------------------------------------------

        return {
            "status": "MAX_ROUNDS_EXCEEDED",
            "response": None,
            "text": (
                "The agent exceeded the maximum number "
                "of tool-calling rounds."
            ),
            "tool_results": tool_results
        }

    def _model_error_result(self, error, tool_results):
        code = getattr(error, "code", None)
        message = getattr(error, "message", str(error))

        if code == 429:
            status = "MODEL_QUOTA_ERROR"
            text = (
                "Gemini API quota was exhausted. "
                "No further model requests can be made until the quota resets."
            )

        elif code is not None and code >= 500:
            status = "MODEL_SERVICE_ERROR"
            text = (
                f"Gemini service temporarily unavailable: {message}"
            )

        else:
            status = "MODEL_API_ERROR"
            text = (
                f"Gemini API request failed: {message}"
            )

        return {
            "status": status,
            "response": None,
            "text": text,
            "tool_results": tool_results,
        }