"""Generalized, property-based analysis of multi-step tool workflows.

The trajectory analyser is a risk signal, not an authorization replacement.
It reasons over action properties, resource sensitivity, taint, destinations,
and structured parent-artifact references instead of relying only on one
fixed tool sequence. Deterministic authorization and information-flow checks
remain mandatory at the execution boundary.
"""

SENSITIVE_RESOURCES = {"payroll", "employees", "customers"}
READ_TOOLS = {
    "read_email_inbox",
    "query_database",
    "search_employee",
    "search_customer",
    "get_customer",
    "get_calendar_events",
    "search_documents",
    "read_document",
}
WRITE_TOOLS = {"send_email_message", "update_crm_record"}


def _is_external_email(recipient):
    recipient = str(recipient or "").strip().casefold()
    if "@" not in recipient:
        return True
    return recipient.rsplit("@", 1)[1] not in {"company.com"}


def _latest_actions(history):
    """Deduplicate inspection/execution records, keeping the latest per request."""
    latest = {}
    for action in history or []:
        request_id = action.get("request_id")
        if request_id:
            latest[request_id] = action
        else:
            # Older history entries without IDs remain usable as risk signals.
            latest[f"legacy:{len(latest)}"] = action
    return list(latest.values())


def requires_deep_trajectory_inspection(history, request):
    """Cheap pre-routing cue for cross-tool sensitive-read -> write workflows.

    This is intentionally a lightweight metadata check, not full trajectory
    analysis. It lets the router select CONTEXTUAL/DEEP before deciding whether
    to run expensive trajectory and semantic inspection.
    """
    if getattr(request, "tool", "") not in WRITE_TOOLS:
        return False
    latest_actions = _latest_actions(history)
    for action in latest_actions:
        decision = str(action.get("decision", "")).upper()
        resource = str(action.get("resource", "")).casefold()
        tool = action.get("tool")

        # Successful sensitive reads require deep inspection before a write.
        if decision == "ALLOW" and (
            resource in SENSITIVE_RESOURCES or tool == "query_database"
        ):
            return True

        # A denied attempt followed by an outbound write can be a coordinated
        # attack. Route it to DEEP so trajectory analysis can compare the
        # attempted resource with the proposed outbound content.
        if decision in {"BLOCK", "ESCALATE"} and (
            resource in SENSITIVE_RESOURCES
            or tool in {"query_database", "search_employee", "search_customer"}
        ):
            return True
    return False


def analyze_trajectory(history, request, resource, tainted):
    score = 0
    reasons = []
    critical = False

    latest_actions = _latest_actions(history)
    prior_actions = [
        action for action in latest_actions
        if action.get("decision") == "ALLOW"
    ]
    current_tool = request.tool
    current_is_write = current_tool in WRITE_TOOLS

    # Preserve a distinction between data actually read and a denied attempt.
    # A denied attempt is not evidence that data was obtained, but an outbound
    # message explicitly referring to the same restricted resource is a
    # coordinated exfiltration attempt and must be blocked.
    if current_tool == "send_email_message" and _is_external_email(
        request.arguments.get("recipient", "")
    ):
        outbound_text = " ".join(
            str(request.arguments.get(field, ""))
            for field in ("subject", "body")
        ).casefold()
        outbound_text += " " + str(getattr(request, "intent", "") or "").casefold()
        for action in latest_actions:
            if str(action.get("decision", "")).upper() not in {"BLOCK", "ESCALATE"}:
                continue
            resource = str(action.get("resource", "")).casefold()
            attempted_tool = action.get("tool")
            if attempted_tool not in {"query_database", "search_employee", "search_customer"} and resource not in SENSITIVE_RESOURCES:
                continue
            resource_terms = {
                "payroll": ("payroll", "salary", "compensation"),
                "employees": ("employee", "staff", "personnel"),
                "customers": ("customer", "client", "account record"),
            }.get(resource, (resource,) if resource else ())
            if any(term and term in outbound_text for term in resource_terms):
                score += 70
                critical = True
                reasons.append(
                    "External email references a sensitive resource after a denied access attempt"
                )
                break

    prior_sensitive_reads = [
        action for action in prior_actions
        if (
            str(action.get("resource", "")).casefold() in SENSITIVE_RESOURCES
            or action.get("tool") == "query_database"
        )
    ]
    prior_reads = [
        action for action in prior_actions
        if action.get("tool") in READ_TOOLS
    ]

    # A sensitive read followed by a write is a general cross-tool risk,
    # independent of the exact read/write tool pair.
    if current_is_write and prior_sensitive_reads:
        score += 35
        reasons.append(
            "A write action follows prior access to sensitive enterprise data"
        )

        if current_tool == "send_email_message":
            recipient = request.arguments.get("recipient", "")
            if _is_external_email(recipient):
                score += 35
                critical = True
                reasons.append(
                    "Sensitive-data access is followed by an external email destination"
                )

    # Several sensitive reads within one workflow can create cumulative
    # exposure even if no single request appears exceptional.
    if len(prior_sensitive_reads) >= 2:
        score += 15
        reasons.append(
            "Workflow has accumulated multiple sensitive-resource reads"
        )

    # Explicit parent links or context sources signal cross-step dependence.
    # They do not by themselves prove that data was leaked.
    if current_is_write and (getattr(request, "parent_artifact_ids", None) or []):
        score += 10
        reasons.append(
            "Write action depends on one or more prior artifacts"
        )

    if current_is_write and (getattr(request, "context_sources", None) or []):
        score += 10
        reasons.append(
            "Write action is grounded in retrieved or external context"
        )

    if tainted and current_is_write:
        score += 25
        reasons.append("Tainted context is influencing a write action")

    # Retain the earlier tainted sensitive-read signal.
    if (
        current_tool == "query_database"
        and tainted
        and request.arguments.get("table") in SENSITIVE_RESOURCES
    ):
        score += 30
        reasons.append(
            "Sensitive database access is influenced by tainted context"
        )

    # A retrieved message followed by a sensitive read is suspicious only
    # when there is an explicit taint signal; the mere sequence is not blocked.
    if (
        current_tool == "query_database"
        and tainted
        and any(action.get("tool") == "read_email_inbox" for action in prior_reads)
        and request.arguments.get("table") in SENSITIVE_RESOURCES
    ):
        score += 10
        reasons.append(
            "Tainted email context precedes sensitive database access"
        )

    score = min(score, 100)
    return {"score": score, "critical": critical, "reasons": reasons}
