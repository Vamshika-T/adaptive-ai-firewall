from models.schemas import (
    ToolRequest,
    ActionRecord
)

from models.decisions import SecurityDecision

from tools.registry import execute_tool

from firewall.authorization import (
    get_user,
    check_rbac
)

from firewall.abac import (
    check_abac,
    filter_document_results
)

from firewall.resources import (
    get_resource,
    get_sensitivity,
    get_sensitivity_score
)

from firewall.intent import (
    analyze_intent
)

from firewall.trajectory import (
    analyze_trajectory
)

from firewall.risk_engine import (
    calculate_risk,
    decide_action
)


class FirewallInterceptor:

    def __init__(self):

        self.session_history = {}

    # -----------------------------------------------------
    # SESSION HISTORY
    # -----------------------------------------------------

    def get_history(
        self,
        session_id
    ):

        return self.session_history.get(
            session_id,
            []
        )

    # -----------------------------------------------------
    # RECORD ACTION
    # -----------------------------------------------------

    def add_history(
        self,
        request,
        resource,
        decision,
        tainted=False
    ):

        record = ActionRecord(

            request_id=request.request_id,

            session_id=request.session_id,

            user_id=request.user_id,

            tool=request.tool,

            resource=resource,

            decision=decision.action,

            risk_score=decision.risk_score,

            tainted=tainted,

            # Provenance belongs to the separate
            # provenance/taint phase.
            provenance_trusted=True
        )

        if (
            request.session_id
            not in self.session_history
        ):

            self.session_history[
                request.session_id
            ] = []

        self.session_history[
            request.session_id
        ].append(
            record.model_dump()
        )

    # -----------------------------------------------------
    # INSPECTION
    # -----------------------------------------------------

    def inspect(
        self,
        request: ToolRequest
    ):

        reasons = []

        checks = []

        # =================================================
        # 1. IDENTITY
        # =================================================

        user = get_user(
            request.user_id
        )

        checks.append(
            "Identity verification"
        )

        if user is None:

            return SecurityDecision(

                request_id=request.request_id,

                action="BLOCK",

                risk_score=100,

                reasons=[
                    "Unknown user identity"
                ],

                checks=checks
            )

        # =================================================
        # 2. RBAC
        # =================================================

        authorized, authorization_reason = (
            check_rbac(
                request.user_id,
                request.tool,
                request.arguments
            )
        )

        checks.append(
            "RBAC authorization"
        )

        if not authorized:

            decision = SecurityDecision(

                request_id=request.request_id,

                action="BLOCK",

                risk_score=100,

                reasons=[
                    authorization_reason
                ],

                checks=checks
            )

            resource = get_resource(
                request.tool,
                request.arguments
            )

            self.add_history(
                request,
                resource,
                decision
            )

            return decision

        # =================================================
        # 3. ABAC
        # =================================================

        abac_allowed, abac_reason = (
            check_abac(
                request.user_id,
                request.tool,
                request.arguments
            )
        )

        checks.append(
            "ABAC policy evaluation"
        )

        if not abac_allowed:

            decision = SecurityDecision(

                request_id=request.request_id,

                action="BLOCK",

                risk_score=100,

                reasons=[
                    abac_reason
                ],

                checks=checks
            )

            resource = get_resource(
                request.tool,
                request.arguments
            )

            self.add_history(
                request,
                resource,
                decision
            )

            return decision

        # =================================================
        # 4. RESOURCE SENSITIVITY
        # =================================================

        resource = get_resource(
            request.tool,
            request.arguments
        )

        sensitivity = get_sensitivity(
            resource
        )

        sensitivity_score = (
            get_sensitivity_score(
                resource
            )
        )

        checks.append(
            "Resource sensitivity"
        )

        # =================================================
        # 5. INTENT
        # =================================================

        intent_result = analyze_intent(
            request
        )

        checks.append(
            "Intent consistency"
        )

        if not intent_result["consistent"]:

            reasons.append(
                intent_result["reason"]
            )

        # =================================================
        # 6. TRAJECTORY
        # =================================================

        history = self.get_history(
            request.session_id
        )

        trajectory_result = (
            analyze_trajectory(

                history,

                request,

                resource,

                request.tainted
            )
        )

        checks.append(
            "Action trajectory analysis"
        )

        reasons.extend(
            trajectory_result["reasons"]
        )

        # =================================================
        # 7. RISK
        # =================================================

        risk_score = calculate_risk(

            authorization_ok=True,

            sensitivity_score=sensitivity_score,

            intent_consistent=(
                intent_result["consistent"]
            ),

            trajectory_score=(
                trajectory_result["score"]
            )
        )
        if trajectory_result["critical"]:
            risk_score = max(
                risk_score,
                85
            )

        checks.append(
            "Risk aggregation"
        )

        # =================================================
        # 8. DECISION
        # =================================================

        action = decide_action(
            risk_score
        )

        if action == "ALLOW":

            if not reasons:

                reasons.append(
                    "Request passed authorization, "
                    "attribute, and contextual checks"
                )

        decision = SecurityDecision(

            request_id=request.request_id,

            action=action,

            risk_score=risk_score,

            reasons=reasons,

            checks=checks
        )

        # =================================================
        # 9. AUDIT HISTORY
        # =================================================

        self.add_history(

            request,

            resource,

            decision,

            request.tainted
        )

        return decision

    # -----------------------------------------------------
    # EXECUTION
    # -----------------------------------------------------

    def execute(
        self,
        request: ToolRequest
    ):

        decision = self.inspect(
            request
        )

        # BLOCK and ESCALATE stop execution.
        if decision.action in {
            "BLOCK",
            "ESCALATE"
        }:

            return (
                decision,
                None
            )

        # -------------------------------------------------
        # Execute enterprise tool
        # -------------------------------------------------

        result = execute_tool(

            request.tool,

            request.arguments
        )

        # -------------------------------------------------
        # Filter document search results.
        # This prevents an allowed search operation from
        # exposing documents outside the user's ABAC scope.
        # -------------------------------------------------

        if request.tool == "search_documents":

            result = filter_document_results(

                request.user_id,

                result
            )

        return (
            decision,
            result
        )