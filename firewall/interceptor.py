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

from firewall.provenance import ProvenanceTracker

from firewall.inspection import (
    determine_inspection_level
)

from firewall.semantic_inspection import analyze_semantic_risk

class FirewallInterceptor:

    def __init__(self):
        self.session_history = {}
        self.provenance_tracker = ProvenanceTracker()
        self.security_contexts = {}

    # -----------------------------------------------------
    # SESSION HISTORY
    # -----------------------------------------------------

    def get_history(self, session_id):

        return self.session_history.get(
            session_id,
            []
        )

    # -----------------------------------------------------
    # SECURITY CONTEXT
    # -----------------------------------------------------

    def get_security_context(self, request, resource):

        from models.schemas import SecurityContext

        user = get_user(
            request.user_id
        )

        if request.session_id not in self.security_contexts:

            self.security_contexts[
                request.session_id
            ] = SecurityContext(

                user_id=request.user_id,

                role=(
                    user["role"]
                    if user
                    else ""
                ),

                department=(
                    user["department"]
                    if user
                    else ""
                ),

                resource=resource,

                sensitivity=get_sensitivity(
                    resource
                ),

                intent=request.intent
            )

        context = self.security_contexts[
            request.session_id
        ]

        # Update current request information
        context.resource = resource

        context.sensitivity = get_sensitivity(
            resource
        )

        context.intent = request.intent

        # -------------------------------------------------
        # Phase 2B provenance state
        # -------------------------------------------------

        context.provenance_trusted = (
            self.provenance_tracker.is_trusted(
                request.session_id
            )
        )

        context.tainted = (
            self.provenance_tracker.is_tainted(
                request.session_id
            )
        )

        context.provenance_sources = (
            self.provenance_tracker.get_sources(
                request.session_id
            )
        )

        return context

    # -----------------------------------------------------
    # RECORD ACTION
    # -----------------------------------------------------

    def add_history(
        self,
        request,
        resource,
        decision,
        tainted=False,
        provenance_trusted=True
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

            provenance_trusted=provenance_trusted
        )

        if request.session_id not in self.session_history:

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

    def inspect(self, request: ToolRequest):

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

            decision = SecurityDecision(

                request_id=request.request_id,

                action="BLOCK",

                risk_score=100,

                reasons=[
                    "Unknown user identity"
                ],

                checks=checks
            )

            return decision

        # =================================================
        # 2. PHASE 2B - PROVENANCE
        # =================================================

        provenance_result = (
            self.provenance_tracker.process_context_sources(
                request.session_id,
                request.context_sources
            )
        )

        # Determine resource for the request
        resource = get_resource(
            request.tool,
            request.arguments
        )

        # Update security context
        security_context = (
            self.get_security_context(
                request,
                resource
            )
        )

        # -------------------------------------------------
        # Effective taint
        #
        # Taint can come from:
        # 1. Explicit request taint
        # 2. Current request provenance
        # 3. Existing session taint
        # -------------------------------------------------

        effective_tainted = (

            request.tainted

            or provenance_result["tainted"]

            or security_context.tainted
        )

        # =================================================
        # 3. RBAC
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

                decision,

                effective_tainted,

                security_context.provenance_trusted
            )

            return decision

        # =================================================
        # 4. ABAC
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

                decision,

                effective_tainted,

                security_context.provenance_trusted
            )

            return decision

        # =================================================
        # 5. RESOURCE SENSITIVITY
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
        # 6. INTENT
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
        # 7. TRAJECTORY
        # =================================================

        history = self.get_history(
            request.session_id
        )

        trajectory_result = (
            analyze_trajectory(
                history,
                request,
                resource,
                effective_tainted
            )
        )

        checks.append("Action trajectory analysis")
        reasons.extend(trajectory_result["reasons"])

        # =================================================
        # PHASE 2D - SEMANTIC / STI INSPECTION
        # =================================================

        semantic_result = analyze_semantic_risk(
            request=request,
            resource=resource,
            tainted=effective_tainted,
            provenance_trusted=security_context.provenance_trusted,
            trajectory_score=trajectory_result["score"]
        )

        semantic_score = semantic_result["semantic_score"]

        reasons.extend(
            semantic_result["reasons"]
        )

        checks.append(
            "Semantic/STI inspection"
        )

        # =================================================
        # PHASE 2D - ADAPTIVE INSPECTION
        # =================================================

        inspection_result = determine_inspection_level(

            request=request,
            resource=resource,
            sensitivity_score=sensitivity_score,
            tainted=effective_tainted,

            provenance_trusted=(
                security_context.provenance_trusted
            ),
            trajectory_score=(
                trajectory_result["score"]
            ),
            semantic_score=semantic_score
        )

        inspection_level = inspection_result["level"]

        reasons.extend(
            inspection_result["reasons"]
        )

        checks.append(
            "Adaptive inspection routing"
        )

        reasons.extend(
            trajectory_result["reasons"]
        )

        # =================================================
        # 8. RISK
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

        # Critical trajectory gets a minimum high risk
        if trajectory_result["critical"]:

            risk_score = max(
                risk_score,
                85
            )

        checks.append(
            "Risk aggregation"
        )

        # =================================================
        # 9. DECISION
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
            inspection_level=inspection_level,
            reasons=reasons,
            checks=checks
        )

        # =================================================
        # 10. AUDIT HISTORY
        # =================================================

        self.add_history(

            request,

            resource,

            decision,

            effective_tainted,

            security_context.provenance_trusted
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

        # -------------------------------------------------
        # BLOCK and ESCALATE stop execution
        # -------------------------------------------------

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
        # Filter document search results
        #
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