from models.schemas import (
    ToolRequest,
    SecurityContext,
    ActionRecord
)

from models.decisions import SecurityDecision

from tools.registry import execute_tool

from firewall.authorization import (
    get_user,
    is_authorized
)

from firewall.resources import (
    get_resource,
    get_sensitivity_score,
    get_sensitivity
)

from firewall.provenance import (
    evaluate_provenance
)

from firewall.taint import (
    evaluate_taint
)

from firewall.intent import (
    analyze_intent
)

from firewall.trajectory import (
    analyze_trajectory
)

from firewall.risk_engine import (
    calculate_risk
)

from firewall.router import (
    choose_inspection_level
)

from firewall.sti import (
    deep_semantic_inspection,
    safety_first_decision
)

from firewall.resource_limits import (
    ResourceGuard
)


class FirewallInterceptor:

    def __init__(self):

        self.resource_guard = ResourceGuard()

        self.session_history = {}

    def get_history(self, session_id):

        return self.session_history.get(
            session_id,
            []
        )

    def add_history(
        self,
        request,
        resource,
        decision
    ):

        record = ActionRecord(
            request_id=request.request_id,
            session_id=request.session_id,
            user_id=request.user_id,
            tool=request.tool,
            resource=resource,
            decision=decision.action,
            risk_score=decision.risk_score,
            tainted=request.tainted,
            provenance_trusted=(
                "untrusted provenance"
                not in " ".join(
                    decision.reasons
                ).lower()
            )
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

    def inspect(
        self,
        request: ToolRequest
    ):

        reasons = []
        checks = []

        # ------------------------------------------------
        # 1. Identity
        # ------------------------------------------------

        user = get_user(
            request.user_id
        )

        if user is None:

            return SecurityDecision(
                request_id=request.request_id,
                action="BLOCK",
                risk_score=100,
                inspection_level="FAST",
                reasons=[
                    "Unknown user identity"
                ],
                checks=[
                    "Identity verification"
                ]
            )

        # ------------------------------------------------
        # 2. Resource / budget protection
        # ------------------------------------------------

        budget_ok, budget_reason = (
            self.resource_guard.check_request_budget(
                request.session_id
            )
        )

        checks.append(
            "Session resource budget"
        )

        if not budget_ok:

            return SecurityDecision(
                request_id=request.request_id,
                action="BLOCK",
                risk_score=100,
                inspection_level="FAST",
                reasons=[
                    budget_reason
                ],
                checks=checks
            )

        # ------------------------------------------------
        # 3. RBAC
        # ------------------------------------------------

        authorized, authorization_reason = (
            is_authorized(
                request.user_id,
                request.tool
            )
        )

        checks.append(
            "RBAC authorization"
        )

        # Authorization is a HARD boundary.
        if not authorized:

            decision = SecurityDecision(
                request_id=request.request_id,
                action="BLOCK",
                risk_score=100,
                inspection_level="FAST",
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

        # ------------------------------------------------
        # 4. Resource sensitivity
        # ------------------------------------------------

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

        # ------------------------------------------------
        # 5. Provenance
        # ------------------------------------------------

        provenance_result = (
            evaluate_provenance(
                request.context_sources
            )
        )

        checks.append(
            "Provenance analysis"
        )

        if not provenance_result["trusted"]:

            reasons.append(
                "Untrusted provenance detected"
            )

        # ------------------------------------------------
        # 6. Taint
        # ------------------------------------------------

        tainted = evaluate_taint(
            request,
            provenance_result
        )

        if tainted:

            reasons.append(
                "Request contains tainted context"
            )

        checks.append(
            "Taint analysis"
        )

        # ------------------------------------------------
        # 7. Intent
        # ------------------------------------------------

        intent_result = analyze_intent(
            request
        )

        if not intent_result["consistent"]:

            reasons.append(
                intent_result["reason"]
            )

        checks.append(
            "Intent consistency"
        )

        # ------------------------------------------------
        # 8. Trajectory
        # ------------------------------------------------

        history = self.get_history(
            request.session_id
        )

        trajectory_result = (
            analyze_trajectory(
                history,
                request,
                resource,
                tainted
            )
        )

        reasons.extend(
            trajectory_result["reasons"]
        )

        checks.append(
            "Action trajectory analysis"
        )

        # ------------------------------------------------
        # 9. Risk
        # ------------------------------------------------

        risk_score = calculate_risk(
            authorization_ok=True,
            sensitivity_score=sensitivity_score,
            provenance_trusted=(
                provenance_result["trusted"]
            ),
            tainted=tainted,
            intent_consistent=(
                intent_result["consistent"]
            ),
            trajectory_score=(
                trajectory_result["score"]
            )
        )

        # ------------------------------------------------
        # 10. Adaptive routing
        # ------------------------------------------------

        inspection_level = (
            choose_inspection_level(
                risk_score=risk_score,
                tainted=tainted,
                provenance_trusted=(
                    provenance_result["trusted"]
                ),
                sensitivity_score=sensitivity_score
            )
        )

        checks.append(
            f"Adaptive routing: {inspection_level}"
        )

        # ------------------------------------------------
        # 11. Deep inspection
        # ------------------------------------------------

        if inspection_level == "DEEP":

            deep_budget_ok, deep_reason = (
                self.resource_guard
                .check_deep_inspection_budget(
                    request.session_id
                )
            )

            checks.append(
                "Deep inspection resource budget"
            )

            if not deep_budget_ok:

                decision = SecurityDecision(
                    request_id=request.request_id,
                    action="ESCALATE",
                    risk_score=max(
                        risk_score,
                        70
                    ),
                    inspection_level="DEEP",
                    reasons=[
                        "Deep inspection budget exceeded",
                        "Safety-first enforcement applied"
                    ] + reasons,
                    checks=checks
                )

                self.add_history(
                    request,
                    resource,
                    decision
                )

                return decision

            sti_result = (
                deep_semantic_inspection(
                    request,
                    intent_result,
                    provenance_result,
                    trajectory_result
                )
            )

            checks.append(
                "Deep semantic inspection"
            )

            reasons.extend(
                sti_result["reasons"]
            )

            final_action = (
                safety_first_decision(
                    request,
                    sensitivity_score,
                    sti_result
                )
            )

            if final_action == "BLOCK":

                risk_score = max(
                    risk_score,
                    85
                )

            elif final_action == "ESCALATE":

                risk_score = max(
                    risk_score,
                    65
                )

            decision = SecurityDecision(
                request_id=request.request_id,
                action=final_action,
                risk_score=risk_score,
                inspection_level="DEEP",
                reasons=reasons,
                checks=checks
            )

            self.add_history(
                request,
                resource,
                decision
            )

            return decision

        # ------------------------------------------------
        # 12. Contextual enforcement
        # ------------------------------------------------

        if inspection_level == "CONTEXTUAL":

            if (
                tainted
                and sensitivity_score >= 75
            ):

                action = "ESCALATE"

            elif risk_score >= 70:

                action = "ESCALATE"

            elif risk_score >= 35:

                action = "MONITOR"

            else:

                action = "ALLOW"

            decision = SecurityDecision(
                request_id=request.request_id,
                action=action,
                risk_score=risk_score,
                inspection_level="CONTEXTUAL",
                reasons=reasons,
                checks=checks
            )

            self.add_history(
                request,
                resource,
                decision
            )

            return decision

        # ------------------------------------------------
        # 13. Fast path
        # ------------------------------------------------

        decision = SecurityDecision(
            request_id=request.request_id,
            action="ALLOW",
            risk_score=risk_score,
            inspection_level="FAST",
            reasons=(
                reasons
                if reasons
                else [
                    "Request passed fast-path security checks"
                ]
            ),
            checks=checks
        )

        self.add_history(
            request,
            resource,
            decision
        )

        return decision

    def execute(
        self,
        request: ToolRequest
    ):

        decision = self.inspect(
            request
        )

        if decision.action in {
            "BLOCK",
            "ESCALATE"
        }:

            return decision, None

        result = execute_tool(
            request.tool,
            request.arguments
        )

        return decision, result