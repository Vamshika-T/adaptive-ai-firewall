
from firewall.semantic_auditor import SemanticAuditor, SemanticAuditResult
from models.schemas import (
    ToolRequest,
    ActionRecord
)
from firewall.information_flow import InformationFlowTracker

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
    analyze_trajectory,
    requires_deep_trajectory_inspection,
)

from firewall.risk_engine import (
    calculate_risk,
    decide_action
)

from firewall.provenance import ProvenanceTracker

from firewall.inspection import (
    determine_preliminary_inspection_level,
    determine_inspection_level
)

from firewall.semantic_inspection import (
    analyze_semantic_risk
)

from firewall.resource_limits import (
    ResourceGuard
)


class FirewallInterceptor:

    def __init__(self, semantic_auditor=None):
        # Allow controlled evaluation/tests to reuse or inject an auditor.
        # Production defaults to the configured Gemini-backed auditor.
        self.semantic_auditor = semantic_auditor or SemanticAuditor()
        self.session_history = {}
        self.provenance_tracker = ProvenanceTracker()
        self.information_flow = InformationFlowTracker()
        self.security_contexts = {}

        # Trusted task state is maintained by the application, not inferred
        # from model messages or retrieved enterprise content. A new top-level
        # user request explicitly starts a new task generation for the session.
        self.trusted_tasks = {}
        self._task_generations = {}

        # Resource and denial-of-service protection.
        self.resource_guard = ResourceGuard(
            max_requests_per_session=50,
            max_deep_inspections=10
        )

        # Adaptive-routing instrumentation.
        # These counters observe behavior; they do not affect decisions.
        self.routing_metrics = {
            "preliminary": {
                "FAST": 0,
                "CONTEXTUAL": 0,
                "DEEP": 0,
            },
            "final": {
                "FAST": 0,
                "CONTEXTUAL": 0,
                "DEEP": 0,
            },
            "semantic_auditor_calls": 0,
        }

    # TRUSTED ORIGINAL TASK

    @staticmethod
    def _normalise_task(task):
        return " ".join(str(task or "").split())

    def begin_trusted_task(self, session_id, original_task):
        """Register a task supplied at the authenticated user-entry boundary.

        Call once for each new top-level user request, before the agent starts
        processing model output. Tool outputs and model-generated messages must
        never call this method to redefine the task.
        """
        task = self._normalise_task(original_task)
        if not task:
            raise ValueError("A non-empty trusted original task is required")

        generation = self._task_generations.get(session_id, 0) + 1
        self._task_generations[session_id] = generation
        self.trusted_tasks[session_id] = {
            "task": task,
            "generation": generation,
        }
        return {"session_id": session_id, "generation": generation}

    def get_trusted_task(self, session_id):
        """Return the current trusted task record without modifying it."""
        record = self.trusted_tasks.get(session_id)
        return dict(record) if record else None

    # SESSION HISTORY

    def get_history(self, session_id):
        return self.session_history.get(session_id, [])

    # SECURITY CONTEXT

    def get_security_context(self, request, resource):
        from models.schemas import SecurityContext

        user = get_user(request.user_id)

        if request.session_id not in self.security_contexts:
            self.security_contexts[request.session_id] = SecurityContext(
                user_id=request.user_id,
                role=user["role"] if user else "",
                department=user["department"] if user else "",
                resource=resource,
                sensitivity=get_sensitivity(resource),
                intent=request.intent
            )

        context = self.security_contexts[request.session_id]

        # Update current request information.
        context.resource = resource
        context.sensitivity = get_sensitivity(resource)
        context.intent = request.intent

        # Refresh provenance state.
        context.provenance_trusted = (
            self.provenance_tracker.is_trusted(request.session_id)
        )
        context.tainted = (
            self.provenance_tracker.is_tainted(request.session_id)
        )
        context.provenance_sources = (
            self.provenance_tracker.get_sources(request.session_id)
        )

        return context

    # RECORD ACTION

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
            self.session_history[request.session_id] = []

        self.session_history[request.session_id].append(
            record.model_dump()
        )

    # INSPECTION

    def inspect(self, request: ToolRequest):
        reasons = []
        checks = []

        # 0. RESOURCE AND REQUEST BUDGET

        budget_ok, budget_reason = (
            self.resource_guard.check_request_budget(request.session_id)
        )
        checks.append("Resource request budget")

        if not budget_ok:
            decision = SecurityDecision(
                request_id=request.request_id,
                action="BLOCK",
                risk_score=100,
                reasons=[budget_reason],
                checks=checks
            )

            resource = get_resource(request.tool, request.arguments)
            self.add_history(
                request,
                resource,
                decision,
                request.tainted,
                False
            )
            return decision

        # 1. IDENTITY

        user = get_user(request.user_id)
        checks.append("Identity verification")

        if user is None:
            decision = SecurityDecision(
                request_id=request.request_id,
                action="BLOCK",
                risk_score=100,
                reasons=["Unknown user identity"],
                checks=checks
            )
            return decision

        # 2. PROVENANCE

        provenance_result = (
            self.provenance_tracker.process_context_sources(
                request.session_id,
                request.context_sources
            )
        )

        resource = get_resource(request.tool, request.arguments)

        security_context = self.get_security_context(
            request,
            resource
        )

        # Taint can originate from the request, current provenance,
        # or previously observed session state.
        effective_tainted = (
            request.tainted
            or provenance_result["tainted"]
            or security_context.tainted
        )

        # 3. RBAC

        authorized, authorization_reason = check_rbac(
            request.user_id,
            request.tool,
            request.arguments
        )
        checks.append("RBAC authorization")

        if not authorized:
            decision = SecurityDecision(
                request_id=request.request_id,
                action="BLOCK",
                risk_score=100,
                reasons=[authorization_reason],
                checks=checks
            )

            self.add_history(
                request,
                resource,
                decision,
                effective_tainted,
                security_context.provenance_trusted
            )
            return decision

        # 4. ABAC

        abac_allowed, abac_reason = check_abac(
            request.user_id,
            request.tool,
            request.arguments
        )
        checks.append("ABAC policy evaluation")

        if not abac_allowed:
            decision = SecurityDecision(
                request_id=request.request_id,
                action="BLOCK",
                risk_score=100,
                reasons=[abac_reason],
                checks=checks
            )

            self.add_history(
                request,
                resource,
                decision,
                effective_tainted,
                security_context.provenance_trusted
            )
            return decision

        # 5. RESOURCE SENSITIVITY

        resource = get_resource(request.tool, request.arguments)
        sensitivity = get_sensitivity(resource)
        sensitivity_score = get_sensitivity_score(resource)

        checks.append("Resource sensitivity")

        # 5A. PRELIMINARY ADAPTIVE ROUTING

        preliminary_inspection_result = (
            determine_preliminary_inspection_level(
                request=request,
                sensitivity_score=sensitivity_score,
                tainted=effective_tainted,
                provenance_trusted=security_context.provenance_trusted,
            )
        )

        preliminary_inspection_level = (
            preliminary_inspection_result["level"]
        )

        # A write following a sensitive-data read requires deep workflow
        # inspection, even when the current resource is not highly sensitive.
        if requires_deep_trajectory_inspection(
            self.get_history(request.session_id),
            request
        ):
            preliminary_inspection_level = "DEEP"
            preliminary_inspection_result["reasons"].append(
                "Prior sensitive-data access followed by a write "
                "requires deep workflow inspection"
            )

        self.routing_metrics["preliminary"][
            preliminary_inspection_level
        ] += 1

        reasons.extend(preliminary_inspection_result["reasons"])
        checks.append("Preliminary adaptive inspection routing")

        # 6. ADAPTIVE INSPECTION AND DEEP-INSPECTION BUDGET

        inspection_level = preliminary_inspection_level
        deep_budget_reserved = False

        # Reserve deep-inspection capacity BEFORE trajectory analysis,
        # semantic inspection, or any model-based auditor call.
        if preliminary_inspection_level == "DEEP":
            deep_budget_ok, deep_budget_reason = (
                self.resource_guard.check_deep_inspection_budget(
                    request.session_id
                )
            )
            checks.append("Deep inspection budget")

            if not deep_budget_ok:
                self.routing_metrics["final"]["DEEP"] += 1

                decision = SecurityDecision(
                    request_id=request.request_id,
                    action="BLOCK",
                    risk_score=100,
                    inspection_level="DEEP",
                    reasons=[
                        deep_budget_reason,
                        "Request blocked before expensive deep inspection "
                        "because capacity is exhausted",
                    ],
                    checks=checks,
                )

                self.add_history(
                    request,
                    resource,
                    decision,
                    effective_tainted,
                    security_context.provenance_trusted,
                )
                return decision

            deep_budget_reserved = True

        intent_result = {
            "consistent": True,
            "reason": "Intent check skipped on FAST path",
        }
        trajectory_result = {
            "score": 0,
            "critical": False,
            "reasons": [],
        }
        semantic_result = {
            "semantic_score": 0,
            "suspicious": False,
            "reasons": [],
        }
        semantic_score = 0

        if inspection_level in {"CONTEXTUAL", "DEEP"}:
            intent_result = analyze_intent(request)
            checks.append("Intent consistency")

            if not intent_result["consistent"]:
                reasons.append(intent_result["reason"])

            history = self.get_history(request.session_id)
            trajectory_result = analyze_trajectory(
                history,
                request,
                resource,
                effective_tainted
            )
            checks.append("Action trajectory analysis")
            reasons.extend(trajectory_result.get("reasons", []))

            semantic_result = analyze_semantic_risk(
                request=request,
                resource=resource,
                tainted=effective_tainted,
                provenance_trusted=security_context.provenance_trusted,
                trajectory_score=trajectory_result.get("score", 0),
            )
            semantic_score = semantic_result.get("semantic_score", 0)
            reasons.extend(semantic_result.get("reasons", []))
            checks.append("Semantic/STI inspection")

            # Inspection findings may increase depth, never decrease it.
            final_result = determine_inspection_level(
                request=request,
                resource=resource,
                sensitivity_score=sensitivity_score,
                tainted=effective_tainted,
                provenance_trusted=security_context.provenance_trusted,
                trajectory_score=trajectory_result.get("score", 0),
                semantic_score=semantic_score,
            )

            levels = {
                "FAST": 0,
                "CONTEXTUAL": 1,
                "DEEP": 2,
            }
            candidate_level = final_result["level"]

            if levels.get(candidate_level, 2) > levels.get(
                inspection_level, 2
            ):
                inspection_level = candidate_level

            reasons.extend(final_result.get("reasons", []))
            checks.append("Adaptive inspection refinement")

        # A request initially routed to CONTEXTUAL could be promoted to DEEP
        # by inspection findings. Reserve capacity before risk aggregation
        # and before the execution method can invoke the model auditor.
        if inspection_level == "DEEP" and not deep_budget_reserved:
            deep_budget_ok, deep_budget_reason = (
                self.resource_guard.check_deep_inspection_budget(
                    request.session_id
                )
            )
            checks.append("Deep inspection budget")

            if not deep_budget_ok:
                self.routing_metrics["final"]["DEEP"] += 1

                decision = SecurityDecision(
                    request_id=request.request_id,
                    action="BLOCK",
                    risk_score=100,
                    inspection_level="DEEP",
                    reasons=[
                        deep_budget_reason,
                        "Request blocked because safe deep inspection "
                        "capacity is exhausted",
                    ],
                    checks=checks,
                )

                self.add_history(
                    request,
                    resource,
                    decision,
                    effective_tainted,
                    security_context.provenance_trusted,
                )
                return decision

        self.routing_metrics["final"][inspection_level] += 1

        # 7. RISK AGGREGATION

        risk_score = calculate_risk(
            authorization_ok=True,
            sensitivity_score=sensitivity_score,
            intent_consistent=intent_result["consistent"],
            trajectory_score=trajectory_result.get("score", 0),
        )

        if trajectory_result.get("critical", False):
            risk_score = max(risk_score, 85)

        if semantic_score >= 60:
            risk_score = max(risk_score, 60)

        checks.append("Risk aggregation")

        # A critical trajectory is a mandatory enforcement condition.
        action = (
            "BLOCK"
            if trajectory_result.get("critical", False)
            else decide_action(risk_score)
        )

        if (
            inspection_level == "DEEP"
            and semantic_result.get("suspicious", False)
            and action == "ALLOW"
        ):
            if sensitivity_score >= 75:
                action = "BLOCK"
                risk_score = max(risk_score, 85)
            elif sensitivity_score >= 50:
                action = "ESCALATE"
                risk_score = max(risk_score, 60)
            else:
                action = "MONITOR"
                risk_score = max(risk_score, 30)

        # Deep inspections always require model-based auditing.
        # Contextual inspections require auditing when risk signals justify
        # the additional model call.
        model_audit_required = (
            inspection_level == "DEEP"
            or (
                inspection_level == "CONTEXTUAL"
                and (
                    not intent_result["consistent"]
                    or trajectory_result.get("score", 0) > 0
                    or trajectory_result.get("critical", False)
                    or semantic_result.get("suspicious", False)
                    or semantic_score >= 30
                    or effective_tainted
                    or not security_context.provenance_trusted
                    or sensitivity_score >= 50
                    or (
                        "Suspicious intent signal requires contextual inspection"
                        in reasons
                    )
                    or (
                        request.tool in {
                            "query_database",
                            "send_email_message",
                            "update_crm_record",
                        }
                        and bool(request.context_sources)
                    )
                )
            )
        )

        if model_audit_required:
            checks.append("Model-based semantic audit required")

        if action == "ALLOW" and not reasons:
            reasons.append(
                "Request passed authorization and applicable inspection checks"
            )

        decision = SecurityDecision(
            request_id=request.request_id,
            action=action,
            risk_score=risk_score,
            inspection_level=inspection_level,
            reasons=reasons,
            checks=checks,
        )

        self.add_history(
            request,
            resource,
            decision,
            effective_tainted,
            security_context.provenance_trusted,
        )
        return decision

    def get_routing_metrics(self):
        """Return a snapshot of adaptive-routing counters."""
        return {
            "preliminary": dict(self.routing_metrics["preliminary"]),
            "final": dict(self.routing_metrics["final"]),
            "semantic_auditor_calls": (
                self.routing_metrics["semantic_auditor_calls"]
            ),
        }

    # EXECUTION

    def execute(
        self,
        request: ToolRequest,
        original_task=None,
    ):
        """
        Inspect and audit a tool request before execution.

        ALLOW permits execution.
        MONITOR and ESCALATE require approval.
        BLOCK never permits execution.

        Parent artifact IDs are validated before tool execution.
        Derived outputs inherit the sensitivity and provenance of
        their parent artifacts.
        """
        # Resolve the trusted task before inspection or any model call.
        # A direct first execute() call may establish the task for backwards
        # compatibility; subsequent calls cannot redefine it.
        task_record = self.trusted_tasks.get(request.session_id)
        supplied_task = self._normalise_task(original_task)

        if task_record is None and supplied_task:
            self.begin_trusted_task(request.session_id, supplied_task)
            task_record = self.trusted_tasks[request.session_id]

        trusted_task = task_record["task"] if task_record else ""

        if supplied_task and trusted_task and supplied_task != trusted_task:
            decision = SecurityDecision(
                request_id=request.request_id,
                action="BLOCK",
                risk_score=100,
                inspection_level="DEEP",
                reasons=[
                    "Request blocked because the supplied task differs "
                    "from the application-trusted original task",
                    "Untrusted content cannot redefine the trusted task",
                ],
                checks=["Trusted original-task validation"],
            )

            self.add_history(
                request,
                get_resource(request.tool, request.arguments),
                decision,
                request.tainted,
                self.provenance_tracker.is_trusted(request.session_id),
            )
            return decision, None

        decision = self.inspect(request)

        # Deterministic security decisions take priority.
        if decision.action in {"BLOCK", "ESCALATE"}:
            return decision, None

        # Validate artifact lineage before any enterprise tool can execute.
        if request.parent_artifact_ids:
            existing_artifacts = self.information_flow.get_artifacts(
                request.session_id
            )
            existing_ids = {
                artifact["artifact_id"]
                for artifact in existing_artifacts
            }

            unknown_parent_ids = [
                parent_id
                for parent_id in request.parent_artifact_ids
                if parent_id not in existing_ids
            ]

            if unknown_parent_ids:
                decision.action = "BLOCK"
                decision.risk_score = max(decision.risk_score, 100)
                decision.checks.append("Artifact lineage validation")
                decision.reasons.append(
                    "Request blocked because one or more parent "
                    "artifact IDs are unknown in this session: "
                    + ", ".join(unknown_parent_ids)
                )

                self.add_history(
                    request,
                    get_resource(request.tool, request.arguments),
                    decision,
                    request.tainted,
                    self.provenance_tracker.is_trusted(
                        request.session_id
                    ),
                )
                return decision, None

            decision.checks.append("Artifact lineage validation")

        # Deep inspections always receive a model audit.
        # Contextual inspections receive one when inspect() identifies
        # risk signals that justify the model call.
        if (
            decision.inspection_level == "DEEP"
            or "Model-based semantic audit required" in decision.checks
        ):
            self.routing_metrics["semantic_auditor_calls"] += 1

            # Fail closed if the model auditor errors or returns an invalid
            # response. An audit failure must never silently permit execution.
            try:
                raw_audit_result = self.semantic_auditor.audit(
                    request=request,
                    original_task=trusted_task or None,
                    inspection_level=decision.inspection_level,
                )

                if isinstance(raw_audit_result, SemanticAuditResult):
                    audit_result = SemanticAuditResult.model_validate(
                        raw_audit_result.model_dump(),
                        strict=True,
                    )
                elif isinstance(raw_audit_result, dict):
                    audit_result = SemanticAuditResult.model_validate(
                        raw_audit_result,
                        strict=True,
                    )
                else:
                    raise ValueError(
                        "Auditor returned an unsupported response type"
                    )

            except Exception as error:
                decision.action = "ESCALATE"
                decision.risk_score = 100
                decision.checks.append(
                    "Model-based semantic security audit (FAIL-CLOSED)"
                )
                decision.reasons.append(
                    "Request was not executed because semantic auditing "
                    "failed validation or raised an error: "
                    f"{type(error).__name__}: {error}"
                )

                self.add_history(
                    request,
                    get_resource(request.tool, request.arguments),
                    decision,
                    request.tainted,
                    self.provenance_tracker.is_trusted(request.session_id),
                )
                return decision, None

            decision.checks.append("Model-based semantic security audit")
            decision.reasons.extend(audit_result.reasons)

            # Never reduce the existing risk score.
            decision.risk_score = max(
                decision.risk_score,
                audit_result.risk_score,
            )

            if audit_result.recommendation == "BLOCK":
                decision.action = "BLOCK"
                decision.risk_score = max(decision.risk_score, 85)

            elif audit_result.recommendation == "ESCALATE":
                decision.action = "ESCALATE"
                decision.risk_score = max(decision.risk_score, 60)

            elif audit_result.recommendation == "MONITOR":
                if decision.action == "ALLOW":
                    decision.action = "MONITOR"
                decision.risk_score = max(decision.risk_score, 30)

            elif audit_result.risk_score >= 70:
                decision.action = "BLOCK"

            elif audit_result.risk_score >= 45:
                decision.action = "ESCALATE"

            elif audit_result.risk_score >= 25:
                if decision.action == "ALLOW":
                    decision.action = "MONITOR"

            # Record the final decision after auditing.
            self.add_history(
                request,
                get_resource(request.tool, request.arguments),
                decision,
                request.tainted,
                True,
            )

        # Enforce information-flow policy before outbound email execution.
        if (
            decision.action == "ALLOW"
            and request.tool == "send_email_message"
        ):
            flow_result = self.information_flow.check_outbound_payload(
                session_id=request.session_id,
                recipient=request.arguments.get("recipient", ""),
                payload=request.arguments.get("body", ""),
            )

            decision.checks.append("Outbound information-flow policy")
            decision.reasons.append(flow_result["reason"])

            if not flow_result["allowed"]:
                decision.action = "BLOCK"
                decision.risk_score = max(decision.risk_score, 100)
                decision.reasons.append(
                    "Outbound action blocked because sensitive "
                    "artifact content was detected"
                )

                self.add_history(
                    request,
                    get_resource(request.tool, request.arguments),
                    decision,
                    request.tainted,
                    self.provenance_tracker.is_trusted(
                        request.session_id,
                    ),
                )

        # MONITOR is not equivalent to permission to execute.
        if decision.action in {"BLOCK", "ESCALATE", "MONITOR"}:
            return decision, None

        # Only ALLOW reaches the enterprise tool.
        result = execute_tool(
            request.tool,
            request.arguments,
        )

        if request.tool == "search_documents":
            result = filter_document_results(
                request.user_id,
                result,
            )

        # Record successful tool output and preserve artifact lineage.
        resource = get_resource(
            request.tool,
            request.arguments,
        )

        if result is not None:
            if request.parent_artifact_ids:
                artifact = self.information_flow.record_derived_artifact(
                    session_id=request.session_id,
                    tool=request.tool,
                    resource=resource,
                    result=result,
                    parent_artifact_ids=request.parent_artifact_ids,
                )
            else:
                artifact = self.information_flow.record_artifact(
                    session_id=request.session_id,
                    tool=request.tool,
                    resource=resource,
                    result=result,
                    sensitivity=get_sensitivity(resource),
                    provenance_sources=request.context_sources,
                )

            request.output_artifact_id = artifact["artifact_id"]

        return decision, result
