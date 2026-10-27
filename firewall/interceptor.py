import time

from firewall.semantic_auditor import SemanticAuditor, SemanticAuditResult
from models.schemas import ToolRequest, ActionRecord
from firewall.information_flow import InformationFlowTracker
from models.decisions import SecurityDecision
from tools.registry import execute_tool
from firewall.authorization import get_user, check_rbac
from firewall.abac import check_abac, filter_document_results
from firewall.resources import (
    get_resource,
    get_sensitivity,
    get_sensitivity_score,
)
from firewall.intent import analyze_intent
from firewall.trajectory import (
    analyze_trajectory,
    requires_deep_trajectory_inspection,
)
from firewall.risk_engine import calculate_risk, decide_action
from firewall.provenance import ProvenanceTracker
from firewall.inspection import (
    determine_preliminary_inspection_level,
    determine_inspection_level,
)
from firewall.semantic_inspection import analyze_semantic_risk
from firewall.resource_limits import ResourceGuard


class FirewallInterceptor:
    def __init__(
        self,
        semantic_auditor=None,
        *,
        enable_semantic_auditor=True,
        adaptive_routing=True,
        enable_information_flow=True,
    ):
        # Evaluation switches default to the full protection configuration.
        self.enable_semantic_auditor = enable_semantic_auditor
        self.adaptive_routing = adaptive_routing
        self.enable_information_flow = enable_information_flow

        self.semantic_auditor = (
            semantic_auditor
            if semantic_auditor is not None
            else SemanticAuditor()
        )
        self.session_history = {}
        self.provenance_tracker = ProvenanceTracker()
        self.information_flow = InformationFlowTracker()
        self.security_contexts = {}

        # Trusted task state is maintained by the application, not inferred
        # from model messages or retrieved enterprise content.
        self.trusted_tasks = {}
        self._task_generations = {}

        # Resource and denial-of-service protection remains enabled for
        # every evaluation configuration.
        self.resource_guard = ResourceGuard(
            max_requests_per_session=50,
            max_deep_inspections=10,
        )

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
            "semantic_auditor_failures": 0,
            "semantic_auditor_latency_ms_total": 0.0,
            "semantic_auditor_latency_ms_last": 0.0,
        }

    # TRUSTED ORIGINAL TASK

    @staticmethod
    def _normalise_task(task):
        return " ".join(str(task or "").split())

    def begin_trusted_task(self, session_id, original_task):
        """Register a task supplied at the authenticated user-entry boundary."""
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
                intent=request.intent,
            )

        context = self.security_contexts[request.session_id]
        context.resource = resource
        context.sensitivity = get_sensitivity(resource)
        context.intent = request.intent
        context.provenance_trusted = (
            self.provenance_tracker.is_trusted(request.session_id)
        )
        context.tainted = self.provenance_tracker.is_tainted(
            request.session_id
        )
        context.provenance_sources = self.provenance_tracker.get_sources(
            request.session_id
        )

        return context

    # RECORD ACTION

    def add_history(
        self,
        request,
        resource,
        decision,
        tainted=False,
        provenance_trusted=True,
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
            provenance_trusted=provenance_trusted,
        )

        self.session_history.setdefault(request.session_id, []).append(
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
                checks=checks,
            )
            resource = get_resource(request.tool, request.arguments)
            self.add_history(
                request,
                resource,
                decision,
                request.tainted,
                False,
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
                checks=checks,
            )
            return decision

        # 2. PROVENANCE

        provenance_result = self.provenance_tracker.process_context_sources(
            request.session_id,
            request.context_sources,
        )

        resource = get_resource(request.tool, request.arguments)
        security_context = self.get_security_context(request, resource)

        effective_tainted = (
            request.tainted
            or provenance_result["tainted"]
            or security_context.tainted
        )

        # 3. RBAC

        authorized, authorization_reason = check_rbac(
            request.user_id,
            request.tool,
            request.arguments,
        )
        checks.append("RBAC authorization")

        if not authorized:
            decision = SecurityDecision(
                request_id=request.request_id,
                action="BLOCK",
                risk_score=100,
                reasons=[authorization_reason],
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

        # 4. ABAC

        abac_allowed, abac_reason = check_abac(
            request.user_id,
            request.tool,
            request.arguments,
        )
        checks.append("ABAC policy evaluation")

        if not abac_allowed:
            decision = SecurityDecision(
                request_id=request.request_id,
                action="BLOCK",
                risk_score=100,
                reasons=[abac_reason],
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

        # 5. RESOURCE SENSITIVITY

        resource = get_resource(request.tool, request.arguments)
        sensitivity_score = get_sensitivity_score(resource)
        checks.append("Resource sensitivity")

        # 5A. PRELIMINARY ROUTING

        preliminary_inspection_result = (
            determine_preliminary_inspection_level(
                request=request,
                sensitivity_score=sensitivity_score,
                tainted=effective_tainted,
                provenance_trusted=security_context.provenance_trusted,
            )
        )

        preliminary_inspection_level = preliminary_inspection_result["level"]

        if not self.adaptive_routing:
            preliminary_inspection_level = "DEEP"
            preliminary_inspection_result["reasons"].append(
                "Fixed DEEP routing enabled by evaluation ablation"
            )

        if requires_deep_trajectory_inspection(
            self.get_history(request.session_id),
            request,
        ):
            if preliminary_inspection_level != "DEEP":
                preliminary_inspection_result["reasons"].append(
                    "Prior sensitive-data access followed by a write "
                    "requires deep workflow inspection"
                )
            preliminary_inspection_level = "DEEP"

        self.routing_metrics["preliminary"][
            preliminary_inspection_level
        ] += 1

        reasons.extend(preliminary_inspection_result["reasons"])
        checks.append("Preliminary inspection routing")

        # 6. INSPECTION AND DEEP-INSPECTION BUDGET

        inspection_level = preliminary_inspection_level
        deep_budget_reserved = False

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

            trajectory_result = analyze_trajectory(
                self.get_history(request.session_id),
                request,
                resource,
                effective_tainted,
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

            final_result = determine_inspection_level(
                request=request,
                resource=resource,
                sensitivity_score=sensitivity_score,
                tainted=effective_tainted,
                provenance_trusted=security_context.provenance_trusted,
                trajectory_score=trajectory_result.get("score", 0),
                semantic_score=semantic_score,
            )

            levels = {"FAST": 0, "CONTEXTUAL": 1, "DEEP": 2}
            candidate_level = final_result["level"]

            if levels.get(candidate_level, 2) > levels.get(
                inspection_level, 2
            ):
                inspection_level = candidate_level

            reasons.extend(final_result.get("reasons", []))
            checks.append("Adaptive inspection refinement")

        # Reserve capacity if later inspection findings promoted the request.
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

        if model_audit_required and self.enable_semantic_auditor:
            checks.append("Model-based semantic audit required")
        elif model_audit_required:
            reasons.append(
                "Model-based semantic audit skipped by evaluation ablation"
            )

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
        """Return a snapshot of routing, audit, and audit-latency metrics."""
        return {
            "preliminary": dict(self.routing_metrics["preliminary"]),
            "final": dict(self.routing_metrics["final"]),
            "semantic_auditor_calls": self.routing_metrics[
                "semantic_auditor_calls"
            ],
            "semantic_auditor_failures": self.routing_metrics[
                "semantic_auditor_failures"
            ],
            "semantic_auditor_latency_ms_total": self.routing_metrics[
                "semantic_auditor_latency_ms_total"
            ],
            "semantic_auditor_latency_ms_last": self.routing_metrics[
                "semantic_auditor_latency_ms_last"
            ],
        }

    # EXECUTION

    def execute(self, request: ToolRequest, original_task=None):
        """Inspect, audit, and authorize a tool request before execution."""
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

        if decision.action in {"BLOCK", "ESCALATE"}:
            return decision, None

        # Validate artifact lineage unless the information-flow ablation
        # explicitly disables enforcement.
        if self.enable_information_flow and request.parent_artifact_ids:
            existing_artifacts = self.information_flow.get_artifacts(
                request.session_id
            )
            existing_ids = {
                artifact["artifact_id"] for artifact in existing_artifacts
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
                    self.provenance_tracker.is_trusted(request.session_id),
                )
                return decision, None

            decision.checks.append("Artifact lineage validation")
        elif not self.enable_information_flow:
            decision.reasons.append(
                "Artifact lineage enforcement disabled by evaluation ablation"
            )

        # Model-based semantic auditing.
        audit_required = (
            decision.inspection_level == "DEEP"
            or "Model-based semantic audit required" in decision.checks
        )

        if audit_required and self.enable_semantic_auditor:
            self.routing_metrics["semantic_auditor_calls"] += 1
            audit_started = time.perf_counter()

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
                self.routing_metrics["semantic_auditor_failures"] += 1
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

            finally:
                audit_duration_ms = (
                    time.perf_counter() - audit_started
                ) * 1000

                self.routing_metrics[
                    "semantic_auditor_latency_ms_last"
                ] = audit_duration_ms

                self.routing_metrics[
                    "semantic_auditor_latency_ms_total"
                ] += audit_duration_ms

            # A structured failure response must fail closed regardless
            # of its recommendation or reported risk score.
            if (
                "Semantic audit could not safely complete"
                in audit_result.reasons
            ):
                self.routing_metrics["semantic_auditor_failures"] += 1
                decision.action = "ESCALATE"
                decision.risk_score = 100
                decision.checks.append(
                    "Model-based semantic security audit (FAIL-CLOSED)"
                )
                decision.reasons.extend(audit_result.reasons)
                decision.reasons.append(
                    "Request was not executed because the auditor "
                    "reported that it could not safely complete"
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
            decision.risk_score = max(
                decision.risk_score,
                audit_result.risk_score,
            )

            # Enforce semantic assessment fields independently of the
            # auditor's recommendation.
            if not audit_result.arguments_integrity:
                decision.action = "BLOCK"
                decision.risk_score = max(decision.risk_score, 85)
                decision.reasons.append(
                    "Blocked because the semantic auditor found "
                    "the proposed arguments inconsistent or unsafe"
                )

            elif (
                not audit_result.task_aligned
                or not audit_result.action_appropriate
            ):
                if decision.action != "BLOCK":
                    decision.action = "ESCALATE"
                decision.risk_score = max(decision.risk_score, 60)
                decision.reasons.append(
                    "Escalated because the semantic auditor found "
                    "a task-alignment or action-suitability concern"
                )

            if audit_result.suspicious and decision.action != "BLOCK":
                decision.action = "ESCALATE"
                decision.risk_score = max(decision.risk_score, 60)
                decision.reasons.append(
                    "Escalated because the semantic auditor marked "
                    "the proposed action as suspicious"
                )

            # Apply the recommendation without weakening existing controls.
            if audit_result.recommendation == "BLOCK":
                decision.action = "BLOCK"
                decision.risk_score = max(decision.risk_score, 85)

            elif audit_result.risk_score >= 70:
                decision.action = "BLOCK"
                decision.risk_score = max(decision.risk_score, 70)

            elif audit_result.recommendation == "ESCALATE":
                if decision.action != "BLOCK":
                    decision.action = "ESCALATE"
                decision.risk_score = max(decision.risk_score, 60)

            elif audit_result.recommendation == "MONITOR":
                if decision.action == "ALLOW":
                    decision.action = "MONITOR"
                decision.risk_score = max(decision.risk_score, 30)

            elif audit_result.risk_score >= 45:
                if decision.action != "BLOCK":
                    decision.action = "ESCALATE"

            elif audit_result.risk_score >= 25:
                if decision.action == "ALLOW":
                    decision.action = "MONITOR"

            self.add_history(
                request,
                get_resource(request.tool, request.arguments),
                decision,
                request.tainted,
                self.provenance_tracker.is_trusted(request.session_id),
            )

        elif audit_required:
            decision.reasons.append(
                "Model-based semantic audit skipped by evaluation ablation"
            )

        # Enforce outbound email content policy.
        if (
            self.enable_information_flow
            and decision.action == "ALLOW"
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
                    self.provenance_tracker.is_trusted(request.session_id),
                )

        elif (
            not self.enable_information_flow
            and decision.action == "ALLOW"
            and request.tool == "send_email_message"
        ):
            decision.reasons.append(
                "Outbound information-flow enforcement disabled "
                "by evaluation ablation"
            )

        # Enforce destination-specific sensitivity limits for writes.
        # This is separate from outbound email content inspection.
        if (
            self.enable_information_flow
            and decision.action == "ALLOW"
        ):
            write_flow_result = (
                self.information_flow.check_sensitive_write(
                    session_id=request.session_id,
                    tool=request.tool,
                    arguments=request.arguments,
                    parent_artifact_ids=request.parent_artifact_ids,
                )
            )

            # The tracker returns this exact reason for non-write actions.
            # Only record a policy check when the action is a write.
            if (
                write_flow_result["reason"]
                != "Action is not classified as a write operation"
            ):
                decision.checks.append(
                    "Destination-specific write information-flow policy"
                )
                decision.reasons.append(write_flow_result["reason"])

                if not write_flow_result["allowed"]:
                    decision.action = "BLOCK"
                    decision.risk_score = max(
                        decision.risk_score,
                        100,
                    )
                    decision.reasons.append(
                        "Write blocked by destination-specific "
                        "information-flow enforcement"
                    )
                    self.add_history(
                        request,
                        get_resource(
                            request.tool,
                            request.arguments,
                        ),
                        decision,
                        request.tainted,
                        self.provenance_tracker.is_trusted(
                            request.session_id
                        ),
                    )

        # MONITOR is not permission to execute.
        if decision.action in {"BLOCK", "ESCALATE", "MONITOR"}:
            return decision, None

        result = execute_tool(request.tool, request.arguments)

        if request.tool == "search_documents":
            result = filter_document_results(request.user_id, result)

        # Preserve artifact recording even in the information-flow ablation.
        resource = get_resource(request.tool, request.arguments)

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
