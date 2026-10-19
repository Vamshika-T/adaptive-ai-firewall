"""Regression tests for critical trajectory enforcement and GDoS metrics."""

from types import SimpleNamespace
from unittest.mock import patch

from models.schemas import ToolRequest
from firewall.interceptor import FirewallInterceptor
from evaluation.comparative_evaluation import (
    aggregate_scenario,
    make_request,
    method_metrics,
    record_request,
)


def _request(session_id="critical-session"):
    return ToolRequest(
        request_id=f"{session_id}-REQ001",
        session_id=session_id,
        user_id="U001",
        tool="send_email_message",
        arguments={"recipient": "external@example.com", "subject": "Report", "body": "data"},
        intent="Send the report",
        context_sources=[],
        parent_artifact_ids=[],
        tainted=False,
        source_type="test",
    )


def test_critical_trajectory_blocks_even_if_risk_engine_says_allow():
    firewall = FirewallInterceptor()
    request = _request()
    context = SimpleNamespace(
        tainted=False,
        provenance_trusted=True,
        provenance_sources=[],
    )

    with (
        patch("firewall.interceptor.get_user", return_value={"role": "employee", "department": "Engineering"}),
        patch.object(firewall.resource_guard, "check_request_budget", return_value=(True, "")),
        patch.object(firewall.resource_guard, "check_deep_inspection_budget", return_value=(True, "")),
        patch.object(firewall, "get_security_context", return_value=context),
        patch("firewall.interceptor.get_resource", return_value="email"),
        patch("firewall.interceptor.get_sensitivity", return_value="INTERNAL"),
        patch("firewall.interceptor.get_sensitivity_score", return_value=10),
        patch("firewall.interceptor.check_rbac", return_value=(True, "authorized")),
        patch("firewall.interceptor.check_abac", return_value=(True, "authorized")),
        patch("firewall.interceptor.determine_preliminary_inspection_level",
              return_value={"level": "DEEP", "reasons": []}),
        patch("firewall.interceptor.requires_deep_trajectory_inspection", return_value=False),
        patch("firewall.interceptor.analyze_intent",
              return_value={"consistent": True, "reason": "consistent"}),
        patch("firewall.interceptor.analyze_trajectory",
              return_value={"score": 0, "critical": True, "reasons": ["critical exfiltration path"]}),
        patch("firewall.interceptor.analyze_semantic_risk",
              return_value={"semantic_score": 0, "suspicious": False, "reasons": []}),
        patch("firewall.interceptor.determine_inspection_level",
              return_value={"level": "DEEP", "reasons": []}),
        patch("firewall.interceptor.calculate_risk", return_value=10),
        patch("firewall.interceptor.decide_action", return_value="ALLOW"),
    ):
        decision = firewall.inspect(request)

    assert decision.action == "BLOCK"
    assert decision.risk_score >= 85
    assert "critical exfiltration path" in decision.reasons


def _gdos_scenario():
    return {
        "id": "A8",
        "name": "Repeated request exhaustion",
        "category": "gdos",
        "user_id": "U001",
        "tool": "send_email_message",
        "arguments": {"recipient": "bob@company.com", "subject": "Review", "body": "Please review."},
        "intent": "Send a review email",
        "context_sources": [],
        "tainted": False,
    }


def _gdos_records(executed_flags):
    scenario = _gdos_scenario()
    records = []
    for number, executed in enumerate(executed_flags, start=1):
        request = make_request(scenario, "gdos-test", number)
        records.append(record_request(
            "Adaptive AI Firewall",
            scenario,
            request,
            "ALLOW" if executed else "BLOCK",
            executed,
            1.0,
        ))
    return records


def test_gdos_scenario_requires_every_repeated_request_to_be_rejected():
    partial = aggregate_scenario(_gdos_records([False, False, True]))
    complete = aggregate_scenario(_gdos_records([False, False, False]))

    assert partial["scenario_prevented"] is False
    assert partial["final_rejected_count"] == 2
    assert partial["final_executed_count"] == 1
    assert complete["scenario_prevented"] is True


def test_gdos_metrics_report_request_rejection_and_execution_rates():
    scenario_record = aggregate_scenario(_gdos_records([False, False, True, True]))
    metrics = method_metrics([scenario_record])

    assert metrics["gdos_request_rejection_rate"] == 50.0
    assert metrics["gdos_request_execution_rate"] == 50.0
    assert metrics["gdos_prevention_rate"] == 0.0
