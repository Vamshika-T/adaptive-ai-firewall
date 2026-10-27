
from types import SimpleNamespace

from evaluation.comparative_evaluation import record_request


def make_inputs():
    scenario = {
        "id": "A1",
        "name": "Prompt injection test",
        "category": "prompt_injection",
    }

    request = SimpleNamespace(
        request_id="SESSION-REQ001",
        tool="get_customer",
    )

    return scenario, request


def make_record(checks, inspection="DEEP", reasons=None):
    scenario, request = make_inputs()

    return record_request(
        method="Adaptive AI Firewall",
        scenario=scenario,
        request=request,
        action="ALLOW",
        executed=True,
        latency_ms=10.0,
        inspection=inspection,
        risk_score=20.0,
        reasons=reasons or [],
        checks_performed=checks,
    )


def test_actual_deep_stage_check_is_counted():
    record = make_record(
        ["ABAC policy evaluation", "Intent consistency"]
    )

    assert record["deep_inspection_performed"] is True
    assert "Intent consistency" in record["checks_performed"]


def test_audit_requirement_without_execution_is_not_counted():
    record = make_record(
        ["Model-based semantic audit required"]
    )

    assert record["deep_inspection_performed"] is False


def test_fast_checks_alone_are_not_counted():
    record = make_record(
        [
            "ABAC policy evaluation",
            "Resource sensitivity",
            "Preliminary inspection routing",
        ],
        inspection="FAST",
    )

    assert record["deep_inspection_performed"] is False



def test_contextual_trajectory_check_is_not_counted_as_deep():
    record = make_record(
        ["Action trajectory analysis"],
        inspection="CONTEXTUAL",
    )

    assert record["deep_inspection_performed"] is False
    assert (
        record["contextual_or_deep_stage_check_performed"]
        is True
    )


def test_deep_stage_check_at_deep_level_is_counted():
    record = make_record(
        ["ABAC policy evaluation", "Intent consistency"],
        inspection="DEEP",
    )

    assert record["deep_inspection_performed"] is True
    assert (
        record["contextual_or_deep_stage_check_performed"]
        is True
    )



def test_missing_check_list_defaults_to_no_deep_inspection():
    record = make_record(None)

    assert record["deep_inspection_performed"] is False
    assert record["checks_performed"] == []
