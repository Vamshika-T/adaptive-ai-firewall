
from models.schemas import ToolRequest
from firewall.inspection import (
    determine_preliminary_inspection_level,
)


def make_request(tool="search_employee", context_sources=None):
    return ToolRequest(
        request_id="ROUTING-TEST-001",
        session_id="ROUTING-SESSION-001",
        user_id="U001",
        tool=tool,
        arguments={"employee_id": "U001"},
        intent="Look up an employee.",
        context_sources=context_sources or [],
    )


def test_low_risk_request_uses_fast_inspection():
    request = make_request()

    result = determine_preliminary_inspection_level(
        request=request,
        sensitivity_score=25,
        tainted=False,
        provenance_trusted=True,
    )

    assert result["level"] == "FAST"


def test_context_sources_use_contextual_inspection():
    request = make_request(
        context_sources=["email:E005"]
    )

    result = determine_preliminary_inspection_level(
        request=request,
        sensitivity_score=25,
        tainted=False,
        provenance_trusted=True,
    )

    assert result["level"] == "CONTEXTUAL"


def test_confidential_resource_uses_contextual_inspection():
    request = make_request()

    result = determine_preliminary_inspection_level(
        request=request,
        sensitivity_score=50,
        tainted=False,
        provenance_trusted=True,
    )

    assert result["level"] == "CONTEXTUAL"


def test_restricted_resource_uses_deep_inspection():
    request = make_request()

    result = determine_preliminary_inspection_level(
        request=request,
        sensitivity_score=75,
        tainted=False,
        provenance_trusted=True,
    )

    assert result["level"] == "DEEP"


def test_tainted_request_uses_deep_inspection():
    request = make_request()

    result = determine_preliminary_inspection_level(
        request=request,
        sensitivity_score=25,
        tainted=True,
        provenance_trusted=True,
    )

    assert result["level"] == "DEEP"


def test_untrusted_provenance_uses_deep_inspection():
    request = make_request()

    result = determine_preliminary_inspection_level(
        request=request,
        sensitivity_score=25,
        tainted=False,
        provenance_trusted=False,
    )

    assert result["level"] == "DEEP"


def test_tainted_write_action_explains_deep_inspection():
    request = make_request(
        tool="send_email_message"
    )

    result = determine_preliminary_inspection_level(
        request=request,
        sensitivity_score=25,
        tainted=True,
        provenance_trusted=True,
    )

    assert result["level"] == "DEEP"
    assert any(
        "write action" in reason.lower()
        for reason in result["reasons"]
    )


if __name__ == "__main__":
    print("Running adaptive routing tests...")

    test_low_risk_request_uses_fast_inspection()
    test_context_sources_use_contextual_inspection()
    test_confidential_resource_uses_contextual_inspection()
    test_restricted_resource_uses_deep_inspection()
    test_tainted_request_uses_deep_inspection()
    test_untrusted_provenance_uses_deep_inspection()
    test_tainted_write_action_explains_deep_inspection()

    print("All adaptive routing tests passed.")
