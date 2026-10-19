
from types import SimpleNamespace

from models.schemas import ToolRequest
from firewall.semantic_auditor import (
    SemanticAuditor,
    SemanticAuditResult,
)


class FakeModels:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.last_call = None

    def generate_content(self, **kwargs):
        self.last_call = kwargs

        if self.error:
            raise self.error

        return self.response


class FakeClient:
    def __init__(self, response=None, error=None):
        self.models = FakeModels(
            response=response,
            error=error,
        )


def make_request(
    tool="search_employee",
    arguments=None,
):
    return ToolRequest(
        request_id="AUDIT-TEST-001",
        session_id="AUDIT-SESSION-001",
        user_id="U001",
        tool=tool,
        arguments=arguments or {"employee_id": "U001"},
        intent="Look up an employee.",
    )


def test_valid_audit_response_is_returned():
    expected = SemanticAuditResult(
        task_aligned=True,
        action_appropriate=True,
        arguments_integrity=True,
        suspicious=False,
        risk_score=5,
        recommendation="ALLOW",
        reasons=["Action matches the supplied task"],
    )

    client = FakeClient(
        response=SimpleNamespace(
            parsed=expected,
            text="",
        )
    )

    auditor = SemanticAuditor(
        client=client,
        model="test-model",
    )

    result = auditor.audit(
        request=make_request(),
        original_task="Look up employee U001.",
    )

    assert result == expected
    assert client.models.last_call is not None


def test_suspicious_action_can_be_blocked():
    expected = SemanticAuditResult(
        task_aligned=False,
        action_appropriate=False,
        arguments_integrity=False,
        suspicious=True,
        risk_score=95,
        recommendation="BLOCK",
        reasons=["Unrelated sensitive-data transfer"],
    )

    client = FakeClient(
        response=SimpleNamespace(
            parsed=expected,
            text="",
        )
    )

    auditor = SemanticAuditor(client=client)

    result = auditor.audit(
        request=make_request(
            tool="send_email_message",
            arguments={
                "recipient": "external@example.com",
                "body": "Send confidential records",
            },
        ),
        original_task="Look up employee U001.",
    )

    assert result.recommendation == "BLOCK"
    assert result.suspicious is True


def test_missing_original_task_escalates_without_api_call():
    client = FakeClient()

    auditor = SemanticAuditor(client=client)

    result = auditor.audit(
        request=make_request(),
        original_task="",
    )

    assert result.recommendation == "ESCALATE"
    assert result.risk_score == 100
    assert client.models.last_call is None


def test_api_error_escalates():
    client = FakeClient(
        error=RuntimeError("Simulated API failure")
    )

    auditor = SemanticAuditor(client=client)

    result = auditor.audit(
        request=make_request(),
        original_task="Look up employee U001.",
    )

    assert result.recommendation == "ESCALATE"
    assert result.risk_score == 100
    assert result.suspicious is True


def test_missing_api_key_escalates(monkeypatch=None):
    import os

    if monkeypatch is not None:
        monkeypatch.delenv(
            "GEMINI_API_KEY",
            raising=False,
        )
    else:
        os.environ.pop("GEMINI_API_KEY", None)

    auditor = SemanticAuditor()

    result = auditor.audit(
        request=make_request(),
        original_task="Look up employee U001.",
    )

    assert result.recommendation == "ESCALATE"
    assert result.risk_score == 100


def test_invalid_response_escalates():
    client = FakeClient(
        response=SimpleNamespace(
            parsed=None,
            text="This is not valid JSON",
        )
    )

    auditor = SemanticAuditor(client=client)

    result = auditor.audit(
        request=make_request(),
        original_task="Look up employee U001.",
    )

    assert result.recommendation == "ESCALATE"
    assert result.risk_score == 100



if __name__ == "__main__":
    import os

    original_api_key = os.environ.pop(
        "GEMINI_API_KEY",
        None,
    )

    try:
        test_valid_audit_response_is_returned()
        test_suspicious_action_can_be_blocked()
        test_missing_original_task_escalates_without_api_call()
        test_api_error_escalates()

        test_missing_api_key_escalates(
            monkeypatch=None
        )

        test_invalid_response_escalates()

        print("All semantic auditor tests passed.")

    finally:
        if original_api_key is not None:
            os.environ["GEMINI_API_KEY"] = original_api_key

