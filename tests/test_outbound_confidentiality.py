"""Deterministic regression tests for external email information-flow checks."""

from firewall.information_flow import InformationFlowTracker


def test_explicit_confidential_label_blocks_external_email_without_artifact():
    tracker = InformationFlowTracker()

    result = tracker.check_outbound_payload(
        session_id="test-a4",
        recipient="external@example.com",
        payload="[Confidential company information]",
    )

    assert result["allowed"] is False
    assert "confidential" in result["reason"].lower()
    assert "confidential company information" in result["matched_markers"]


def test_explicit_confidential_label_is_allowed_to_internal_recipient():
    tracker = InformationFlowTracker()

    result = tracker.check_outbound_payload(
        session_id="test-internal",
        recipient="bob@company.com",
        payload="[Confidential company information]",
    )

    assert result["allowed"] is True


def test_non_sensitive_external_email_remains_allowed():
    tracker = InformationFlowTracker()

    result = tracker.check_outbound_payload(
        session_id="test-normal",
        recipient="customer@example.com",
        payload="Please review the public project update.",
    )

    assert result["allowed"] is True
