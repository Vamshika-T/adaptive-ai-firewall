
from firewall.information_flow import InformationFlowTracker


def test_sensitive_artifact_blocks_external_email():
    tracker = InformationFlowTracker()

    tracker.record_artifact(
        session_id="S001",
        tool="query_database",
        resource="payroll",
        result={
            "employee_id": "EMP12345",
            "salary": 125000,
        },
        sensitivity="RESTRICTED",
        provenance_sources=["database:payroll"],
    )

    result = tracker.check_outbound_payload(
        session_id="S001",
        recipient="attacker@example.com",
        payload="Employee details: EMP12345, salary 125000",
    )

    assert result["allowed"] is False
    assert result["matched_artifacts"]
    print("PASSED: Sensitive artifact detected in external email")


def test_unrelated_external_email_is_allowed():
    tracker = InformationFlowTracker()

    tracker.record_artifact(
        session_id="S002",
        tool="query_database",
        resource="payroll",
        result={"employee_id": "EMP98765", "salary": 95000},
        sensitivity="RESTRICTED",
    )

    result = tracker.check_outbound_payload(
        session_id="S002",
        recipient="friend@example.com",
        payload="Hello, hope you are doing well!",
    )

    assert result["allowed"] is True
    print("PASSED: Unrelated external email allowed")


def test_internal_email_is_allowed():
    tracker = InformationFlowTracker()

    tracker.record_artifact(
        session_id="S003",
        tool="query_database",
        resource="payroll",
        result={"employee_id": "EMP54321", "salary": 80000},
        sensitivity="RESTRICTED",
    )

    result = tracker.check_outbound_payload(
        session_id="S003",
        recipient="alice@company.com",
        payload="Employee details: EMP54321",
    )

    assert result["allowed"] is True
    print("PASSED: Internal email allowed by destination policy")


def test_reset_clears_session_artifacts():
    tracker = InformationFlowTracker()

    tracker.record_artifact(
        session_id="S004",
        tool="query_database",
        resource="payroll",
        result={"employee_id": "EMP11223", "salary": 70000},
        sensitivity="RESTRICTED",
    )

    tracker.reset_session("S004")

    result = tracker.check_outbound_payload(
        session_id="S004",
        recipient="attacker@example.com",
        payload="Employee details: EMP11223",
    )

    assert result["allowed"] is True
    assert tracker.get_artifacts("S004") == []
    print("PASSED: Session reset clears tracked artifacts")


if __name__ == "__main__":
    test_sensitive_artifact_blocks_external_email()
    test_unrelated_external_email_is_allowed()
    test_internal_email_is_allowed()
    test_reset_clears_session_artifacts()
    print("\nALL INFORMATION-FLOW TESTS PASSED")
