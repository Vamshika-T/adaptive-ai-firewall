
from firewall.information_flow import InformationFlowTracker


def test_derived_artifact_inherits_sensitivity_and_provenance():
    tracker = InformationFlowTracker()

    parent = tracker.record_artifact(
        session_id="LINEAGE_001",
        tool="query_database",
        resource="payroll",
        result={
            "employee_id": "EMP-123456",
            "salary": 125000,
        },
        sensitivity="RESTRICTED",
        provenance_sources=["database:payroll"],
    )

    derived = tracker.record_derived_artifact(
        session_id="LINEAGE_001",
        tool="summarize_data",
        resource="summary",
        result="A summary of employee compensation.",
        parent_artifact_ids=[parent["artifact_id"]],
    )

    assert derived["artifact_id"] != parent["artifact_id"]
    assert derived["parent_artifact_ids"] == [
        parent["artifact_id"]
    ]
    assert derived["sensitivity"] == "RESTRICTED"
    assert derived["provenance_sources"] == ["database:payroll"]

    check = tracker.check_outbound_payload(
        session_id="LINEAGE_001",
        recipient="attacker@example.com",
        payload="Report: A summary of employee compensation.",
    )

    assert check["allowed"] is False
    assert any(
        match["artifact_id"] == derived["artifact_id"]
        for match in check["matched_artifacts"]
    )

    print("PASSED: Unique artifact IDs assigned")
    print("PASSED: Parent lineage preserved")
    print("PASSED: Sensitivity inherited")
    print("PASSED: Provenance inherited")
    print("PASSED: Derived sensitive content detected")


def test_multiple_parents_inherit_highest_sensitivity():
    tracker = InformationFlowTracker()

    public_artifact = tracker.record_artifact(
        session_id="LINEAGE_002",
        tool="read_public_data",
        resource="public_docs",
        result={"description": "Public information"},
        sensitivity="PUBLIC",
        provenance_sources=["documents:public"],
    )

    restricted_artifact = tracker.record_artifact(
        session_id="LINEAGE_002",
        tool="query_database",
        resource="payroll",
        result={"employee_id": "EMP-987654"},
        sensitivity="RESTRICTED",
        provenance_sources=["database:payroll"],
    )

    derived = tracker.record_derived_artifact(
        session_id="LINEAGE_002",
        tool="summarize_data",
        resource="combined_summary",
        result="Combined report",
        parent_artifact_ids=[
            public_artifact["artifact_id"],
            restricted_artifact["artifact_id"],
        ],
    )

    assert derived["sensitivity"] == "RESTRICTED"
    assert derived["provenance_sources"] == [
        "database:payroll",
        "documents:public",
    ]

    print("PASSED: Highest parent sensitivity inherited")
    print("PASSED: All parent provenance sources preserved")


def test_unknown_parent_is_rejected():
    tracker = InformationFlowTracker()

    try:
        tracker.record_derived_artifact(
            session_id="LINEAGE_003",
            tool="summarize_data",
            resource="summary",
            result="Some summary",
            parent_artifact_ids=["missing-parent"],
        )
    except ValueError:
        print("PASSED: Unknown parent rejected")
    else:
        raise AssertionError(
            "Expected ValueError for unknown parent"
        )


def test_multilevel_lineage_inherits_restricted_sensitivity():
    tracker = InformationFlowTracker()
    session_id = "LINEAGE_MULTI_001"

    original = tracker.record_artifact(
        session_id=session_id,
        tool="query_database",
        resource="payroll",
        result={
            "employee_id": "U001",
            "salary": 145000,
        },
        sensitivity="RESTRICTED",
        provenance_sources=["database:payroll"],
    )

    summary = tracker.record_derived_artifact(
        session_id=session_id,
        tool="summarize_data",
        resource="summary",
        result="Restricted compensation summary for U001.",
        parent_artifact_ids=[original["artifact_id"]],
    )

    report = tracker.record_derived_artifact(
        session_id=session_id,
        tool="generate_report",
        resource="report",
        result=(
            "Final report: Restricted compensation summary for U001."
        ),
        parent_artifact_ids=[summary["artifact_id"]],
    )

    assert summary["sensitivity"] == "RESTRICTED"
    assert report["sensitivity"] == "RESTRICTED"

    assert summary["parent_artifact_ids"] == [
        original["artifact_id"]
    ]
    assert report["parent_artifact_ids"] == [
        summary["artifact_id"]
    ]

    assert report["provenance_sources"] == ["database:payroll"]

    check = tracker.check_outbound_payload(
        session_id=session_id,
        recipient="attacker@example.com",
        payload=(
            "Final report: Restricted compensation summary for U001."
        ),
    )

    assert check["allowed"] is False
    assert any(
        match["artifact_id"] == report["artifact_id"]
        for match in check["matched_artifacts"]
    )

    print("PASSED: Multi-level parent chain preserved")
    print("PASSED: Restricted sensitivity inherited through both steps")
    print("PASSED: Original provenance preserved")
    print("PASSED: Final report detected in external payload")


if __name__ == "__main__":
    test_derived_artifact_inherits_sensitivity_and_provenance()
    test_multiple_parents_inherit_highest_sensitivity()
    test_unknown_parent_is_rejected()
    test_multilevel_lineage_inherits_restricted_sensitivity()

    print("\nALL DERIVED-LINEAGE TESTS PASSED")
