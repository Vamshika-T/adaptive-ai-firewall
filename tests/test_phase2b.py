from firewall.provenance import (
    evaluate_provenance,
    ProvenanceTracker
)


# ---------------------------------------------------------
# TEST 1: Trusted internal email
# ---------------------------------------------------------

result = evaluate_provenance(
    ["email:E001"]
)

assert result["trusted"] is True
assert result["tainted"] is False

print(
    "TEST 1 PASSED: Trusted internal email"
)


# ---------------------------------------------------------
# TEST 2: Untrusted external email
# ---------------------------------------------------------

result = evaluate_provenance(
    ["email:E003"]
)

assert result["trusted"] is False
assert result["tainted"] is True

print(
    "TEST 2 PASSED: Untrusted external email detected"
)


# ---------------------------------------------------------
# TEST 3: Trusted external email
# ---------------------------------------------------------

result = evaluate_provenance(
    ["email:E005"]
)

assert result["trusted"] is True
assert result["tainted"] is False

print(
    "TEST 3 PASSED: Trusted external email remains trusted"
)


# ---------------------------------------------------------
# TEST 4: Mixed sources
# ---------------------------------------------------------

result = evaluate_provenance(
    [
        "email:E001",
        "email:E003"
    ]
)

assert result["trusted"] is False
assert result["tainted"] is True
assert len(result["sources"]) == 2

print(
    "TEST 4 PASSED: Mixed trusted/untrusted sources detected"
)


# ---------------------------------------------------------
# TEST 5: Unknown source
# ---------------------------------------------------------

result = evaluate_provenance(
    ["unknown:SOURCE001"]
)

assert result["trusted"] is False
assert result["tainted"] is True

print(
    "TEST 5 PASSED: Unknown source treated conservatively"
)


# ---------------------------------------------------------
# TEST 6: Session taint propagation
# ---------------------------------------------------------

tracker = ProvenanceTracker()

session_id = "PHASE2B_SESSION_001"

tracker.process_context_sources(
    session_id,
    ["email:E003"]
)

assert tracker.is_tainted(
    session_id
) is True

print(
    "TEST 6 PASSED: Untrusted context taints session"
)


# ---------------------------------------------------------
# TEST 7: Taint persists
# ---------------------------------------------------------

tracker.process_context_sources(
    session_id,
    ["email:E001"]
)

assert tracker.is_tainted(
    session_id
) is True

print(
    "TEST 7 PASSED: Taint persists after trusted context"
)


# ---------------------------------------------------------
# TEST 8: Trusted external source does not taint
# ---------------------------------------------------------

tracker2 = ProvenanceTracker()

session_id = "PHASE2B_SESSION_002"

tracker2.process_context_sources(
    session_id,
    ["email:E005"]
)

assert tracker2.is_tainted(
    session_id
) is False

print(
    "TEST 8 PASSED: Trusted external source does not taint session"
)


# ---------------------------------------------------------
# TEST 9: Provenance history is maintained
# ---------------------------------------------------------

sources = tracker.get_sources(
    "PHASE2B_SESSION_001"
)

assert len(sources) == 2
assert sources[0]["id"] == "E003"
assert sources[1]["id"] == "E001"

print(
    "TEST 9 PASSED: Provenance history maintained"
)


# ---------------------------------------------------------
# TEST 10: Session reset
# ---------------------------------------------------------

tracker.reset_session(
    "PHASE2B_SESSION_001"
)

assert tracker.is_tainted(
    "PHASE2B_SESSION_001"
) is False

assert tracker.get_sources(
    "PHASE2B_SESSION_001"
) == []

print(
    "TEST 10 PASSED: Session reset clears provenance"
)


print()
print("ALL PHASE 2B PROVENANCE TESTS PASSED")