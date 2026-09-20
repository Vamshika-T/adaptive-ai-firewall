from firewall.resource_limits import ResourceGuard


# ---------------------------------------------------------
# TEST 1: Request budget
# ---------------------------------------------------------

guard = ResourceGuard(
    max_requests_per_session=2,
    max_deep_inspections=1
)

ok, reason = guard.check_request_budget(
    "SESSION001"
)

assert ok is True

ok, reason = guard.check_request_budget(
    "SESSION001"
)

assert ok is True

ok, reason = guard.check_request_budget(
    "SESSION001"
)

assert ok is False
assert reason == "Session request limit exceeded"

print(
    "TEST 1 PASSED: Session request budget enforced"
)


# ---------------------------------------------------------
# TEST 2: Deep inspection budget
# ---------------------------------------------------------

ok, reason = guard.check_deep_inspection_budget(
    "SESSION001"
)

assert ok is True

ok, reason = guard.check_deep_inspection_budget(
    "SESSION001"
)

assert ok is False
assert reason == "Deep inspection budget exceeded"

print(
    "TEST 2 PASSED: Deep inspection budget enforced"
)


# ---------------------------------------------------------
# TEST 3: Session reset
# ---------------------------------------------------------

guard.reset_session(
    "SESSION001"
)

ok, reason = guard.check_request_budget(
    "SESSION001"
)

assert ok is True

ok, reason = guard.check_deep_inspection_budget(
    "SESSION001"
)

assert ok is True

print(
    "TEST 3 PASSED: Resource budgets reset with session"
)


print()
print("ALL RESOURCE LIMIT TESTS PASSED")