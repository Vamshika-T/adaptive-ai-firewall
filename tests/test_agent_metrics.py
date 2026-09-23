from evaluation.agent_metrics import AgentMetrics


class MockDecision:

    def __init__(self, action, risk_score):
        self.action = action
        self.risk_score = risk_score


def make_result(
    action,
    risk_score,
    tool_result
):

    return {
        "status": "COMPLETED",
        "tool_results": [
            {
                "decision": MockDecision(
                    action,
                    risk_score
                ),
                "result": tool_result
            }
        ]
    }


metrics = AgentMetrics()


# ============================================================
# LEGITIMATE REQUESTS
# ============================================================

result = make_result(
    "ALLOW",
    7.5,
    []
)

metrics.record_result(result)
metrics.record_legitimate_workflow(result)


result = make_result(
    "ALLOW",
    10.0,
    {
        "customer_id": "C001"
    }
)

metrics.record_result(result)
metrics.record_legitimate_workflow(result)


# ============================================================
# BLOCKED ATTACKS
# ============================================================

result = make_result(
    "BLOCK",
    100.0,
    None
)

metrics.record_result(result)
metrics.record_attack(result)


result = make_result(
    "BLOCK",
    100.0,
    None
)

metrics.record_result(result)
metrics.record_attack(result)


# ============================================================
# MONITOR
# ============================================================

result = make_result(
    "MONITOR",
    26.25,
    {
        "status": "executed"
    }
)

metrics.record_result(result)


# ============================================================
# VALIDATION
# ============================================================

summary = metrics.summary()

print("\n========================================")
print("AGENT METRICS")
print("========================================")

for key, value in summary.items():
    print(f"{key}: {value}")


assert summary["total_requests"] == 5
assert summary["allowed_requests"] == 2
assert summary["blocked_requests"] == 2
assert summary["monitor_requests"] == 1

assert summary["attack_scenarios"] == 2
assert summary["attacks_prevented"] == 2

assert summary["legitimate_workflows"] == 2
assert summary["legitimate_successes"] == 2

assert summary["attack_prevention_rate"] == 100.0
assert summary["legitimate_success_rate"] == 100.0

assert summary["tool_execution_rate"] == 60.0


print("\n========================================")
print("AGENT METRICS TEST PASSED")
print("========================================")