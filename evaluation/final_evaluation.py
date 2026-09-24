"""
Final deterministic security evaluation.

This program evaluates:

1. Authorization
2. ABAC
3. Trajectory analysis
4. Taint handling
5. Semantic inspection
6. Adaptive inspection
7. GDoS/resource limits
8. Legitimate workflows
9. Baseline vs protected execution

It uses the existing FirewallInterceptor.
It does NOT duplicate firewall security logic.
"""


from firewall.interceptor import FirewallInterceptor

from models.schemas import ToolRequest

from evaluation.scenarios import (
    SECURITY_SCENARIOS,
    LEGITIMATE_SCENARIOS,
)

from evaluation.security_metrics import (
    calculate_metrics,
    print_metrics,
)

from evaluation.baseline_vs_protected import (
    run_comparison,
)


# ============================================================
# REQUEST CREATION
# ============================================================


def create_request(
    scenario,
    session_id,
    request_number
):

    return ToolRequest(

        request_id=(
            f"{session_id}-REQ"
            f"{request_number:03d}"
        ),

        session_id=session_id,

        user_id=scenario["user_id"],

        tool=scenario["tool"],

        arguments=dict(
            scenario.get(
                "arguments",
                {}
            )
        ),

        intent=scenario.get(
            "intent",
            ""
        ),

        context_sources=list(
            scenario.get(
                "context_sources",
                []
            )
        ),

        tainted=scenario.get(
            "tainted",
            False
        ),

        source_type="evaluation",
    )


# ============================================================
# SINGLE REQUEST EVALUATION
# ============================================================


def evaluate_request(
    firewall,
    scenario,
    session_id,
    request_number
):

    request = create_request(
        scenario,
        session_id,
        request_number
    )

    decision, result = (
        firewall.execute(
            request
        )
    )

    reason_text = " ".join(
        decision.reasons
    ).lower()

    trajectory_detected = (
        "trajectory" in reason_text
        or "exfiltration" in reason_text
        or "follows" in reason_text
    )

    taint_detected = (
        request.tainted
        or "tainted" in reason_text
        or "provenance" in reason_text
    )

    resource_limit_block = (
        "budget" in reason_text
        or "limit exceeded" in reason_text
    )

    return {

        "scenario_id":
            scenario["id"],

        "scenario_name":
            scenario["name"],

        "category":
            scenario["category"],

        "firewall_reached":
            True,

        "action":
            decision.action,

        "risk_score":
            decision.risk_score,

        "inspection_level":
            decision.inspection_level,

        "tool_executed":
            result is not None,

        "result":
            result,

        "dangerous_execution":
            result is not None
            and scenario["category"]
            not in {
                "gdos",
                "gdos_deep",
            },

        "success":
            result is not None
            and decision.action
            in {
                "ALLOW",
                "MONITOR",
            },

        "trajectory_detected":
            trajectory_detected,

        "taint_detected":
            taint_detected,

        "resource_limit_block":
            resource_limit_block,

        "reasons":
            decision.reasons,
    }


# ============================================================
# SECURITY SCENARIOS
# ============================================================


def run_security_scenarios():

    records = []

    for scenario in SECURITY_SCENARIOS:

        firewall = FirewallInterceptor()

        session_id = (
            f"SEC-{scenario['id']}"
        )

        request_number = 1

        # ----------------------------------------------------
        # Prelude actions create session context.
        # ----------------------------------------------------

        for prelude in scenario.get(
            "prelude",
            []
        ):

            prelude_request = ToolRequest(

                request_id=(
                    f"{session_id}-PRE"
                    f"{request_number:03d}"
                ),

                session_id=session_id,

                user_id=prelude[
                    "user_id"
                ],

                tool=prelude[
                    "tool"
                ],

                arguments=dict(
                    prelude.get(
                        "arguments",
                        {}
                    )
                ),

                intent=prelude.get(
                    "intent",
                    ""
                ),

                source_type="evaluation",
            )

            firewall.execute(
                prelude_request
            )

            request_number += 1

        # ----------------------------------------------------
        # Normal scenario
        # ----------------------------------------------------

        repeat = scenario.get(
            "repeat",
            1
        )

        execution_results = []

        for _ in range(
            repeat
        ):

            record = evaluate_request(

                firewall,

                scenario,

                session_id,

                request_number
            )

            execution_results.append(
                record
            )

            request_number += 1

        # ----------------------------------------------------
        # Aggregate repeated resource tests into
        # ONE evaluation scenario.
        # ----------------------------------------------------

        if repeat > 1:

            final_record = (
                execution_results[-1]
            )

            executed_count = sum(
                item["tool_executed"]
                for item in execution_results
            )

            block_count = sum(
                item["action"] == "BLOCK"
                for item in execution_results
            )

            deep_block_count = sum(
                (
                    item["action"] == "BLOCK"
                    and item[
                        "resource_limit_block"
                    ]
                )
                for item in execution_results
            )

            final_record = dict(
                final_record
            )

            final_record[
                "repeat_count"
            ] = repeat

            final_record[
                "tool_execution_count"
            ] = executed_count

            final_record[
                "block_count"
            ] = block_count

            final_record[
                "resource_limit_block_count"
            ] = deep_block_count

            final_record[
                "dangerous_execution"
            ] = False

            final_record[
                "scenario_prevented"
            ] = (
                deep_block_count > 0
            )

            records.append(
                final_record
            )

        else:

            record = execution_results[0]

            # ------------------------------------------------
            # Security criterion for each attack class.
            # ------------------------------------------------

            if scenario["category"] in {
                "authorization",
                "abac",
            }:

                record[
                    "scenario_prevented"
                ] = (
                    record["action"]
                    == "BLOCK"
                )

            elif scenario["category"] in {
                "trajectory_exfiltration",
            }:

                record[
                    "scenario_prevented"
                ] = (
                    record["action"]
                    in {
                        "BLOCK",
                        "ESCALATE",
                    }
                )

            elif scenario["category"] in {
                "taint",
            }:

                record[
                    "scenario_prevented"
                ] = (
                    record["action"]
                    in {
                        "BLOCK",
                        "ESCALATE",
                    }
                )

            elif scenario["category"] == (
                "semantic_intent"
            ):

                # Semantic detection itself is the
                # security objective for this scenario.
                record[
                    "scenario_prevented"
                ] = (
                    record[
                        "taint_detected"
                    ]
                    or record[
                        "trajectory_detected"
                    ]
                    or record["action"]
                    in {
                        "BLOCK",
                        "ESCALATE",
                        "MONITOR",
                    }
                )

            else:

                record[
                    "scenario_prevented"
                ] = False

            records.append(
                record
            )

    for record in records:

        record["type"] = "attack"

    return records


# ============================================================
# LEGITIMATE SCENARIOS
# ============================================================


def run_legitimate_scenarios():

    records = []

    for scenario in (
        LEGITIMATE_SCENARIOS
    ):

        firewall = FirewallInterceptor()

        session_id = (
            f"LEG-{scenario['id']}"
        )

        record = evaluate_request(

            firewall,

            scenario,

            session_id,

            1
        )

        record[
            "scenario_prevented"
        ] = False

        record[
            "type"
        ] = "legitimate"

        records.append(
            record
        )

    return records


# ============================================================
# PRINT SCENARIO TABLE
# ============================================================


def print_scenario_results(
    records
):

    print("\n")

    print("=" * 100)

    print(
        "SCENARIO RESULTS"
    )

    print("=" * 100)

    print(
        f"{'ID':<7}"
        f"{'TYPE':<12}"
        f"{'ACTION':<12}"
        f"{'RISK':<8}"
        f"{'INSPECTION':<13}"
        f"{'EXECUTED':<11}"
        f"NAME"
    )

    print("-" * 100)

    for record in records:

        print(

            f"{record['scenario_id']:<7}"

            f"{record['type']:<12}"

            f"{record['action']:<12}"

            f"{record['risk_score']:<8}"

            f"{record['inspection_level']:<13}"

            f"{str(record['tool_executed']):<11}"

            f"{record['scenario_name']}"
        )


# ============================================================
# MAIN
# ============================================================


def main():

    print("\n")

    print("=" * 100)

    print(
        "ADAPTIVE CONTEXT-AWARE AI FIREWALL"
    )

    print(
        "FINAL PERSON 2 SECURITY EVALUATION"
    )

    print("=" * 100)

    # --------------------------------------------------------
    # Security
    # --------------------------------------------------------

    security_records = (
        run_security_scenarios()
    )

    # --------------------------------------------------------
    # Legitimate
    # --------------------------------------------------------

    legitimate_records = (
        run_legitimate_scenarios()
    )

    all_records = (
        security_records
        + legitimate_records
    )

    # --------------------------------------------------------
    # Scenario output
    # --------------------------------------------------------

    print_scenario_results(
        all_records
    )

    # --------------------------------------------------------
    # Metrics
    # --------------------------------------------------------

    metrics = calculate_metrics(
        all_records
    )

    print_metrics(
        metrics
    )

    # --------------------------------------------------------
    # Baseline comparison
    # --------------------------------------------------------

    print("\n")

    print("=" * 100)

    print(
        "CONTROLLED BASELINE VS PROTECTED EXPERIMENT"
    )

    print("=" * 100)

    run_comparison()

    # --------------------------------------------------------
    # Important interpretation
    # --------------------------------------------------------

    print("\n")

    print("=" * 100)

    print(
        "EVALUATION COMPLETE"
    )

    print("=" * 100)

    print(
        "The values above are generated from actual executions "
        "of the current repository."
    )

    print(
        "They must be treated as this experiment's measured "
        "results, not as predetermined claims."
    )


if __name__ == "__main__":

    main()