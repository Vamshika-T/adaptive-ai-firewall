"""
Unfamiliar Attack Evaluation

Compares:

1. No Defense
2. RBAC/ABAC Only
3. AgentVisor-style STI
4. Adaptive AI Firewall

against previously unseen/unfamiliar controlled attack scenarios.

This evaluator is intentionally separate from:
    evaluation/comparative_evaluation.py
"""

import csv
import os
import statistics
import time

from models.schemas import ToolRequest
from tools.registry import execute_tool

from firewall.authorization import check_rbac
from firewall.abac import check_abac
from firewall.interceptor import FirewallInterceptor

from evaluation.unfamiliar_scenarios import UNFAMILIAR_SCENARIOS


# ============================================================
# OUTPUT DIRECTORY
# ============================================================

OUTPUT_DIR = os.path.join(
    os.path.dirname(__file__),
    "comparison_results",
    "unfamiliar",
)

os.makedirs(OUTPUT_DIR, exist_ok=True)


# ============================================================
# REQUEST HELPERS
# ============================================================

def get_requests(scenario):
    """
    Build the complete request sequence.

    The unfamiliar scenario format stores the final request
    directly at the scenario level:

        scenario["tool"]
        scenario["arguments"]
        scenario["intent"]
        ...

    Prelude requests are stored in:

        scenario["prelude"]
    """

    requests = []

    # --------------------------------------------------------
    # Prelude requests
    # --------------------------------------------------------

    for prelude_request in scenario.get("prelude", []):
        requests.append(prelude_request)

    # --------------------------------------------------------
    # Final request
    # --------------------------------------------------------

    requests.append({
        "user_id": scenario["user_id"],
        "tool": scenario["tool"],
        "arguments": scenario.get(
            "arguments",
            {},
        ),
        "intent": scenario.get(
            "intent",
            "",
        ),
        "tainted": scenario.get(
            "tainted",
            False,
        ),
        "context_sources": scenario.get(
            "context_sources",
            [],
        ),
        "source_type": scenario.get(
            "source_type",
            "agent",
        ),
        "request_id": scenario.get(
            "request_id"
        ),
        "function_call_id": scenario.get(
            "function_call_id"
        ),
    })

    return requests


def make_request(
    scenario,
    request_data,
    index,
):
    """
    Convert a scenario request dictionary into ToolRequest.
    """

    request_id = request_data.get(
        "request_id"
    )

    if not request_id:
        request_id = (
            f"{scenario['id']}-REQ-{index + 1}"
        )

    return ToolRequest(
        request_id=request_id,
        session_id=scenario["id"],
        user_id=request_data.get(
            "user_id",
            scenario["user_id"],
        ),
        tool=request_data["tool"],
        arguments=request_data.get(
            "arguments",
            {},
        ),
        intent=request_data.get(
            "intent",
            "",
        ),
        context_sources=request_data.get(
            "context_sources",
            [],
        ),
        tainted=request_data.get(
            "tainted",
            False,
        ),
        source_type=request_data.get(
            "source_type",
            "agent",
        ),
        function_call_id=request_data.get(
            "function_call_id"
        ),
    )


# ============================================================
# DIRECT EXECUTION
# ============================================================

def execute_direct(request):

    start = time.perf_counter()

    try:

        result = execute_tool(
            request.tool,
            request.arguments,
        )

        latency = (
            time.perf_counter() - start
        ) * 1000

        return {
            "executed": True,
            "result": result,
            "latency_ms": latency,
            "action": "ALLOW",
            "error": None,
        }

    except Exception as exc:

        latency = (
            time.perf_counter() - start
        ) * 1000

        return {
            "executed": False,
            "result": None,
            "latency_ms": latency,
            "action": "EXCEPTION",
            "error": str(exc),
        }


# ============================================================
# NORMALIZE RBAC / ABAC RESULT
# ============================================================

def extract_check_result(result):

    if isinstance(result, tuple):

        allowed = bool(result[0])

        reason = (
            result[1]
            if len(result) > 1
            else ""
        )

        return allowed, str(reason)

    if hasattr(result, "allowed"):

        allowed = bool(
            result.allowed
        )

        reason = getattr(
            result,
            "reason",
            "",
        )

        return allowed, str(reason)

    return bool(result), ""


# ============================================================
# DECISION FIELD HELPER
# ============================================================

def get_decision_value(
    decision,
    name,
    default=None,
):

    if hasattr(decision, name):

        return getattr(
            decision,
            name,
            default,
        )

    if isinstance(decision, dict):

        return decision.get(
            name,
            default,
        )

    return default


# ============================================================
# RECORD
# ============================================================

def base_record(
    scenario,
    method,
    request,
    execution,
    is_prelude=False,
    risk=None,
    inspection=None,
    reasons=None,
):

    return {
        "scenario_id": scenario["id"],
        "scenario_name": scenario["name"],
        "category": scenario.get(
            "category",
            "",
        ),
        "type": scenario["type"],
        "method": method,

        "request_id": request.request_id,
        "tool": request.tool,
        "user_id": request.user_id,

        "is_prelude": is_prelude,

        "action": execution.get(
            "action"
        ),
        "executed": execution.get(
            "executed"
        ),

        "risk_score": risk,
        "inspection_level": inspection,

        "latency_ms": execution.get(
            "latency_ms",
            0,
        ),

        "reasons": "; ".join(
            str(reason)
            for reason in (reasons or [])
            if reason
        ),

        "error": execution.get(
            "error"
        ),
    }


# ============================================================
# 1. NO DEFENSE
# ============================================================

def run_no_defense(scenario):

    records = []

    requests = get_requests(
        scenario
    )

    for index, request_data in enumerate(
        requests
    ):

        request = make_request(
            scenario,
            request_data,
            index,
        )

        execution = execute_direct(
            request
        )

        records.append(
            base_record(
                scenario=scenario,
                method="No Defense",
                request=request,
                execution=execution,
                is_prelude=(
                    index < len(requests) - 1
                ),
            )
        )

    return records


# ============================================================
# 2. RBAC / ABAC ONLY
# ============================================================

def run_rbac_abac(scenario):

    records = []

    requests = get_requests(
        scenario
    )

    for index, request_data in enumerate(
        requests
    ):

        request = make_request(
            scenario,
            request_data,
            index,
        )

        start = time.perf_counter()

        try:

            # ------------------------------------------------
            # RBAC
            # ------------------------------------------------

            rbac_result = check_rbac(
                request.user_id,
                request.tool,
                request.arguments,
            )

            rbac_allowed, rbac_reason = (
                extract_check_result(
                    rbac_result
                )
            )

            if not rbac_allowed:

                latency = (
                    time.perf_counter()
                    - start
                ) * 1000

                execution = {
                    "executed": False,
                    "result": None,
                    "latency_ms": latency,
                    "action": "BLOCK",
                    "error": None,
                }

                records.append(
                    base_record(
                        scenario,
                        "RBAC/ABAC Only",
                        request,
                        execution,
                        index < len(requests) - 1,
                        reasons=[
                            rbac_reason
                        ],
                    )
                )

                continue

            # ------------------------------------------------
            # ABAC
            # ------------------------------------------------

            abac_result = check_abac(
                request.user_id,
                request.tool,
                request.arguments,
            )

            abac_allowed, abac_reason = (
                extract_check_result(
                    abac_result
                )
            )

            if not abac_allowed:

                latency = (
                    time.perf_counter()
                    - start
                ) * 1000

                execution = {
                    "executed": False,
                    "result": None,
                    "latency_ms": latency,
                    "action": "BLOCK",
                    "error": None,
                }

                records.append(
                    base_record(
                        scenario,
                        "RBAC/ABAC Only",
                        request,
                        execution,
                        index < len(requests) - 1,
                        reasons=[
                            abac_reason
                        ],
                    )
                )

                continue

            # ------------------------------------------------
            # Authorized -> execute
            # ------------------------------------------------

            execution = execute_direct(
                request
            )

            execution["latency_ms"] += (
                time.perf_counter() - start
            ) * 1000

            records.append(
                base_record(
                    scenario,
                    "RBAC/ABAC Only",
                    request,
                    execution,
                    index < len(requests) - 1,
                )
            )

        except Exception as exc:

            latency = (
                time.perf_counter()
                - start
            ) * 1000

            execution = {
                "executed": False,
                "result": None,
                "latency_ms": latency,
                "action": "EXCEPTION",
                "error": str(exc),
            }

            records.append(
                base_record(
                    scenario,
                    "RBAC/ABAC Only",
                    request,
                    execution,
                    index < len(requests) - 1,
                )
            )

    return records


# ============================================================
# 3. AGENTVISOR-STYLE STI
# ============================================================

FORBIDDEN_PATTERNS = [
    "ignore previous instructions",
    "ignore previous instruction",
    "reveal secret",
    "reveal confidential",
    "reveal sensitive",
    "leak secret",
    "leak confidential",
    "leak sensitive",
]


def visor_suitability(request):

    text = (
        f"{request.intent} "
        f"{request.tool} "
        f"{request.arguments}"
    ).lower()

    for pattern in FORBIDDEN_PATTERNS:

        if pattern in text:

            return (
                False,
                f"Forbidden goal pattern: {pattern}",
            )

    return True, ""


def visor_taint(request):
    """
    The baseline intentionally does not inspect the raw
    firewall tainted/context_sources fields.
    """

    return True, ""


def visor_integrity(
    history,
    request,
):

    previous_tools = [
        item["tool"]
        for item in history
    ]

    recipient = str(
        request.arguments.get(
            "recipient",
            "",
        )
    ).lower()

    sender = str(
        request.arguments.get(
            "sender",
            "",
        )
    ).lower()

    external_recipient = (
        recipient != ""
        and recipient != sender
        and "@" in recipient
    )

    if (
        request.tool
        == "send_email_message"
        and "query_database"
        in previous_tools
        and external_recipient
    ):

        return (
            False,
            "External email follows database access",
        )

    return True, ""


def run_agentvisor(scenario):

    records = []

    history = []

    requests = get_requests(
        scenario
    )

    for index, request_data in enumerate(
        requests
    ):

        request = make_request(
            scenario,
            request_data,
            index,
        )

        start = time.perf_counter()

        try:

            suitable, suitability_reason = (
                visor_suitability(
                    request
                )
            )

            taint_ok, taint_reason = (
                visor_taint(
                    request
                )
            )

            integrity_ok, integrity_reason = (
                visor_integrity(
                    history,
                    request,
                )
            )

            reasons = [
                reason
                for reason in [
                    suitability_reason,
                    taint_reason,
                    integrity_reason,
                ]
                if reason
            ]

            allowed = (
                suitable
                and taint_ok
                and integrity_ok
            )

            if not allowed:

                latency = (
                    time.perf_counter()
                    - start
                ) * 1000

                execution = {
                    "executed": False,
                    "result": None,
                    "latency_ms": latency,
                    "action": "BLOCK",
                    "error": None,
                }

            else:

                execution = execute_direct(
                    request
                )

                execution["latency_ms"] += (
                    time.perf_counter()
                    - start
                ) * 1000

            records.append(
                base_record(
                    scenario,
                    "AgentVisor-style STI",
                    request,
                    execution,
                    index < len(requests) - 1,
                    reasons=reasons,
                )
            )

            history.append({
                "tool": request.tool,
                "arguments": dict(
                    request.arguments
                ),
                "status": execution[
                    "action"
                ],
            })

        except Exception as exc:

            latency = (
                time.perf_counter()
                - start
            ) * 1000

            execution = {
                "executed": False,
                "result": None,
                "latency_ms": latency,
                "action": "EXCEPTION",
                "error": str(exc),
            }

            records.append(
                base_record(
                    scenario,
                    "AgentVisor-style STI",
                    request,
                    execution,
                    index < len(requests) - 1,
                )
            )

    return records


# ============================================================
# 4. ADAPTIVE AI FIREWALL
# ============================================================

def run_adaptive_firewall(scenario):

    records = []

    # One firewall instance per scenario.
    #
    # This is important because the trajectory detector,
    # provenance tracker and session history need to see
    # the previous requests in the same scenario.

    firewall = FirewallInterceptor()

    requests = get_requests(
        scenario
    )

    for index, request_data in enumerate(
        requests
    ):

        request = make_request(
            scenario,
            request_data,
            index,
        )

        start = time.perf_counter()

        try:

            decision = firewall.inspect(
                request
            )

            inspection_latency = (
                time.perf_counter()
                - start
            ) * 1000

            action = get_decision_value(
                decision,
                "action",
                "UNKNOWN",
            )

            # Enum -> string
            action = getattr(
                action,
                "value",
                action,
            )

            action = str(
                action
            ).upper()

            risk = get_decision_value(
                decision,
                "risk_score",
                None,
            )

            inspection = get_decision_value(
                decision,
                "inspection_level",
                None,
            )

            reasons = get_decision_value(
                decision,
                "reasons",
                [],
            )

            if reasons is None:
                reasons = []

            # ------------------------------------------------
            # BLOCK / ESCALATE
            # ------------------------------------------------

            if action in {
                "BLOCK",
                "ESCALATE",
            }:

                execution = {
                    "executed": False,
                    "result": None,
                    "latency_ms": inspection_latency,
                    "action": action,
                    "error": None,
                }

            # ------------------------------------------------
            # ALLOW / MONITOR
            # ------------------------------------------------

            else:

                tool_start = (
                    time.perf_counter()
                )

                try:

                    result = execute_tool(
                        request.tool,
                        request.arguments,
                    )

                    tool_latency = (
                        time.perf_counter()
                        - tool_start
                    ) * 1000

                    execution = {
                        "executed": True,
                        "result": result,
                        "latency_ms": (
                            inspection_latency
                            + tool_latency
                        ),
                        "action": action,
                        "error": None,
                    }

                except Exception as exc:

                    tool_latency = (
                        time.perf_counter()
                        - tool_start
                    ) * 1000

                    execution = {
                        "executed": False,
                        "result": None,
                        "latency_ms": (
                            inspection_latency
                            + tool_latency
                        ),
                        "action": "EXCEPTION",
                        "error": str(exc),
                    }

            records.append(
                base_record(
                    scenario,
                    "Adaptive AI Firewall",
                    request,
                    execution,
                    index < len(requests) - 1,
                    risk=risk,
                    inspection=inspection,
                    reasons=reasons,
                )
            )

        except Exception as exc:

            latency = (
                time.perf_counter()
                - start
            ) * 1000

            execution = {
                "executed": False,
                "result": None,
                "latency_ms": latency,
                "action": "EXCEPTION",
                "error": str(exc),
            }

            records.append(
                base_record(
                    scenario,
                    "Adaptive AI Firewall",
                    request,
                    execution,
                    index < len(requests) - 1,
                )
            )

    return records


# ============================================================
# AGGREGATE SCENARIOS
# ============================================================

def aggregate_scenarios(records):

    grouped = {}

    for record in records:

        key = (
            record["scenario_id"],
            record["method"],
        )

        grouped.setdefault(
            key,
            [],
        ).append(record)

    results = []

    for (
        scenario_key,
        scenario_records,
    ) in grouped.items():

        scenario_id, method = scenario_key

        scenario_type = scenario_records[0][
            "type"
        ]

        final_records = [
            record
            for record in scenario_records
            if not record["is_prelude"]
        ]

        prelude_records = [
            record
            for record in scenario_records
            if record["is_prelude"]
        ]

        final_executed = any(
            record["executed"]
            for record in final_records
        )

        final_actions = [
            record["action"]
            for record in final_records
        ]

        executed_requests = sum(
            1
            for record in scenario_records
            if record["executed"]
        )

        total_requests = len(
            scenario_records
        )

        latencies = [
            record["latency_ms"]
            for record in scenario_records
        ]

        risks = [
            record["risk_score"]
            for record in scenario_records
            if record["risk_score"] is not None
        ]

        deep_inspections = sum(
            1
            for record in scenario_records
            if str(
                record["inspection_level"]
            ).upper() == "DEEP"
        )

        # ----------------------------------------------------
        # ATTACK
        # ----------------------------------------------------

        if scenario_type == "attack":

            # A prelude may legitimately execute.
            #
            # The attack is prevented when the final impact
            # request does not execute.

            prevented = not final_executed

            dangerous_execution = (
                final_executed
            )

        # ----------------------------------------------------
        # LEGITIMATE
        # ----------------------------------------------------

        else:

            prevented = False
            dangerous_execution = False

        results.append({

            "scenario_id": scenario_id,

            "scenario_name": scenario_records[0][
                "scenario_name"
            ],

            "category": scenario_records[0][
                "category"
            ],

            "type": scenario_type,

            "method": method,

            "prevented": prevented,

            "dangerous_execution": (
                dangerous_execution
            ),

            "final_executed": (
                final_executed
            ),

            "final_actions": (
                "; ".join(final_actions)
            ),

            "total_requests": (
                total_requests
            ),

            "prelude_requests": len(
                prelude_records
            ),

            "executed_requests": (
                executed_requests
            ),

            "total_latency_ms": sum(
                latencies
            ),

            "avg_latency_ms": (
                statistics.mean(latencies)
                if latencies
                else 0
            ),

            "median_latency_ms": (
                statistics.median(latencies)
                if latencies
                else 0
            ),

            "mean_risk": (
                statistics.mean(risks)
                if risks
                else None
            ),

            "max_risk": (
                max(risks)
                if risks
                else None
            ),

            "deep_inspections": (
                deep_inspections
            ),

            "deep_inspection_rate": (
                deep_inspections
                / total_requests
                if total_requests
                else 0
            ),
        })

    return results


# ============================================================
# METHOD METRICS
# ============================================================

def calculate_method_metrics(
    scenario_results
):

    methods = sorted(
        set(
            result["method"]
            for result in scenario_results
        )
    )

    metrics = []

    for method in methods:

        rows = [
            result
            for result in scenario_results
            if result["method"] == method
        ]

        attacks = [
            result
            for result in rows
            if result["type"] == "attack"
        ]

        legitimate = [
            result
            for result in rows
            if result["type"]
            == "legitimate"
        ]

        attack_count = len(
            attacks
        )

        legitimate_count = len(
            legitimate
        )

        prevented_attacks = sum(
            1
            for result in attacks
            if result["prevented"]
        )

        dangerous_executions = sum(
            1
            for result in attacks
            if result["dangerous_execution"]
        )

        legitimate_successes = sum(
            1
            for result in legitimate
            if result["final_executed"]
        )

        false_positives = (
            legitimate_count
            - legitimate_successes
        )

        scenario_latencies = [
            result["avg_latency_ms"]
            for result in rows
        ]

        total_requests = sum(
            result["total_requests"]
            for result in rows
        )

        executed_requests = sum(
            result["executed_requests"]
            for result in rows
        )

        deep_inspections = sum(
            result["deep_inspections"]
            for result in rows
        )

        metrics.append({

            "method": method,

            "attack_count": (
                attack_count
            ),

            "attack_prevention_rate": (
                prevented_attacks
                / attack_count
                if attack_count
                else 0
            ),

            # Same numerator/denominator, but explicitly
            # named for the unfamiliar-scenario experiment.
            "first_exposure_prevention_rate": (
                prevented_attacks
                / attack_count
                if attack_count
                else 0
            ),

            "dangerous_execution_rate": (
                dangerous_executions
                / attack_count
                if attack_count
                else 0
            ),

            "legitimate_count": (
                legitimate_count
            ),

            "legitimate_success_rate": (
                legitimate_successes
                / legitimate_count
                if legitimate_count
                else 0
            ),

            "false_positive_rate": (
                false_positives
                / legitimate_count
                if legitimate_count
                else 0
            ),

            "avg_scenario_latency_ms": (
                statistics.mean(
                    scenario_latencies
                )
                if scenario_latencies
                else 0
            ),

            "median_scenario_latency_ms": (
                statistics.median(
                    scenario_latencies
                )
                if scenario_latencies
                else 0
            ),

            "executed_requests": (
                executed_requests
            ),

            "total_requests": (
                total_requests
            ),

            "deep_inspection_rate": (
                deep_inspections
                / total_requests
                if total_requests
                else 0
            ),
        })

    return metrics


# ============================================================
# CSV WRITER
# ============================================================

def write_csv(
    path,
    rows,
):

    if not rows:
        return

    fieldnames = list(
        rows[0].keys()
    )

    with open(
        path,
        "w",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(rows)


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("UNFAMILIAR ATTACK EVALUATION")
    print("=" * 70)

    print(
        f"Scenarios: "
        f"{len(UNFAMILIAR_SCENARIOS)}"
    )

    all_records = []

    methods = [

        (
            "No Defense",
            run_no_defense,
        ),

        (
            "RBAC/ABAC Only",
            run_rbac_abac,
        ),

        (
            "AgentVisor-style STI",
            run_agentvisor,
        ),

        (
            "Adaptive AI Firewall",
            run_adaptive_firewall,
        ),
    ]

    # ========================================================
    # RUN
    # ========================================================

    for scenario in UNFAMILIAR_SCENARIOS:

        print(
            f"\n[{scenario['id']}] "
            f"{scenario['name']}"
        )

        for method_name, runner in methods:

            try:

                records = runner(
                    scenario
                )

                all_records.extend(
                    records
                )

                final_records = [
                    record
                    for record in records
                    if not record[
                        "is_prelude"
                    ]
                ]

                final_executed = any(
                    record["executed"]
                    for record in final_records
                )

                final_actions = [
                    str(
                        record["action"]
                    )
                    for record in final_records
                ]

                print(
                    f"  "
                    f"{method_name:<25}"
                    f"final_executed="
                    f"{final_executed} "
                    f"action="
                    f"{','.join(final_actions)}"
                )

            except Exception as exc:

                print(
                    f"  "
                    f"{method_name:<25}"
                    f"ERROR: {exc}"
                )

    # ========================================================
    # AGGREGATE
    # ========================================================

    scenario_results = (
        aggregate_scenarios(
            all_records
        )
    )

    method_metrics = (
        calculate_method_metrics(
            scenario_results
        )
    )

    # ========================================================
    # SAVE CSV
    # ========================================================

    scenario_path = os.path.join(
        OUTPUT_DIR,
        "scenario_results.csv",
    )

    metrics_path = os.path.join(
        OUTPUT_DIR,
        "method_metrics.csv",
    )

    write_csv(
        scenario_path,
        scenario_results,
    )

    write_csv(
        metrics_path,
        method_metrics,
    )

    # ========================================================
    # PRINT RESULTS
    # ========================================================

    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)

    for metric in method_metrics:

        print(
            f"\n{metric['method']}"
        )

        print(
            "  Attack Prevention: "
            f"{metric['attack_prevention_rate'] * 100:.2f}%"
        )

        print(
            "  First-Exposure Prevention: "
            f"{metric['first_exposure_prevention_rate'] * 100:.2f}%"
        )

        print(
            "  Dangerous Execution: "
            f"{metric['dangerous_execution_rate'] * 100:.2f}%"
        )

        print(
            "  Legitimate Success: "
            f"{metric['legitimate_success_rate'] * 100:.2f}%"
        )

        print(
            "  False Positive: "
            f"{metric['false_positive_rate'] * 100:.2f}%"
        )

        print(
            "  Avg Scenario Latency: "
            f"{metric['avg_scenario_latency_ms']:.2f} ms"
        )

        print(
            "  Median Scenario Latency: "
            f"{metric['median_scenario_latency_ms']:.2f} ms"
        )

        print(
            "  Deep Inspection Rate: "
            f"{metric['deep_inspection_rate'] * 100:.2f}%"
        )

        print(
            "  Executed Requests: "
            f"{metric['executed_requests']}/"
            f"{metric['total_requests']}"
        )

    # ========================================================
    # FILE LOCATIONS
    # ========================================================

    print("\n" + "=" * 70)
    print("FILES")
    print("=" * 70)

    print(
        scenario_path
    )

    print(
        metrics_path
    )


if __name__ == "__main__":
    main()