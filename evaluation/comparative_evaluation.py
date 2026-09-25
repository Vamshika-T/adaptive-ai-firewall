"""
Controlled four-way comparative evaluation.

Methods:
    1. No Defense
    2. RBAC/ABAC Only
    3. AgentVisor-style STI Baseline
    4. Adaptive AI Firewall (proposed system)

Important:
- All methods use the SAME A1-A10 and L1-L6 scenarios.
- No Defense executes tool requests directly.
- RBAC/ABAC Only uses only the repository's RBAC + ABAC checks.
- AgentVisor-style is an independent deterministic approximation of
  the paper's STI audit boundary. It is NOT a reproduction of the
  original AgentVisor implementation or its LLM-based self-correction.
- Adaptive uses the existing FirewallInterceptor unchanged.
- Results are measured at runtime; no numbers are hard-coded.
"""

import csv
import statistics
import time
from pathlib import Path

from models.schemas import ToolRequest
from tools.registry import execute_tool
from firewall.authorization import check_rbac
from firewall.abac import check_abac
from firewall.interceptor import FirewallInterceptor

from evaluation.scenarios import (
    SECURITY_SCENARIOS,
    LEGITIMATE_SCENARIOS,
)


OUTPUT_DIR = Path(__file__).parent / "comparison_results"


# -----------------------------------------------------------------
# Common helpers
# -----------------------------------------------------------------


def make_request(scenario, session_id, request_number):
    return ToolRequest(
        request_id=(
            f"{session_id}-REQ{request_number:03d}"
        ),
        session_id=session_id,
        user_id=scenario["user_id"],
        tool=scenario["tool"],
        arguments=dict(scenario.get("arguments", {})),
        intent=scenario.get("intent", ""),
        context_sources=list(
            scenario.get("context_sources", [])
        ),
        tainted=scenario.get("tainted", False),
        source_type="comparison",
    )


def execute_direct(request):
    start = time.perf_counter()
    result = execute_tool(
        request.tool,
        request.arguments,
    )
    latency_ms = (
        time.perf_counter() - start
    ) * 1000
    return result, latency_ms


def base_record(
    method,
    scenario,
    action,
    executed,
    latency_ms,
    inspection="NONE",
    risk_score=0.0,
    reasons=None,
):
    return {
        "method": method,
        "scenario_id": scenario["id"],
        "scenario_name": scenario["name"],
        "type": (
            "attack"
            if scenario["id"].startswith("A")
            else "legitimate"
        ),
        "scenario_category": scenario["category"],
        "action": action,
        "risk_score": risk_score,
        "inspection_level": inspection,
        "executed": executed,
        "latency_ms": latency_ms,
        "reasons": reasons or [],
        "dangerous_execution": (
            scenario["id"].startswith("A")
            and executed
            and scenario["category"]
            not in {"gdos", "gdos_deep"}
        ),
    }


# -----------------------------------------------------------------
# 1. NO DEFENSE
# -----------------------------------------------------------------


def run_no_defense(scenario, session_id):
    """
    No security enforcement.
    Every proposed tool call is executed.
    """

    records = []
    request_number = 1

    for prelude in scenario.get("prelude", []):
        request = make_request(
            prelude,
            session_id,
            request_number,
        )
        execute_direct(request)
        request_number += 1

    repeat = scenario.get("repeat", 1)

    for _ in range(repeat):
        request = make_request(
            scenario,
            session_id,
            request_number,
        )

        result, latency_ms = execute_direct(request)

        records.append(
            base_record(
                "No Defense",
                scenario,
                "ALLOW",
                True,
                latency_ms,
                "NONE",
                0.0,
                [],
            )
        )

        request_number += 1

    return records


# -----------------------------------------------------------------
# 2. RBAC / ABAC ONLY
# -----------------------------------------------------------------


def rbac_abac_decision(request):
    """Only repository RBAC + ABAC. No trajectory, taint,
    semantic inspection, risk engine, or resource limits."""

    allowed, reason = check_rbac(
        request.user_id,
        request.tool,
        request.arguments,
    )

    if not allowed:
        return "BLOCK", reason

    allowed, reason = check_abac(
        request.user_id,
        request.tool,
        request.arguments,
    )

    if not allowed:
        return "BLOCK", reason

    return "ALLOW", reason


def run_rbac_abac(scenario, session_id):
    records = []
    request_number = 1

    for prelude in scenario.get("prelude", []):
        request = make_request(
            prelude,
            session_id,
            request_number,
        )
        action, _ = rbac_abac_decision(request)
        if action == "ALLOW":
            execute_direct(request)
        request_number += 1

    repeat = scenario.get("repeat", 1)

    for _ in range(repeat):
        request = make_request(
            scenario,
            session_id,
            request_number,
        )

        start = time.perf_counter()
        action, reason = rbac_abac_decision(request)

        if action == "ALLOW":
            result = execute_tool(
                request.tool,
                request.arguments,
            )
            executed = True
        else:
            result = None
            executed = False

        latency_ms = (
            time.perf_counter() - start
        ) * 1000

        records.append(
            base_record(
                "RBAC/ABAC Only",
                scenario,
                action,
                executed,
                latency_ms,
                "NONE",
                0.0,
                [reason],
            )
        )

        request_number += 1

    return records


# -----------------------------------------------------------------
# 3. AGENTVISOR-STYLE STI BASELINE
# -----------------------------------------------------------------

# This is deliberately independent from our firewall modules.
# It models the paper's trusted visor boundary:
#   S = Suitability
#   T = Taint / goal alignment
#   I = Integrity / argument consistency
#
# The visor does NOT inspect raw external context. It only sees:
#   - trusted task intent
#   - sanitized history
#   - proposed tool + arguments
#
# Because this deterministic project has no second LLM available for
# semantic auditing, a small rule-based approximation is used.

AGENTVISOR_ALLOWED_TOOLS = {
    "read_email_inbox",
    "send_email_message",
    "query_database",
    "search_employee",
    "search_customer",
    "get_calendar_events",
    "get_customer",
    "update_crm_record",
    "search_documents",
    "read_document",
}


AGENTVISOR_FORBIDDEN_GOAL_PATTERNS = (
    "ignore previous instructions",
    "ignore all previous instructions",
    "disregard previous instructions",
    "reveal secret",
    "reveal confidential",
    "reveal sensitive",
    "leak secret",
    "leak confidential",
    "leak sensitive",
)


def visor_suitability(request):
    if request.tool not in AGENTVISOR_ALLOWED_TOOLS:
        return False, "S: tool is outside the trusted agent policy"

    return True, "S: tool is permitted under the trusted tool policy"


def visor_taint(request, sanitized_history):
    """
    Taint check intentionally does NOT inspect request.tainted or
    request.context_sources. Those represent raw/untrusted context
    metadata and would violate the context-isolated visor model.
    """

    intent = (request.intent or "").lower()

    for pattern in AGENTVISOR_FORBIDDEN_GOAL_PATTERNS:
        if pattern in intent:
            return False, (
                "T: proposed action conflicts with the trusted task goal"
            )

    # External disclosure after sensitive database access is treated
    # as a new goal not supported by the sanitized task trajectory.
    previous_tools = [
        item["tool"]
        for item in sanitized_history
    ]

    recipient = str(
        request.arguments.get("recipient", "")
    ).lower()

    if (
        request.tool == "send_email_message"
        and "query_database" in previous_tools
        and recipient
        and not recipient.endswith("@company.com")
    ):
        return False, (
            "T: external disclosure is inconsistent with the trusted task state"
        )

    return True, "T: proposed goal is aligned with the trusted task state"


def visor_integrity(request, sanitized_history):
    """
    Deterministic argument-integrity checks.

    These checks only compare arguments with trusted task text/history;
    they do not perform enterprise RBAC/ABAC authorization.
    """

    intent = (request.intent or "").lower()

    if request.tool == "get_calendar_events":
        email = str(
            request.arguments.get("user_email", "")
        ).lower()

        # If the task explicitly names an email address, it must match.
        if "@" in intent and email not in intent:
            return False, (
                "I: calendar target is inconsistent with the user-specified entity"
            )

    if request.tool == "send_email_message":
        recipient = str(
            request.arguments.get("recipient", "")
        ).lower()

        # If the user names a recipient, require that recipient.
        if "@" in intent and recipient not in intent:
            return False, (
                "I: email recipient is inconsistent with the user-specified entity"
            )

    return True, "I: arguments are consistent with trusted task information"


def visor_audit(request, sanitized_history):
    """Return ALLOW or EXCEPTION plus STI reasons."""

    checks = [
        visor_suitability(request),
        visor_taint(request, sanitized_history),
        visor_integrity(request, sanitized_history),
    ]

    failed = [
        reason
        for passed, reason in checks
        if not passed
    ]

    if failed:
        return "EXCEPTION", failed

    return "ALLOW", [
        reason
        for _, reason in checks
    ]


def run_agentvisor_style(scenario, session_id):
    records = []
    request_number = 1
    sanitized_history = []

    for prelude in scenario.get("prelude", []):
        request = make_request(
            prelude,
            session_id,
            request_number,
        )

        start = time.perf_counter()
        action, reasons = visor_audit(
            request,
            sanitized_history,
        )

        if action == "ALLOW":
            execute_tool(
                request.tool,
                request.arguments,
            )

            sanitized_history.append({
                "tool": request.tool,
                "arguments": dict(request.arguments),
                "status": "executed",
            })

        else:
            sanitized_history.append({
                "tool": request.tool,
                "arguments": dict(request.arguments),
                "status": "exception",
            })

        request_number += 1

    repeat = scenario.get("repeat", 1)

    for _ in range(repeat):
        request = make_request(
            scenario,
            session_id,
            request_number,
        )

        start = time.perf_counter()
        action, reasons = visor_audit(
            request,
            sanitized_history,
        )

        if action == "ALLOW":
            execute_tool(
                request.tool,
                request.arguments,
            )
            executed = True

            sanitized_history.append({
                "tool": request.tool,
                "arguments": dict(request.arguments),
                "status": "executed",
            })
        else:
            executed = False

            sanitized_history.append({
                "tool": request.tool,
                "arguments": dict(request.arguments),
                "status": "exception",
            })

        latency_ms = (
            time.perf_counter() - start
        ) * 1000

        records.append(
            base_record(
                "AgentVisor-style STI",
                scenario,
                action,
                executed,
                latency_ms,
                "STI",
                0.0,
                reasons,
            )
        )

        request_number += 1

    return records


# -----------------------------------------------------------------
# 4. ADAPTIVE AI FIREWALL
# -----------------------------------------------------------------


def run_adaptive(scenario, session_id):
    firewall = FirewallInterceptor()
    records = []
    request_number = 1

    for prelude in scenario.get("prelude", []):
        request = make_request(
            prelude,
            session_id,
            request_number,
        )
        firewall.execute(request)
        request_number += 1

    repeat = scenario.get("repeat", 1)

    for _ in range(repeat):
        request = make_request(
            scenario,
            session_id,
            request_number,
        )

        start = time.perf_counter()
        decision, result = firewall.execute(request)
        latency_ms = (
            time.perf_counter() - start
        ) * 1000

        records.append(
            base_record(
                "Adaptive AI Firewall",
                scenario,
                decision.action,
                result is not None,
                latency_ms,
                decision.inspection_level,
                decision.risk_score,
                decision.reasons,
            )
        )

        request_number += 1

    return records


# -----------------------------------------------------------------
# Scenario aggregation
# -----------------------------------------------------------------


def aggregate_scenario(records):
    """Convert repeated requests into one scenario-level result."""

    first = records[0]
    scenario_id = first["scenario_id"]
    is_attack = first["type"] == "attack"

    executed_count = sum(
        item["executed"]
        for item in records
    )

    latencies = [
        item["latency_ms"]
        for item in records
    ]

    actions = [
        item["action"]
        for item in records
    ]

    dangerous = any(
        item["dangerous_execution"]
        for item in records
    )

    if is_attack:
        category = first.get("scenario_category", "")

        # GDoS scenarios are prevented only when the defense
        # actually stops the repeated workload. Merely running
        # a harmless tool repeatedly is not prevention.
        if category in {"gdos", "gdos_deep"}:
            prevented = executed_count < len(records)
        else:
            prevented = not dangerous

        success = False
    else:
        prevented = False
        success = all(
            item["executed"]
            for item in records
        )

    return {
        "method": first["method"],
        "scenario_id": scenario_id,
        "scenario_name": first["scenario_name"],
        "scenario_category": first["scenario_category"],
        "type": first["type"],
        "action": actions[-1],
        "executed": executed_count > 0,
        "executed_count": executed_count,
        "dangerous_execution": dangerous,
        "scenario_prevented": prevented,
        "success": success,
        "risk_score": round(
            statistics.mean(
                item["risk_score"]
                for item in records
            ),
            2,
        ),
        "inspection_level": first["inspection_level"],
        "latency_ms_avg": round(
            statistics.mean(latencies),
            4,
        ),
        "latency_ms_median": round(
            statistics.median(latencies),
            4,
        ),
        "request_count": len(records),
        "reasons": first["reasons"],
    }


def run_method(method_name, scenarios, runner):
    all_records = []

    for scenario in scenarios:
        session_id = (
            f"CMP-{method_name[:3].upper()}-"
            f"{scenario['id']}"
        )

        request_records = runner(
            scenario,
            session_id,
        )

        all_records.append(
            aggregate_scenario(request_records)
        )

    return all_records


# -----------------------------------------------------------------
# Metrics
# -----------------------------------------------------------------


def method_metrics(records):
    attacks = [
        r for r in records
        if r["type"] == "attack"
    ]

    legitimate = [
        r for r in records
        if r["type"] == "legitimate"
    ]

    prevented = [
        r for r in attacks
        if r["scenario_prevented"]
    ]

    dangerous = [
        r for r in attacks
        if r["dangerous_execution"]
    ]

    false_positives = [
        r for r in legitimate
        if not r["success"]
    ]

    gdos = [
        r for r in attacks
        if r["scenario_category"] in {"gdos", "gdos_deep"}
    ]

    gdos_prevented = [
        r for r in gdos
        if r["scenario_prevented"]
    ]

    latencies = [
        r["latency_ms_avg"]
        for r in records
    ]

    executed_requests = sum(
        r["executed_count"]
        for r in records
    )

    total_requests = sum(
        r["request_count"]
        for r in records
    )

    deep_count = sum(
        r["inspection_level"] == "DEEP"
        for r in records
    )

    return {
        "method": records[0]["method"],
        "attack_prevention_rate": round(
            100 * len(prevented) / len(attacks),
            2,
        ) if attacks else 0.0,
        "dangerous_execution_rate": round(
            100 * len(dangerous) / len(attacks),
            2,
        ) if attacks else 0.0,
        "gdos_prevention_rate": round(
            100 * len(gdos_prevented) / len(gdos),
            2,
        ) if gdos else 0.0,
        "legitimate_success_rate": round(
            100 * sum(r["success"] for r in legitimate)
            / len(legitimate),
            2,
        ) if legitimate else 0.0,
        "false_positive_rate": round(
            100 * len(false_positives) / len(legitimate),
            2,
        ) if legitimate else 0.0,
        "avg_latency_ms": round(
            statistics.mean(latencies),
            4,
        ) if latencies else 0.0,
        "median_scenario_latency_ms": round(
            statistics.median(latencies),
            4,
        ) if latencies else 0.0,
        "executed_requests": executed_requests,
        "total_requests": total_requests,
        "deep_inspection_rate": round(
            100 * deep_count / len(records),
            2,
        ) if records else 0.0,
    }


# -----------------------------------------------------------------
# Output
# -----------------------------------------------------------------


def print_results(scenario_records, metrics):
    print("\n" + "=" * 120)
    print("FOUR-WAY CONTROLLED SECURITY COMPARISON")
    print("=" * 120)

    print(
        f"{'METHOD':<25}"
        f"{'ATTACK PREV.':<15}"
        f"{'LEGIT SUCCESS':<15}"
        f"{'FALSE POS.':<13}"
        f"{'DANGEROUS':<13}"
        f"{'GDoS PREV.':<13}"
        f"{'AVG LATENCY':<15}"
        f"{'MEDIAN LATENCY':<16}"
    )
    print("-" * 120)

    for item in metrics:
        print(
            f"{item['method']:<25}"
            f"{item['attack_prevention_rate']:<15}"
            f"{item['legitimate_success_rate']:<15}"
            f"{item['false_positive_rate']:<13}"
            f"{item['dangerous_execution_rate']:<13}"
            f"{item['gdos_prevention_rate']:<13}"
            f"{item['avg_latency_ms']:<15}"
            f"{item['median_scenario_latency_ms']:<16}"
        )

    print("\n" + "=" * 120)
    print("SCENARIO-LEVEL RESULTS")
    print("=" * 120)

    print(
        f"{'METHOD':<25}"
        f"{'ID':<7}"
        f"{'ACTION':<12}"
        f"{'EXEC':<8}"
        f"{'DANGER':<9}"
        f"{'LATENCY ms':<14}"
    )
    print("-" * 120)

    for record in scenario_records:
        print(
            f"{record['method']:<25}"
            f"{record['scenario_id']:<7}"
            f"{record['action']:<12}"
            f"{record['executed_count']:<8}"
            f"{str(record['dangerous_execution']):<9}"
            f"{record['latency_ms_avg']:<14}"
        )


def save_csv(records, filename):
    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    path = OUTPUT_DIR / filename

    fields = [
        "method",
        "scenario_id",
        "scenario_name",
        "type",
        "action",
        "executed",
        "executed_count",
        "dangerous_execution",
        "scenario_prevented",
        "success",
        "risk_score",
        "inspection_level",
        "latency_ms_avg",
        "latency_ms_median",
        "request_count",
    ]

    with open(
        path,
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fields,
        )
        writer.writeheader()

        for record in records:
            writer.writerow({
                field: record.get(field, "")
                for field in fields
            })

    return path


def save_metrics_csv(metrics):
    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    path = OUTPUT_DIR / "method_metrics.csv"

    fields = list(metrics[0].keys())

    with open(
        path,
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fields,
        )
        writer.writeheader()
        writer.writerows(metrics)

    return path


def main():
    scenarios = (
        SECURITY_SCENARIOS
        + LEGITIMATE_SCENARIOS
    )

    method_runners = [
        ("No Defense", run_no_defense),
        ("RBAC/ABAC Only", run_rbac_abac),
        ("AgentVisor-style STI", run_agentvisor_style),
        ("Adaptive AI Firewall", run_adaptive),
    ]

    all_scenario_records = []
    all_metrics = []

    for method_name, runner in method_runners:
        records = run_method(
            method_name,
            scenarios,
            runner,
        )

        all_scenario_records.extend(records)
        all_metrics.append(
            method_metrics(records)
        )

    print_results(
        all_scenario_records,
        all_metrics,
    )

    save_csv(
        all_scenario_records,
        "scenario_results.csv",
    )

    save_metrics_csv(
        all_metrics,
    )

    print("\nSaved:")
    print(
        OUTPUT_DIR / "scenario_results.csv"
    )
    print(
        OUTPUT_DIR / "method_metrics.csv"
    )


if __name__ == "__main__":
    main()
