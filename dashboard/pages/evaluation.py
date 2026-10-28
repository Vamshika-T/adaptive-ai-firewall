
import csv
from pathlib import Path

import streamlit as st

from evaluation.final_evaluation import (
    run_legitimate_scenarios,
    run_security_scenarios,
)

from evaluation.security_metrics import calculate_metrics


st.title("Security Evaluation")

st.caption(
    "Evaluate the Adaptive AI Firewall using the existing "
    "scenario suite and saved controlled-comparison results."
)

st.warning(
    "The Frozen Phase 3 Evaluation and Four-Way Controlled "
    "Comparison are separate experiments. Their results "
    "should not be combined."
)


def optional_number(row, key, converter=float):
    """Return a recorded numeric value or a clear missing-value label."""
    value = (row.get(key) or "").strip()

    if not value:
        return "Not recorded"

    try:
        return converter(value)
    except (TypeError, ValueError):
        return "Invalid value"


# EXISTING PHASE 3 EVALUATION

st.header("Frozen Phase 3 Evaluation")

st.caption(
    "Runs A1-A10 and L1-L6 against the current firewall "
    "and calculates metrics from those executions."
)

if st.button(
    "Run Frozen Phase 3 Evaluation",
    type="primary",
    use_container_width=True,
):
    with st.spinner("Running A1-A10 and L1-L6..."):
        security_records = run_security_scenarios()
        legitimate_records = run_legitimate_scenarios()

        records = security_records + legitimate_records
        metrics = calculate_metrics(records)

        st.session_state.dashboard_evaluation_records = records
        st.session_state.dashboard_evaluation_metrics = metrics


metrics = st.session_state.get("dashboard_evaluation_metrics")
records = st.session_state.get("dashboard_evaluation_records", [])

if metrics is None:
    st.info("Run the Frozen Phase 3 Evaluation to display its results.")
else:
    st.subheader("Measured Security Metrics")

    row1 = st.columns(4)

    row1[0].metric(
        "Attack Prevention",
        f"{metrics['attack_prevention_rate']}%",
    )
    row1[1].metric(
        "Legitimate Success",
        f"{metrics['legitimate_success_rate']}%",
    )
    row1[2].metric(
        "False Positives",
        f"{metrics['false_positive_rate']}%",
    )
    row1[3].metric(
        "Dangerous Executions",
        metrics["dangerous_executions"],
    )

    row2 = st.columns(4)

    row2[0].metric("Blocks", metrics["firewall_blocks"])
    row2[1].metric("Escalations", metrics["firewall_escalations"])
    row2[2].metric(
        "Deep Inspection",
        f"{metrics['deep_inspection_rate']}%",
    )
    row2[3].metric("Average Risk", metrics["average_risk"])

    row3 = st.columns(3)

    row3[0].metric(
        "Trajectory Detections",
        metrics["trajectory_detections"],
    )
    row3[1].metric(
        "Taint Detections",
        metrics["taint_detections"],
    )
    row3[2].metric(
        "Resource Limit Blocks",
        metrics["resource_limit_blocks"],
    )

    st.subheader("Scenario Results")

    scenario_table = []

    for record in records:
        scenario_table.append(
            {
                "ID": record["scenario_id"],
                "Name": record["scenario_name"],
                "Type": record["type"],
                "Action": record["action"],
                "Risk": record["risk_score"],
                "Inspection": record["inspection_level"],
                "Tool Executed": record["tool_executed"],
            }
        )

    st.dataframe(
        scenario_table,
        use_container_width=True,
        hide_index=True,
    )

    st.caption(
        "These metrics describe the recorded executions in this "
        "experiment. They are not universal security guarantees."
    )


# FOUR-WAY CONTROLLED COMPARISON

st.divider()
st.header("Four-Way Controlled Comparison")

st.caption(
    "Displays the saved results from the comparative evaluation. "
    "This section does not rerun the comparison."
)

comparison_dir = (
    Path(__file__).resolve().parents[2]
    / "evaluation"
    / "comparison_results"
)

metrics_path = comparison_dir / "method_metrics.csv"
scenario_path = comparison_dir / "scenario_results.csv"

if not metrics_path.exists() or not scenario_path.exists():
    st.info(
        "Controlled-comparison files were not found. Expected both "
        "method_metrics.csv and scenario_results.csv in "
        "evaluation/comparison_results."
    )
else:
    with metrics_path.open(
        "r",
        newline="",
        encoding="utf-8-sig",
    ) as file:
        method_metrics = list(csv.DictReader(file))

    with scenario_path.open(
        "r",
        newline="",
        encoding="utf-8-sig",
    ) as file:
        scenario_results = list(csv.DictReader(file))

    if not method_metrics or not scenario_results:
        st.warning(
            "One or both controlled-comparison CSV files contain "
            "no data rows."
        )
    else:
        st.subheader("Security and Utility Comparison")

        comparison_table = []

        for row in method_metrics:
            comparison_table.append(
                {
                    "Method": row.get("method", "Unknown"),
                    "Attack Prevention (%)": optional_number(
                        row, "attack_prevention_rate"
                    ),
                    "Dangerous Execution (%)": optional_number(
                        row, "dangerous_execution_rate"
                    ),
                    "GDoS Prevention (%)": optional_number(
                        row, "gdos_prevention_rate"
                    ),
                    "GDoS Request Rejection (%)": optional_number(
                        row, "gdos_request_rejection_rate"
                    ),
                    "GDoS Request Execution (%)": optional_number(
                        row, "gdos_request_execution_rate"
                    ),
                    "Legitimate Success (%)": optional_number(
                        row, "legitimate_success_rate"
                    ),
                    "False Positive (%)": optional_number(
                        row, "false_positive_rate"
                    ),
                    "Deep Inspection (%)": optional_number(
                        row, "deep_inspection_rate"
                    ),
                    "Semantic Audit Attempts": optional_number(
                        row, "semantic_audit_attempts", int
                    ),
                    "Semantic Audit Failures": optional_number(
                        row, "semantic_audit_failures", int
                    ),
                    "Audit Failure Rate (%)": optional_number(
                        row, "semantic_audit_failure_rate"
                    ),
                }
            )

        st.dataframe(
            comparison_table,
            use_container_width=True,
            hide_index=True,
        )

        st.caption(
            "GDoS scenario prevention and request-level rejection "
            "are different measurements. Request-level rates describe "
            "the individual requests recorded by the evaluation."
        )

        # LATENCY COMPARISON

        st.subheader("Latency Comparison")

        latency_table = []

        for row in method_metrics:
            latency_table.append(
                {
                    "Method": row.get("method", "Unknown"),
                    "Average Scenario Latency (ms)": optional_number(
                        row, "avg_scenario_latency_ms"
                    ),
                    "Median Scenario Latency (ms)": optional_number(
                        row, "median_scenario_latency_ms"
                    ),
                    "P95 Scenario Latency (ms)": optional_number(
                        row, "p95_scenario_latency_ms"
                    ),
                    "Average Request Latency (ms)": optional_number(
                        row, "avg_request_latency_ms"
                    ),
                    "Median Request Latency (ms)": optional_number(
                        row, "median_request_latency_ms"
                    ),
                    "P95 Request Latency (ms)": optional_number(
                        row, "p95_request_latency_ms"
                    ),
                    "Executed Requests": optional_number(
                        row, "executed_requests", int
                    ),
                    "Total Requests": optional_number(
                        row, "total_requests", int
                    ),
                    "Total Semantic Audit Latency (ms)": (
                        optional_number(
                            row, "semantic_audit_latency_ms_total"
                        )
                    ),
                    "Average Audit Latency per Attempt (ms)": (
                        optional_number(
                            row,
                            "avg_semantic_audit_latency_ms_per_attempt",
                        )
                    ),
                }
            )

        st.dataframe(
            latency_table,
            use_container_width=True,
            hide_index=True,
        )

        st.caption(
            "Scenario latency aggregates a complete scenario; request "
            "latency measures individual requests. Semantic-auditor "
            "latency is the time attributed to semantic auditing and "
            "is distinct from total scenario and request latency. "
            "'Not recorded' means the CSV does not contain a usable "
            "value; it does not mean the measurement was zero."
        )

        # SCENARIO-LEVEL COMPARISON

        st.subheader("Scenario-Level Comparison")

        scenario_table = []

        for row in scenario_results:
            scenario_table.append(
                {
                    "Method": row.get("method", "Unknown"),
                    "Scenario": row.get("scenario_id", ""),
                    "Scenario Name": row.get("scenario_name", ""),
                    "Type": row.get("type", ""),
                    "Action": row.get("action", ""),
                    "Executed": row.get("executed", ""),
                    "Executed Count": optional_number(
                        row, "executed_count", int
                    ),
                    "Dangerous": row.get("dangerous_execution", ""),
                    "Prevented": row.get("scenario_prevented", ""),
                    "Success": row.get("success", ""),
                    "Risk": optional_number(row, "risk_score"),
                    "Inspection": row.get("inspection_level", ""),
                    "Average Request Latency (ms)": optional_number(
                        row, "latency_ms_avg"
                    ),
                }
            )

        st.dataframe(
            scenario_table,
            use_container_width=True,
            hide_index=True,
        )

        # METHOD DEFINITIONS

        st.subheader("Method Definitions")

        st.write(
            "**No Defense:** Tool requests are executed directly "
            "without security enforcement."
        )

        st.write(
            "**RBAC/ABAC Only:** Uses the repository's role-based "
            "and attribute-based authorization checks. It excludes "
            "trajectory analysis, taint tracking, semantic inspection, "
            "risk scoring, and resource limits in this comparison."
        )

        st.write(
            "**AgentVisor-style STI:** A controlled deterministic "
            "approximation of the Suitability, Taint, and Integrity "
            "auditing concept. It is not a reproduction of the original "
            "AgentVisor implementation or its LLM-based self-correction."
        )

        st.write(
            "**Adaptive AI Firewall:** Uses the actual "
            "FirewallInterceptor from the current repository."
        )

        st.subheader("Experimental Interpretation")

        st.write(
            "The controlled comparison uses the A1-A10 attack scenarios "
            "and L1-L6 legitimate scenarios across the four methods. "
            "Interpret results within the tested scenario set. The "
            "measured outcomes do not establish universal security "
            "guarantees or prove detection of all possible attacks."
        )
