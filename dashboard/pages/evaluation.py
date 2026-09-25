
import csv
from pathlib import Path

import streamlit as st

from evaluation.final_evaluation import (
    run_legitimate_scenarios,
    run_security_scenarios,
)

from evaluation.security_metrics import (
    calculate_metrics
)


st.title("Security Evaluation")

st.caption(
    "Run the existing deterministic evaluation against "
    "the real Adaptive AI Firewall."
)


st.warning(
    "This page executes the existing A1-A10 and L1-L6 "
    "evaluation. It does not fabricate metrics."
)


# -----------------------------------------------------------------
# EXISTING PHASE 3 EVALUATION
# -----------------------------------------------------------------

if st.button(
    "Run Frozen Phase 3 Evaluation",
    type="primary",
    use_container_width=True
):

    with st.spinner(
        "Running A1-A10 and L1-L6..."
    ):

        security_records = (
            run_security_scenarios()
        )

        legitimate_records = (
            run_legitimate_scenarios()
        )

        records = (
            security_records
            + legitimate_records
        )

        metrics = calculate_metrics(
            records
        )

        st.session_state.dashboard_evaluation_records = (
            records
        )

        st.session_state.dashboard_evaluation_metrics = (
            metrics
        )


metrics = st.session_state.get(
    "dashboard_evaluation_metrics"
)

records = st.session_state.get(
    "dashboard_evaluation_records",
    []
)


if metrics is None:

    st.info(
        "Click the button above to run the actual evaluation."
    )

else:

    st.markdown(
        "### Measured Security Metrics"
    )


    row1 = st.columns(4)

    row1[0].metric(
        "Attack Prevention",
        f"{metrics['attack_prevention_rate']}%"
    )

    row1[1].metric(
        "Legitimate Success",
        f"{metrics['legitimate_success_rate']}%"
    )

    row1[2].metric(
        "False Positives",
        f"{metrics['false_positive_rate']}%"
    )

    row1[3].metric(
        "Dangerous Executions",
        metrics["dangerous_executions"]
    )


    row2 = st.columns(4)

    row2[0].metric(
        "Blocks",
        metrics["firewall_blocks"]
    )

    row2[1].metric(
        "Escalations",
        metrics["firewall_escalations"]
    )

    row2[2].metric(
        "Deep Inspection",
        f"{metrics['deep_inspection_rate']}%"
    )

    row2[3].metric(
        "Average Risk",
        metrics["average_risk"]
    )


    row3 = st.columns(3)

    row3[0].metric(
        "Trajectory Detections",
        metrics["trajectory_detections"]
    )

    row3[1].metric(
        "Taint Detections",
        metrics["taint_detections"]
    )

    row3[2].metric(
        "Resource Limit Blocks",
        metrics["resource_limit_blocks"]
    )


    st.markdown(
        "### Scenario Results"
    )


    table = []

    for record in records:

        table.append(
            {
                "ID":
                    record["scenario_id"],

                "Type":
                    record["type"],

                "Action":
                    record["action"],

                "Risk":
                    record["risk_score"],

                "Inspection":
                    record["inspection_level"],

                "Executed":
                    record["tool_executed"],

                "Name":
                    record["scenario_name"],
            }
        )


    st.dataframe(
        table,
        use_container_width=True,
        hide_index=True
    )


    st.markdown(
        "### Interpretation"
    )

    st.write(
        "These values come from actual executions of "
        "the current repository. They are measured "
        "results for this experiment, not universal "
        "security guarantees."
    )


# -----------------------------------------------------------------
# FOUR-WAY CONTROLLED COMPARISON
# -----------------------------------------------------------------

st.divider()

st.header("Four-Way Controlled Comparison")

st.caption(
    "Results are loaded from the latest controlled "
    "comparative evaluation CSV files."
)


comparison_dir = (
    Path(__file__).resolve().parents[2]
    / "evaluation"
    / "comparison_results"
)

metrics_path = (
    comparison_dir
    / "method_metrics.csv"
)

scenario_path = (
    comparison_dir
    / "scenario_results.csv"
)


if not metrics_path.exists() or not scenario_path.exists():

    st.info(
        "Run the controlled comparison first. "
        "Expected files: method_metrics.csv and "
        "scenario_results.csv."
    )

else:

    # -------------------------------------------------------------
    # Load method metrics
    # -------------------------------------------------------------

    with metrics_path.open(
        "r",
        newline="",
        encoding="utf-8"
    ) as file:

        reader = csv.DictReader(file)

        method_metrics = list(reader)


    # -------------------------------------------------------------
    # Load scenario results
    # -------------------------------------------------------------

    with scenario_path.open(
        "r",
        newline="",
        encoding="utf-8"
    ) as file:

        reader = csv.DictReader(file)

        scenario_results = list(reader)


    # -------------------------------------------------------------
    # Main comparison table
    # -------------------------------------------------------------

    st.markdown(
        "#### Security and Utility Comparison"
    )

    comparison_table = []

    for row in method_metrics:

        comparison_table.append(
            {
                "Method":
                    row["method"],

                "Attack Prevention (%)":
                    float(
                        row["attack_prevention_rate"]
                    ),

                "Dangerous Execution (%)":
                    float(
                        row["dangerous_execution_rate"]
                    ),

                "GDoS Prevention (%)":
                    float(
                        row["gdos_prevention_rate"]
                    ),

                "Legitimate Success (%)":
                    float(
                        row["legitimate_success_rate"]
                    ),

                "False Positive (%)":
                    float(
                        row["false_positive_rate"]
                    ),

                "Deep Inspection (%)":
                    float(
                        row["deep_inspection_rate"]
                    ),
            }
        )


    st.dataframe(
        comparison_table,
        use_container_width=True,
        hide_index=True
    )


    # -------------------------------------------------------------
    # Latency comparison
    # -------------------------------------------------------------

    st.markdown(
        "#### Latency Comparison"
    )

    latency_table = []

    for row in method_metrics:

        latency_table.append(
            {
                "Method":
                    row["method"],

                "Average Scenario Latency (ms)":
                    float(
                        row["avg_latency_ms"]
                    ),

                "Median Scenario Latency (ms)":
                    float(
                        row["median_scenario_latency_ms"]
                    ),

                "Executed Requests":
                    int(
                        row["executed_requests"]
                    ),

                "Total Requests":
                    int(
                        row["total_requests"]
                    ),
            }
        )


    st.dataframe(
        latency_table,
        use_container_width=True,
        hide_index=True
    )


    # -------------------------------------------------------------
    # Scenario-level comparison
    # -------------------------------------------------------------

    st.markdown(
        "#### Scenario-Level Comparison"
    )

    scenario_table = []

    for row in scenario_results:

        scenario_table.append(
            {
                "Method":
                    row["method"],

                "Scenario":
                    row["scenario_id"],

                "Scenario Name":
                    row["scenario_name"],

                "Type":
                    row["type"],

                "Action":
                    row["action"],

                "Executed":
                    row["executed"],

                "Executed Count":
                    int(
                        row["executed_count"]
                    ),

                "Dangerous":
                    row["dangerous_execution"],

                "Prevented":
                    row["scenario_prevented"],

                "Success":
                    row["success"],

                "Risk":
                    float(
                        row["risk_score"]
                    ),

                "Inspection":
                    row["inspection_level"],

                "Latency (ms)":
                    float(
                        row["latency_ms_avg"]
                    ),
            }
        )


    st.dataframe(
        scenario_table,
        use_container_width=True,
        hide_index=True
    )


    # -------------------------------------------------------------
    # Method notes
    # -------------------------------------------------------------

    st.markdown(
        "#### Method Definitions"
    )

    st.write(
        "No Defense: tool requests are executed directly "
        "without security enforcement."
    )

    st.write(
        "RBAC/ABAC Only: uses only the repository's "
        "authorization checks. It does not use trajectory, "
        "taint, semantic inspection, risk scoring, or "
        "resource limits."
    )

    st.write(
        "AgentVisor-style STI: controlled deterministic "
        "approximation of the AgentVisor Suitability, "
        "Taint, and Integrity auditing concept. It is "
        "not a reproduction of the original AgentVisor "
        "implementation or its LLM-based self-correction."
    )

    st.write(
        "Adaptive AI Firewall: uses the actual "
        "FirewallInterceptor from the current repository."
    )


    st.markdown(
        "#### Experimental Interpretation"
    )

    st.write(
        "The comparison uses the same A1-A10 attack "
        "scenarios and L1-L6 legitimate scenarios for "
        "all four methods. Results are measured locally "
        "at runtime and should be interpreted as results "
        "from this controlled experiment, not as universal "
        "security guarantees."
    )