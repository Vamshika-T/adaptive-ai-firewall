import streamlit as st


st.title("🏗️ Architecture & Explainability")

st.caption(
    "How a request moves from the user through the LLM agent, "
    "Adaptive AI Firewall, and enterprise tools."
)


# ============================================================
# RUNTIME ARCHITECTURE
# ============================================================

st.markdown("### Runtime Architecture")

architecture = r"""
digraph G {

    graph [
        rankdir=LR,
        bgcolor="transparent",
        nodesep=0.30,
        ranksep=0.45,
        margin=0.05,
        pad=0.05
    ];

    node [
        shape=box,
        style="rounded,filled",
        fontname="Arial",
        fontsize=11,
        color="#2a3542",
        fillcolor="#111820",
        fontcolor="#f5f7fa",
        margin="0.18,0.10"
    ];

    edge [
        color="#718096",
        arrowsize=0.65,
        penwidth=1.2
    ];


    user [
        label="USER"
    ];

    agent [
        label="LLM AGENT\nGEMINI"
    ];

    request [
        label="ToolRequest"
    ];

    firewall [
        label="ADAPTIVE AI FIREWALL\n\nIdentity • RBAC / ABAC\nProvenance / Taint\nContext / Intent\nTrajectory\nSemantic / STI\nRisk Engine\nResource / GDoS"
    ];

    routing [
        label="ADAPTIVE INSPECTION\nFAST / CONTEXTUAL / DEEP"
    ];

    decision [
        label="ENFORCEMENT\nALLOW / MONITOR\nESCALATE / BLOCK"
    ];

    registry [
        label="TOOL REGISTRY"
    ];

    tools [
        label="ENTERPRISE TOOLS"
    ];

    data [
        label="ENTERPRISE DATA"
    ];


    user -> agent;
    agent -> request;
    request -> firewall;
    firewall -> routing;
    routing -> decision;

    decision -> registry [
        label="permitted",
        fontcolor="#9da9b5",
        fontsize=9
    ];

    registry -> tools;
    tools -> data;
}
"""


st.graphviz_chart(
    architecture,
    width="stretch",
    height=430,
)


# ============================================================
# REQUEST LIFECYCLE
# ============================================================

st.markdown("### Request Lifecycle")

lifecycle_col1, lifecycle_col2 = st.columns(2)

with lifecycle_col1:

    st.markdown(
        """
        **1. User Request**

        The user gives a natural-language request to the
        enterprise AI agent.

        **2. LLM Agent**

        Gemini interprets the request and may generate a
        function/tool call.

        **3. ToolRequest**

        The function call is converted into the common
        `ToolRequest` security schema.

        **4. Firewall**

        The request enters the Adaptive AI Firewall before
        any enterprise tool is executed.
        """
    )


with lifecycle_col2:

    st.markdown(
        """
        **5. Security Inspection**

        Identity, authorization, provenance, taint,
        context, trajectory, semantic/STI, risk,
        and resource controls are evaluated.

        **6. Adaptive Routing**

        The firewall chooses FAST, CONTEXTUAL, or DEEP
        inspection according to the observed risk.

        **7. Enforcement**

        The final action is ALLOW, MONITOR, ESCALATE,
        or BLOCK.

        **8. Tool Execution**

        Enterprise tools execute only when the firewall
        permits execution.
        """
    )


# ============================================================
# SECURITY PIPELINE
# ============================================================

st.markdown("### Security Pipeline")

pipeline = [
    (
        "1. Identity",
        "Identify the enterprise user and session."
    ),
    (
        "2. RBAC / ABAC",
        "Check role permissions and contextual authorization."
    ),
    (
        "3. Provenance / Taint",
        "Track whether the request is influenced by untrusted context."
    ),
    (
        "4. Context / Intent",
        "Analyze what the request is attempting to accomplish."
    ),
    (
        "5. Trajectory",
        "Consider previous actions in the current session."
    ),
    (
        "6. Semantic / STI",
        "Perform deeper semantic inspection when required."
    ),
    (
        "7. Adaptive Routing",
        "Choose FAST, CONTEXTUAL, or DEEP inspection."
    ),
    (
        "8. Risk / Enforcement",
        "Aggregate signals and produce the security decision."
    ),
    (
        "9. Resource / GDoS",
        "Enforce request and deep-inspection budgets."
    ),
]


for title, description in pipeline:

    with st.expander(title):

        st.write(description)


# ============================================================
# ENFORCEMENT ACTIONS
# ============================================================

st.markdown("### Enforcement Actions")

action_col1, action_col2, action_col3, action_col4 = st.columns(4)

with action_col1:

    st.success(
        "**ALLOW**\n\n"
        "Authorized request proceeds to the enterprise tool."
    )

with action_col2:

    st.info(
        "**MONITOR**\n\n"
        "Request proceeds while security monitoring records it."
    )

with action_col3:

    st.warning(
        "**ESCALATE**\n\n"
        "Request requires additional scrutiny or human approval."
    )

with action_col4:

    st.error(
        "**BLOCK**\n\n"
        "Request is stopped before dangerous execution."
    )


# ============================================================
# DESIGN PRINCIPLE
# ============================================================

st.markdown("### Design Principle")

st.info(
    "The dashboard is only a visualization and interaction layer. "
    "It does not make security decisions. The FirewallInterceptor "
    "remains the single enforcement authority."
)