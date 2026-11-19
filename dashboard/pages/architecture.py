import streamlit as st

st.title("Architecture & Explainability")

st.caption(
    "Internal workflow of the Adaptive Context-Aware AI Firewall, "
    "from request interception to final security enforcement."
)

# --------------------------------------------------
# RUNTIME ARCHITECTURE
# --------------------------------------------------

st.markdown("### Runtime Architecture")

architecture = r"""
digraph G {

    graph [
        rankdir=TB,
        bgcolor="transparent",
        fontname="Arial",
        fontsize=12,
        nodesep=0.30,
        ranksep=0.38,
        pad=0.25,
        compound=true,
        splines=ortho
    ];

    node [
        shape=box,
        style="rounded,filled",
        fontname="Arial",
        fontsize=10,
        color="#526477",
        fillcolor="#172536",
        fontcolor="white",
        penwidth=1.2,
        margin="0.16,0.10"
    ];

    edge [
        color="#8293A7",
        fontname="Arial",
        fontsize=9,
        fontcolor="#AAB7C4",
        arrowsize=0.7,
        penwidth=1.2
    ];

    user [
        label="USER TASK\n(TRUSTED)",
        fillcolor="#174C70"
    ];

    agent [
        label="LLM AGENT\n(UNTRUSTED)\n\nReads emails, documents and web content",
        fillcolor="#35445B"
    ];

    subgraph cluster_firewall {

        label="ADAPTIVE CONTEXT-AWARE AI FIREWALL";
        color="#4C83B5";
        fontcolor="#8CBCE8";
        fontsize=13;
        style="rounded,dashed";
        penwidth=2;
        margin=18;

        identity [
            label="1–2  Identity Check and\nRequest Budget (50 per session)"
        ];

        provenance [
            label="3  Provenance and Taint Tracking"
        ];

        authorization [
            label="4  RBAC Check, then ABAC Check"
        ];

        sensitivity [
            label="5  Resource Sensitivity Score"
        ];

        router [
            label="6  INSPECTION ROUTER\nFAST / CONTEXTUAL / DEEP",
            fillcolor="#174C70",
            color="#6AADE0",
            penwidth=1.8
        ];

        intent [
            label="Intent\nAnalysis"
        ];

        trajectory [
            label="Trajectory\nAnalysis"
        ];

        semantic [
            label="Semantic\nScoring"
        ];

        risk [
            label="8  RISK AGGREGATION\nR = 0.30 S + 25 I + 0.75 T",
            fillcolor="#654B20",
            color="#D6A84D"
        ];

        audit [
            label="9a  LLM SEMANTIC AUDIT\n(DEEP and flagged CONTEXTUAL)",
            fillcolor="#49385F"
        ];

        information [
            label="9b  INFORMATION-FLOW\nAND LINEAGE CHECKS",
            fillcolor="#254D46"
        ];

        identity -> provenance -> authorization -> sensitivity -> router;

        router -> intent [
            label="CONTEXTUAL / DEEP"
        ];

        router -> trajectory;
        router -> semantic;

        intent -> risk;
        trajectory -> risk;
        semantic -> risk;

        router -> risk [
            label="FAST PATH",
            constraint=false,
            style=dashed
        ];

        risk -> audit -> information;
    }

    subgraph cluster_stores {

        label="STORES & EXTERNAL SERVICES";
        color="#63758A";
        fontcolor="#AAB7C4";
        style="rounded,dashed";

        registry [
            label="Provenance\nRegistry",
            fillcolor="#26394D"
        ];

        policies [
            label="Role and\nAttribute Policies",
            fillcolor="#26394D"
        ];

        classification [
            label="Resource\nClassification",
            fillcolor="#26394D"
        ];

        history [
            label="Session\nHistory",
            fillcolor="#26394D"
        ];

        gemini [
            label="Gemini Auditor\n(Task Context Only)",
            fillcolor="#49385F"
        ];

        artifact [
            label="Artifact Store\n(Lineage)",
            fillcolor="#254D46"
        ];

        registry -> policies -> classification -> history -> gemini -> artifact [
            style=invis
        ];
    }

    user -> identity [
        label="Trusted task"
    ];

    user -> agent [
        label="Task",
        constraint=false
    ];

    agent -> sensitivity [
        label="Tool call"
    ];

    provenance -> registry [
        style=dotted,
        dir=both,
        constraint=false
    ];

    authorization -> policies [
        style=dotted,
        dir=both,
        constraint=false
    ];

    sensitivity -> classification [
        style=dotted,
        dir=both,
        constraint=false
    ];

    trajectory -> history [
        style=dotted,
        dir=both,
        constraint=false
    ];

    audit -> gemini [
        style=dotted,
        dir=both,
        constraint=false
    ];

    information -> artifact [
        style=dotted,
        dir=both,
        constraint=false
    ];

    allow [
        label="ALLOW\n\nRun on enterprise tools",
        fillcolor="#155D3B",
        color="#35B879"
    ];

    monitor [
        label="MONITOR\n\nLogged, flagged and held",
        fillcolor="#79551D",
        color="#D6A84D"
    ];

    escalate [
        label="ESCALATE\n\nHuman review queue",
        fillcolor="#71441C",
        color="#E5A35A"
    ];

    block [
        label="BLOCK\n\nRejected, reasons returned",
        fillcolor="#762D37",
        color="#E36B77"
    ];

    information -> allow;
    information -> monitor;
    information -> escalate;
    information -> block;

    {rank=same; allow; monitor; escalate; block;}
}
"""

st.graphviz_chart(
    architecture,
    width="stretch"
)

st.caption(
    "Solid arrows represent request-processing flow. "
    "Dotted arrows represent interactions with external stores and services."
)


# --------------------------------------------------
# REQUEST LIFECYCLE
# --------------------------------------------------

st.markdown("### Request Lifecycle")

st.markdown(
    """
    The firewall processes requests through the following sequence:
    """
)

lifecycle = [
    (
        "1. User Task",
        "The trusted user task establishes the original purpose of the operation."
    ),
    (
        "2. Identity and Request Budget",
        "The firewall verifies the user identity and checks the session request limit."
    ),
    (
        "3. Provenance and Taint Tracking",
        "The system tracks the origin of information and identifies untrusted inputs."
    ),
    (
        "4. RBAC and ABAC Authorization",
        "RBAC checks role permissions, while ABAC evaluates contextual attributes and policies."
    ),
    (
        "5. Resource Sensitivity",
        "The firewall evaluates the sensitivity of the requested enterprise resource."
    ),
    (
        "6. Adaptive Inspection Router",
        "The request is assigned FAST, CONTEXTUAL or DEEP inspection."
    ),
    (
        "7. Contextual and Deep Analysis",
        "Intent, trajectory and semantic analysis are performed on CONTEXTUAL and DEEP paths."
    ),
    (
        "8. Risk Aggregation",
        "The security signals are combined to calculate the request risk."
    ),
    (
        "9. Semantic Audit and Information Flow",
        "Model-assisted semantic auditing is applied when required, followed by information-flow and lineage checks."
    ),
    (
        "10. Final Enforcement",
        "The firewall produces ALLOW, MONITOR, ESCALATE or BLOCK."
    )
]

for title, description in lifecycle:
    with st.expander(title):
        st.write(description)


# --------------------------------------------------
# SECURITY PIPELINE
# --------------------------------------------------

st.markdown("### Security Pipeline")

pipeline_col1, pipeline_col2 = st.columns(2)

with pipeline_col1:

    st.markdown("#### Authorization and Context")

    st.markdown(
        """
        **Identity Verification**

        Identifies the user and session.

        **RBAC / ABAC**

        Checks role-based and attribute-based permissions.

        **Provenance and Taint**

        Tracks information origin and untrusted context.

        **Resource Sensitivity**

        Evaluates the sensitivity of the requested resource.
        """
    )

with pipeline_col2:

    st.markdown("#### Adaptive Analysis and Enforcement")

    st.markdown(
        """
        **Adaptive Routing**

        Selects FAST, CONTEXTUAL or DEEP inspection.

        **Intent and Trajectory**

        Evaluates task alignment and previous session actions.

        **Semantic and Risk Analysis**

        Evaluates suspicious signals and aggregates risk.

        **Final Enforcement**

        Applies the appropriate security decision.
        """
    )


# --------------------------------------------------
# ENFORCEMENT ACTIONS
# --------------------------------------------------

st.markdown("### Enforcement Actions")

action_col1, action_col2, action_col3, action_col4 = st.columns(4)

with action_col1:
    st.success(
        "**ALLOW**\n\n"
        "Request is permitted and the tool operation can execute."
    )

with action_col2:
    st.info(
        "**MONITOR**\n\n"
        "Request is logged and held without tool execution."
    )

with action_col3:
    st.warning(
        "**ESCALATE**\n\n"
        "Request is withheld and sent for human review."
    )

with action_col4:
    st.error(
        "**BLOCK**\n\n"
        "Request is rejected and execution is prevented."
    )


# --------------------------------------------------
# DESIGN PRINCIPLE
# --------------------------------------------------

st.markdown("### Design Principle")

st.info(
    "The dashboard provides visibility into the security pipeline, "
    "but does not independently make security decisions. "
    "The FirewallInterceptor remains the enforcement authority."
)