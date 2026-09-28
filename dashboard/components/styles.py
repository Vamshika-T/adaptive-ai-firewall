import streamlit as st


def apply_dashboard_styles():
    st.markdown(
        """
        <style>

        /* Page */

        .stApp {
            background: #f5f6f8;
            color: #20262e;
        }

        .main .block-container {
            max-width: 1400px;
            padding-top: 1.5rem;
            padding-bottom: 3rem;
        }

        /* Normal text */

        .stApp p {
            color: #303841;
        }

        .stApp label {
            color: #303841;
        }

        .stCaption,
        [data-testid="stCaptionContainer"] {
            color: #66717c !important;
        }


        /* Sidebar */

        [data-testid="stSidebar"] {
            background: #ffffff;
            border-right: 1px solid #d9dde3;
        }

        [data-testid="stSidebar"] .stMarkdown p,
        [data-testid="stSidebar"] label {
            color: #303841 !important;
        }

        .sidebar-brand {
            margin-bottom: 1.25rem;
        }

        .sidebar-brand-title {
            color: #20262e !important;
            font-size: 1.05rem;
            font-weight: 650;
        }

        .sidebar-brand-subtitle {
            color: #727d88 !important;
            font-size: 0.76rem;
            margin-top: 0.15rem;
        }

        .sidebar-status {
            color: #397154 !important;
            font-size: 0.78rem;
            font-weight: 600;
            margin-bottom: 1rem;
        }


        /* Header */

        .security-header {
            padding-bottom: 1rem;
            margin-bottom: 1.25rem;
            border-bottom: 1px solid #d9dde3;
        }

        .security-title {
            color: #20262e !important;
            font-size: 1.65rem;
            font-weight: 650;
        }

        .security-subtitle {
            color: #727d88 !important;
            font-size: 0.88rem;
            margin-top: 0.2rem;
        }

        .status-pill {
            display: inline-block;
            margin-top: 0.65rem;
            font-size: 0.76rem;
            font-weight: 600;
        }

        .status-ready {
            color: #397154 !important;
        }


        /* Metric cards */

        .metric-card {
            background: #ffffff;
            border: 1px solid #d9dde3;
            border-radius: 5px;
            padding: 0.95rem 1rem;
            min-height: 100px;
        }

        .metric-label {
            color: #66717c !important;
            font-size: 0.74rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.035em;
        }

        .metric-value {
            color: #20262e !important;
            font-size: 1.6rem;
            font-weight: 650;
            margin-top: 0.3rem;
        }

        .metric-description {
            color: #66717c !important;
            font-size: 0.73rem;
            margin-top: 0.2rem;
        }


        /* Section headings */

        .section-title {
            color: #303841 !important;
            font-size: 0.98rem;
            font-weight: 650;
            margin-top: 1.5rem;
            margin-bottom: 0.6rem;
        }


        /* Information boxes */

        .info-box {
            background: #ffffff;
            border: 1px solid #d9dde3;
            border-radius: 5px;
            padding: 0.9rem 1rem;
            color: #59636e !important;
            min-height: 70px;
        }

        .info-box strong {
            color: #20262e !important;
        }


        /* Select boxes */

        [data-baseweb="select"] {
            color: #20262e !important;
        }

        [data-baseweb="select"] > div {
            background: #ffffff !important;
            border-color: #cdd3da !important;
        }

        [data-baseweb="select"] span {
            color: #20262e !important;
        }

        [data-baseweb="popover"] {
            background: #ffffff !important;
        }

        [data-baseweb="popover"] * {
            color: #20262e;
        }


        /* Text inputs */

        [data-baseweb="input"] {
            background: #ffffff !important;
        }

        [data-baseweb="input"] input {
            background: #ffffff !important;
            color: #20262e !important;
            caret-color: #20262e !important;
        }

        [data-baseweb="input"] input::placeholder {
            color: #7a848f !important;
        }


        /* Gemini chat input */

        [data-testid="stChatInput"] {
            background: #ffffff !important;
            border: 1px solid #cdd3da !important;
        }

        [data-testid="stChatInput"] textarea {
            background: #ffffff !important;
            color: #20262e !important;
            caret-color: #20262e !important;
        }

        [data-testid="stChatInput"] textarea::placeholder {
            color: #7a848f !important;
        }


        /* Buttons */

        .stButton > button {
            background: #ffffff !important;
            color: #303841 !important;
            border: 1px solid #cdd3da !important;
        }

        .stButton > button:hover {
            background: #f5f6f8 !important;
            color: #20262e !important;
            border-color: #8d98a3 !important;
        }


        /* Expanders */

        [data-testid="stExpander"] {
            background: #ffffff !important;
            border: 1px solid #d9dde3 !important;
            border-radius: 5px;
        }

        [data-testid="stExpander"] summary {
            background: #ffffff !important;
            color: #303841 !important;
        }

        [data-testid="stExpander"] summary span {
            color: #303841 !important;
        }

        [data-testid="stExpander"] details {
            background: #ffffff !important;
        }

        [data-testid="stExpander"] p {
            color: #303841 !important;
        }

        [data-testid="stExpander"] [data-testid="stMarkdownContainer"] {
            color: #303841 !important;
        }


        /* JSON and code */

        [data-testid="stExpander"] pre {
            background: #f1f3f5 !important;
            color: #303841 !important;
            border: 1px solid #d9dde3;
        }

        [data-testid="stExpander"] code {
            color: #303841 !important;
        }


        /* Chat messages */

        [data-testid="stChatMessage"] {
            background: #ffffff !important;
            border: 1px solid #d9dde3;
        }

        [data-testid="stChatMessage"] p {
            color: #303841 !important;
        }


        /* Dataframe */

        [data-testid="stDataFrame"] {
            border: 1px solid #d9dde3;
        }


        /* Empty state */

        .empty-state {
            background: #ffffff;
            border: 1px solid #d9dde3;
            border-radius: 5px;
            padding: 1.4rem;
            color: #59636e !important;
        }


        /* Security states */

        .status-allow {
            color: #397154 !important;
            font-weight: 650;
        }

        .status-block {
            color: #a33d3d !important;
            font-weight: 650;
        }

        .status-warning {
            color: #936f20 !important;
            font-weight: 650;
        }


        /* Footer */

        .dashboard-footer {
            color: #89919a !important;
            font-size: 0.7rem;
            text-align: center;
            padding-top: 1.75rem;
        }

        /* Inline code */

        .stApp code {
            background: #eef1f4 !important;
            color: #20262e !important;
            border: 1px solid #d5d9de;
            border-radius: 3px;
            padding: 0.1rem 0.3rem;
        }

        /* Sidebar headings */

[data-testid="stSidebar"] h1,
[data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3,
[data-testid="stSidebar"] h4 {
    color: #20262e !important;
}


/* Sidebar navigation */

[data-testid="stSidebarNav"] {
    background: #ffffff !important;
}

[data-testid="stSidebarNav"] a {
    color: #303841 !important;
}

[data-testid="stSidebarNav"] a span {
    color: #303841 !important;
}

[data-testid="stSidebarNav"] a:hover {
    background: #f1f3f5 !important;
    color: #20262e !important;
}

[data-testid="stSidebarNav"] a[aria-current="page"] {
    background: #e9edf1 !important;
    color: #20262e !important;
}

[data-testid="stSidebarNav"] a[aria-current="page"] span {
    color: #20262e !important;
}


/* Material navigation icons */

[data-testid="stSidebarNav"] [data-testid="stIconMaterial"] {
    color: #59636e !important;
}

[data-testid="stSidebarNav"] a[aria-current="page"] [data-testid="stIconMaterial"] {
    color: #20262e !important;
}

        </style>
        """,
        unsafe_allow_html=True,
    )