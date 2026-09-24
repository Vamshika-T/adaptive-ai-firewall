import streamlit as st


def apply_dashboard_styles():
    """Apply global styling for the security console."""

    st.markdown(
        """
        <style>

        /* ---------- Global ---------- */

        .stApp {
            background: #0b0f14;
        }

        .main .block-container {
            padding-top: 2rem;
            padding-bottom: 3rem;
            max-width: 1500px;
        }

        /* ---------- Sidebar ---------- */

        [data-testid="stSidebar"] {
            background: #0f141b;
            border-right: 1px solid #202832;
        }

        [data-testid="stSidebar"] * {
            color: #e8edf2;
        }

        /* ---------- Header ---------- */

        .security-header {
            padding: 1.2rem 1.4rem;
            border: 1px solid #252e38;
            border-radius: 14px;
            background: linear-gradient(
                135deg,
                #111821,
                #0d131a
            );
            margin-bottom: 1.5rem;
        }

        .security-title {
            font-size: 2rem;
            font-weight: 700;
            color: #f5f7fa;
            margin-bottom: 0.25rem;
        }

        .security-subtitle {
            color: #9da9b5;
            font-size: 0.95rem;
        }

        /* ---------- Status ---------- */

        .status-pill {
            display: inline-block;
            padding: 0.35rem 0.75rem;
            border-radius: 999px;
            font-size: 0.8rem;
            font-weight: 600;
            margin-top: 0.8rem;
        }

        .status-ready {
            background: #12301f;
            color: #73e6a1;
            border: 1px solid #205b39;
        }

        .status-pending {
            background: #302710;
            color: #f0c96a;
            border: 1px solid #5b491d;
        }

        /* ---------- Cards ---------- */

        .metric-card {
            background: #111820;
            border: 1px solid #252e38;
            border-radius: 12px;
            padding: 1rem 1.1rem;
            min-height: 115px;
        }

        .metric-label {
            color: #8f9ba7;
            font-size: 0.78rem;
            text-transform: uppercase;
            letter-spacing: 0.06em;
        }

        .metric-value {
            color: #f5f7fa;
            font-size: 1.8rem;
            font-weight: 700;
            margin-top: 0.4rem;
        }

        .metric-description {
            color: #687581;
            font-size: 0.75rem;
            margin-top: 0.25rem;
        }

        /* ---------- Section ---------- */

        .section-title {
            color: #f1f4f7;
            font-size: 1.15rem;
            font-weight: 650;
            margin-top: 1.5rem;
            margin-bottom: 0.7rem;
        }

        /* ---------- Info boxes ---------- */

        .info-box {
            background: #111820;
            border: 1px solid #252e38;
            border-radius: 12px;
            padding: 1rem 1.1rem;
            color: #b8c2cc;
        }

        .info-box strong {
            color: #f1f4f7;
        }

        /* ---------- Event placeholder ---------- */

        .empty-state {
            background: #10161d;
            border: 1px dashed #303a45;
            border-radius: 12px;
            padding: 2rem;
            text-align: center;
            color: #7f8b97;
        }

        /* ---------- Footer ---------- */

        .dashboard-footer {
            color: #687581;
            font-size: 0.75rem;
            text-align: center;
            padding-top: 2rem;
        }

        </style>
        """,
        unsafe_allow_html=True,
    )