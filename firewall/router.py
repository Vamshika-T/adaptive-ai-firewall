def choose_inspection_level(
    risk_score,
    tainted,
    provenance_trusted,
    sensitivity_score
):

    # High-risk or untrusted sensitive requests
    # receive deep inspection.
    if (
        risk_score >= 70
        or (
            tainted
            and sensitivity_score >= 75
        )
        or not provenance_trusted
            and sensitivity_score >= 75
    ):
        return "DEEP"

    # Moderate contextual concerns.
    if (
        risk_score >= 35
        or tainted
        or not provenance_trusted
        or sensitivity_score >= 50
    ):
        return "CONTEXTUAL"

    # Normal low-risk requests.
    return "FAST"