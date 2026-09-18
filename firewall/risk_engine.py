def calculate_risk(
    authorization_ok,
    sensitivity_score,
    provenance_trusted,
    tainted,
    intent_consistent,
    trajectory_score
):
    """
    Calculate a transparent runtime risk score.

    Authorization remains a hard gate.
    Risk scoring is applied to otherwise permitted actions.
    """

    if not authorization_ok:
        return 100

    risk = 0

    # Resource sensitivity
    risk += sensitivity_score * 0.30

    # Provenance
    if not provenance_trusted:
        risk += 20

    # Taint
    if tainted:
        risk += 20

    # Intent mismatch
    if not intent_consistent:
        risk += 15

    # Multi-step trajectory
    risk += trajectory_score * 0.30

    return min(round(risk, 2), 100)