def calculate_risk(
    authorization_ok,
    sensitivity_score,
    intent_consistent,
    trajectory_score
):

    # -----------------------------------------------------
    # Authorization is a hard security boundary.
    # -----------------------------------------------------

    if not authorization_ok:
        return 100

    risk = 0

    # -----------------------------------------------------
    # Resource sensitivity
    # -----------------------------------------------------

    risk += sensitivity_score * 0.30

    # -----------------------------------------------------
    # Intent mismatch
    # -----------------------------------------------------

    if not intent_consistent:
        risk += 25

    # -----------------------------------------------------
    # Multi-step trajectory
    #
    # Trajectory receives a higher weight because
    # dangerous behavior often becomes visible only
    # when multiple actions are considered together.
    # -----------------------------------------------------

    risk += trajectory_score * 0.75

    return min(
        round(risk, 2),
        100
    )


def decide_action(
    risk_score
):

    if risk_score >= 70:
        return "BLOCK"

    if risk_score >= 45:
        return "ESCALATE"

    if risk_score >= 25:
        return "MONITOR"

    return "ALLOW"