def deep_semantic_inspection(
    request,
    intent_result,
    provenance_result,
    trajectory_result
):
    """
    Deep security inspection layer.

    This is the local prototype's semantic security layer.
    It evaluates suitability, trust/taint and integrity-related
    signals before a high-risk request can execute.

    The interface is intentionally isolated so a stronger
    AgentVisor-style semantic implementation can be used
    without changing the firewall pipeline.
    """

    reasons = []

    # Suitability
    if not intent_result["consistent"]:
        reasons.append(
            "Deep inspection: action is inconsistent with stated intent"
        )

    # Taint / provenance
    if not provenance_result["trusted"]:
        reasons.append(
            "Deep inspection: request depends on untrusted provenance"
        )

    if request.tainted:
        reasons.append(
            "Deep inspection: request carries tainted context"
        )

    # Trajectory
    if trajectory_result["score"] >= 30:
        reasons.append(
            "Deep inspection: suspicious action trajectory detected"
        )

    # Unknown / ambiguous context is handled conservatively.
    if not reasons:
        reasons.append(
            "Deep inspection: no direct semantic violation identified"
        )

    suspicious = (
        not intent_result["consistent"]
        or not provenance_result["trusted"]
        or request.tainted
        or trajectory_result["score"] >= 30
    )

    return {
        "suspicious": suspicious,
        "reasons": reasons
    }


def safety_first_decision(
    request,
    sensitivity_score,
    sti_result
):
    """
    Safety-first policy for unfamiliar or ambiguous
    high-impact behavior.
    """

    if not sti_result["suspicious"]:
        return "ALLOW"

    if sensitivity_score >= 75:
        return "BLOCK"

    if sensitivity_score >= 50:
        return "ESCALATE"

    return "MONITOR"