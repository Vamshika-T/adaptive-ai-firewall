def determine_inspection_level(
    request,
    resource,
    sensitivity_score,
    tainted,
    provenance_trusted,
    trajectory_score=0,
    semantic_score=0
):
    """
    Determine the inspection depth required for a request.

    FAST:
        Low-risk requests with no suspicious context.

    CONTEXTUAL:
        Requests involving moderate sensitivity or
        contextual information.

    DEEP:
        Requests involving tainted/untrusted context,
        highly sensitive resources, or suspicious behavior.
    """

    reasons = []

    # -------------------------------------------------
    # DEEP INSPECTION
    # -------------------------------------------------

    if tainted:
        reasons.append(
            "Request is influenced by tainted context"
        )

    if not provenance_trusted:
        reasons.append(
            "Request contains untrusted provenance"
        )

    if trajectory_score >= 30:
        reasons.append(
            "Suspicious action trajectory detected"
        )

    if sensitivity_score >= 75:
        reasons.append(
            "Request targets highly sensitive resource"
        )

    if semantic_score >= 60:
        reasons.append(
            "High semantic/STI risk detected"
        )

    if (
        tainted
        and request.tool in {
            "send_email_message",
            "update_crm_record"
        }
    ):
        reasons.append(
            "Tainted context influences a write action"
        )

    if (
        tainted
        or not provenance_trusted
        or trajectory_score >= 30
        or sensitivity_score >= 75
        or semantic_score >= 60
    ):
        return {
            "level": "DEEP",
            "reasons": reasons
        }

    # -------------------------------------------------
    # CONTEXTUAL INSPECTION
    # -------------------------------------------------

    if sensitivity_score >= 50:
        reasons.append(
            "Request targets a confidential resource"
        )

    if semantic_score >= 30:
        reasons.append(
            "Moderate semantic/STI risk detected"
        )

    if request.context_sources:
        reasons.append(
            "Request contains context sources"
        )

    if trajectory_score > 0:
        reasons.append(
            "Request has non-zero trajectory risk"
        )

    if (
        sensitivity_score >= 50
        or semantic_score >= 30
        or request.context_sources
        or trajectory_score > 0
    ):
        return {
            "level": "CONTEXTUAL",
            "reasons": reasons
        }

    # -------------------------------------------------
    # FAST INSPECTION
    # -------------------------------------------------

    reasons.append(
        "Request has low contextual risk"
    )

    return {
        "level": "FAST",
        "reasons": reasons
    }