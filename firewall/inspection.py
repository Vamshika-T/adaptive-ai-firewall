
def determine_preliminary_inspection_level(
    request,
    sensitivity_score,
    tainted,
    provenance_trusted,
):
    """
    Select an initial inspection depth using information that is
    already available, before optional expensive analysis.

    This is a preliminary routing decision, not the final security
    decision. Later analysis may increase the inspection depth.
    """

    reasons = []

    # Cheap semantic prefilter: suspicious task text must not remain on
    # FAST merely because the target tool/resource is otherwise low risk.
    # This is deliberately a lightweight routing signal; the contextual
    # semantic checks and model auditor still make the deeper assessment.
    intent = (getattr(request, "intent", "") or "").strip().lower()
    override_phrases = (
        "ignore previous instructions",
        "ignore all previous instructions",
        "disregard previous instructions",
        "disregard all previous instructions",
        "forget previous instructions",
        "override previous instructions",
    )
    disclosure_phrases = (
        "reveal secret",
        "reveal confidential",
        "reveal sensitive",
        "leak secret",
        "leak confidential",
        "leak sensitive",
        "export secret",
        "export confidential",
        "export sensitive",
    )
    suspicious_terms = (
        "bypass", "exfiltrate", "reveal", "secret", "password",
        "confidential", "sensitive", "leak", "ignore instructions",
    )
    has_override = any(phrase in intent for phrase in override_phrases)
    has_disclosure = any(phrase in intent for phrase in disclosure_phrases)
    if has_override and has_disclosure:
        reasons.append(
            "Suspicious instruction override and sensitive-disclosure intent "
            "requires deep inspection"
        )
        return {"level": "DEEP", "reasons": reasons}
    if any(term in intent for term in suspicious_terms):
        reasons.append(
            "Suspicious intent signal requires contextual inspection"
        )
        # A potentially malicious task objective is worth deeper checks,
        # even when the individual tool call looks routine.
        return {"level": "CONTEXTUAL", "reasons": reasons}

    # Untrusted or tainted information needs deeper scrutiny.
    if tainted:
        reasons.append("Request is influenced by tainted context")

    if not provenance_trusted:
        reasons.append("Request contains untrusted provenance")

    # High-sensitivity resources need deeper scrutiny.
    if sensitivity_score >= 75:
        reasons.append("Request targets a highly sensitive resource")

    # Write actions influenced by context deserve extra scrutiny.
    if (
        tainted
        and request.tool in {
            "send_email_message",
            "update_crm_record",
        }
    ):
        reasons.append("Tainted context influences a write action")

    if (
        tainted
        or not provenance_trusted
        or sensitivity_score >= 75
    ):
        return {
            "level": "DEEP",
            "reasons": reasons,
        }

    # Moderate-sensitivity requests or requests using external
    # context need contextual inspection.
    if sensitivity_score >= 50:
        reasons.append("Request targets a confidential resource")

    if request.context_sources:
        reasons.append("Request contains context sources")

    if sensitivity_score >= 50 or request.context_sources:
        return {
            "level": "CONTEXTUAL",
            "reasons": reasons,
        }

    reasons.append("Preliminary checks indicate low contextual risk")

    return {
        "level": "FAST",
        "reasons": reasons,
    }


def determine_inspection_level(
    request,
    resource,
    sensitivity_score,
    tainted,
    provenance_trusted,
    trajectory_score=0,
    semantic_score=0,
):
    """
    Determine the final inspection depth after contextual analysis.

    FAST:
        Low-risk requests with no suspicious context.

    CONTEXTUAL:
        Requests involving moderate sensitivity or contextual
        information.

    DEEP:
        Requests involving tainted or untrusted context, highly
        sensitive resources, or suspicious behavior.
    """

    reasons = []

    # DEEP INSPECTION

    if tainted:
        reasons.append("Request is influenced by tainted context")

    if not provenance_trusted:
        reasons.append("Request contains untrusted provenance")

    if trajectory_score >= 30:
        reasons.append("Suspicious action trajectory detected")

    if sensitivity_score >= 75:
        reasons.append("Request targets highly sensitive resource")

    if semantic_score >= 60:
        reasons.append("High semantic/STI risk detected")

    if (
        tainted
        and request.tool in {
            "send_email_message",
            "update_crm_record",
        }
    ):
        reasons.append("Tainted context influences a write action")

    if (
        tainted
        or not provenance_trusted
        or trajectory_score >= 30
        or sensitivity_score >= 75
        or semantic_score >= 60
    ):
        return {
            "level": "DEEP",
            "reasons": reasons,
        }

    # CONTEXTUAL INSPECTION

    if sensitivity_score >= 50:
        reasons.append("Request targets a confidential resource")

    if semantic_score >= 30:
        reasons.append("Moderate semantic/STI risk detected")

    if request.context_sources:
        reasons.append("Request contains context sources")

    if trajectory_score > 0:
        reasons.append("Request has non-zero trajectory risk")

    if (
        sensitivity_score >= 50
        or semantic_score >= 30
        or request.context_sources
        or trajectory_score > 0
    ):
        return {
            "level": "CONTEXTUAL",
            "reasons": reasons,
        }

    # FAST INSPECTION

    reasons.append("Request has low contextual risk")

    return {
        "level": "FAST",
        "reasons": reasons,
    }
