from typing import Dict, Any


SENSITIVE_ACTIONS = {
    "query_database",
    "send_email_message",
    "update_crm_record",
}

EXTERNAL_ACTIONS = {
    "send_email_message",
    "update_crm_record",
}


def analyze_semantic_risk(
    request,
    resource: str,
    tainted: bool,
    provenance_trusted: bool,
    trajectory_score: float = 0,
) -> Dict[str, Any]:
    """
    Analyze the semantic/security context of a tool request.

    Returns:
        semantic_score: 0-100 risk score
        suspicious: whether semantic inspection detected risk
        reasons: explanations for the score
    """

    score = 0
    reasons = []

    tool = request.tool
    intent = (request.intent or "").lower()

    # -------------------------------------------------
    # 1. Tainted context
    # -------------------------------------------------
    if tainted:
        score += 30
        reasons.append(
            "Request is influenced by tainted context"
        )

    # -------------------------------------------------
    # 2. Untrusted provenance
    # -------------------------------------------------
    if not provenance_trusted:
        score += 20
        reasons.append(
            "Request contains untrusted provenance"
        )

    # -------------------------------------------------
    # 3. Sensitive action
    # -------------------------------------------------
    if tool in SENSITIVE_ACTIONS:
        score += 15
        reasons.append(
            "Request performs a security-sensitive action"
        )

    # -------------------------------------------------
    # 4. External/write action
    # -------------------------------------------------
    if tool in EXTERNAL_ACTIONS:
        score += 10
        reasons.append(
            "Request performs an external or write action"
        )

    # -------------------------------------------------
    # 5. Suspicious intent keywords
    # -------------------------------------------------
    suspicious_keywords = [
        "ignore previous",
        "ignore instructions",
        "bypass",
        "override",
        "export",
        "exfiltrate",
        "send confidential",
        "send sensitive",
        "leak",
        "reveal",
        "password",
        "secret",
        "payroll",
    ]

    matched_keywords = [
        keyword
        for keyword in suspicious_keywords
        if keyword in intent
    ]

    if matched_keywords:
        score += min(30, len(matched_keywords) * 10)

        reasons.append(
            "Suspicious semantic intent detected: "
            + ", ".join(matched_keywords)
        )

    # -------------------------------------------------
    # 6. Suspicious trajectory
    # -------------------------------------------------
    if trajectory_score >= 30:
        score += 20
        reasons.append(
            "Request follows a suspicious action trajectory"
        )

    score = min(score, 100)

    return {
        "semantic_score": score,
        "suspicious": score >= 30,
        "reasons": reasons,
    }