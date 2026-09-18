def evaluate_taint(request, provenance_result):
    """
    Determine whether the current action is influenced
    by untrusted information.
    """

    if request.tainted:
        return True

    if not provenance_result["trusted"]:
        return True

    return False