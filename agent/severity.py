def calculate_severity(
    unauthorized=False,
    suspicious_path=False,
    suspicious_parent=False,
):
    score = 0

    if unauthorized:
        score += 1

    if suspicious_path:
        score += 2

    if suspicious_parent:
        score += 2

    if score >= 4:
        return "CRITICAL"

    if score >= 3:
        return "HIGH"

    if score >= 1:
        return "MEDIUM"

    return "LOW"