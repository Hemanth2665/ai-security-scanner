import re


PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+previous\s+instructions",
    r"ignore\s+all\s+instructions",
    r"reveal\s+system\s+prompt",
    r"show\s+me\s+your\s+system\s+prompt",
    r"bypass\s+rules",
    r"jailbreak",
    r"developer\s+mode",
    r"act\s+as\s+dan",
]

SECRET_PATTERNS = [
    r"sk-[A-Za-z0-9]{20,}",
    r"AKIA[0-9A-Z]{16}",
    r"AIza[0-9A-Za-z\-_]{20,}",
    r"ghp_[A-Za-z0-9]{20,}",
    r"xox[baprs]-[A-Za-z0-9-]{10,}",
    r"api[_-]?key\s*=\s*[A-Za-z0-9_\-]{10,}",
    r"password\s*=\s*.+",
]

SUSPICIOUS_URL_PATTERNS = [
    r"http://",
    r"login",
    r"verify",
    r"secure",
    r"account",
    r"password",
    r"\.ru",
    r"\.tk",
    r"\.xyz",
]


def scan_text(text: str) -> dict:
    findings = []
    risk_score = 0

    for pattern in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            findings.append({
                "type": "Prompt Injection",
                "pattern": pattern,
                "severity": "High"
            })
            risk_score += 30

    for pattern in SECRET_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            findings.append({
                "type": "Credential or Secret Leak",
                "pattern": pattern,
                "severity": "Critical"
            })
            risk_score += 40

    for pattern in SUSPICIOUS_URL_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            findings.append({
                "type": "Suspicious URL Indicator",
                "pattern": pattern,
                "severity": "Medium"
            })
            risk_score += 15

    if risk_score > 100:
        risk_score = 100

    if risk_score >= 80:
        overall = "Critical"
    elif risk_score >= 50:
        overall = "High"
    elif risk_score >= 25:
        overall = "Medium"
    elif risk_score > 0:
        overall = "Low"
    else:
        overall = "Clean"

    return {
        "risk_score": risk_score,
        "overall_risk": overall,
        "findings": findings
    }


if __name__ == "__main__":
    sample = input("Enter text to scan: ")
    result = scan_text(sample)
    print(result)
