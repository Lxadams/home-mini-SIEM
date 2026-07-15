SURICATA_CATEGORY_SEVERITY = {
    "not suspicious traffic": 4,
    "unknown traffic": 4,
    "potentially bad traffic": 3,
    "attempted information leak": 3,
    "information leak": 2,
    "large scale information leak": 2,
    "attempted denial of service": 3,
    "denial of service": 2,
    "attempted user privilege gain": 2,
    "unsuccessful user privilege gain": 2,
    "successful user privilege gain": 1,
    "attempted administrator privilege gain": 2,
    "successful administrator privilege gain": 1,
    "decode of an rpc query": 4,
    "executable code was detected": 1,
    "a suspicious string was detected": 3,
    "a suspicious filename was detected": 3,
    "an attempted login using a suspicious username was detected": 2,
    "a system call was detected": 3,
    "a tcp connection was detected": 4,
    "a network trojan was detected": 1,
    "a client was using an unusual port": 3,
    "detection of a network scan": 3,
    "detection of a denial of service attack": 2,
    "detection of a non-standard protocol or event": 4,
    "generic protocol command decode": 4,
    "access to a potentially vulnerable web application": 3,
    "web application attack": 1,
    "misc activity": 4,
    "misc attack": 3,
    "generic icmp event": 4,
    "inappropriate content was detected": 3,
    "potential corporate privacy violation": 3,
    "attempt to login by a default username and password": 2,
    "targeted malicious activity was detected": 1,
    "exploit kit activity detected": 1,
    "device retrieving external ip address detected": 4,
    "domain observed used for c2 detected": 1,
    "possibly unwanted program detected": 3,
    "successful credential theft detected": 1,
    "possible social engineering attempted": 2,
    "crypto currency mining activity detected": 2,
    "malware command and control activity detected": 1,
}

DEFAULT_SEVERITY = 3  # medium, used when a category isn't in the table above
ENGINE_ALERT_SEVERITY = 4  # Suricata's own decoder/stream anomaly events, not threat detections

# Signature-level overrides, checked as a case-insensitive substring match
# against the alert signature. Checked before the category lookup, since
# some signatures deserve different treatment than their broad category.
SIGNATURE_OVERRIDES = [
    ("tor", 2),  # Known Tor relay/exit traffic, worth a closer look than generic Misc Attack
]

def map_suricata_severity(category, signature):
    if signature and signature.startswith("SURICATA "):
        return ENGINE_ALERT_SEVERITY
    if signature:
        sig_lower = signature.lower()
        for keyword, severity in SIGNATURE_OVERRIDES:
            if keyword in sig_lower:
                return severity
    if not category:
        return DEFAULT_SEVERITY
    severity = SURICATA_CATEGORY_SEVERITY.get(category.strip().lower())
    if severity is None:
        print(f"suricata_severity: unmapped category '{category}', using default {DEFAULT_SEVERITY}")
        return DEFAULT_SEVERITY
    return severity