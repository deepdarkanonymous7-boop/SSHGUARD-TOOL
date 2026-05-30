"""
MITRE ATT&CK technique mappings used across SSHGuard modules.
Reference: https://attack.mitre.org
"""

from typing import NamedTuple, List


class Technique(NamedTuple):
    id: str
    name: str
    tactic: str
    url: str


TECHNIQUES = {
    "T1021.004": Technique(
        "T1021.004", "Remote Services: SSH",
        "Lateral Movement",
        "https://attack.mitre.org/techniques/T1021/004/",
    ),
    "T1041": Technique(
        "T1041", "Exfiltration Over C2 Channel",
        "Exfiltration",
        "https://attack.mitre.org/techniques/T1041/",
    ),
    "T1046": Technique(
        "T1046", "Network Service Discovery",
        "Discovery",
        "https://attack.mitre.org/techniques/T1046/",
    ),
    "T1053.003": Technique(
        "T1053.003", "Scheduled Task/Job: Cron",
        "Persistence / Privilege Escalation",
        "https://attack.mitre.org/techniques/T1053/003/",
    ),
    "T1059": Technique(
        "T1059", "Command and Scripting Interpreter",
        "Execution",
        "https://attack.mitre.org/techniques/T1059/",
    ),
    "T1059.001": Technique(
        "T1059.001", "Command and Scripting Interpreter: PowerShell",
        "Execution",
        "https://attack.mitre.org/techniques/T1059/001/",
    ),
    "T1068": Technique(
        "T1068", "Exploitation for Privilege Escalation",
        "Privilege Escalation",
        "https://attack.mitre.org/techniques/T1068/",
    ),
    "T1078": Technique(
        "T1078", "Valid Accounts",
        "Defense Evasion / Persistence / Privilege Escalation",
        "https://attack.mitre.org/techniques/T1078/",
    ),
    "T1098.004": Technique(
        "T1098.004", "Account Manipulation: SSH Authorized Keys",
        "Persistence",
        "https://attack.mitre.org/techniques/T1098/004/",
    ),
    "T1105": Technique(
        "T1105", "Ingress Tool Transfer",
        "Command and Control",
        "https://attack.mitre.org/techniques/T1105/",
    ),
    "T1548.001": Technique(
        "T1548.001", "Abuse Elevation Control Mechanism: Setuid/Setgid",
        "Privilege Escalation / Defense Evasion",
        "https://attack.mitre.org/techniques/T1548/001/",
    ),
    "T1548.003": Technique(
        "T1548.003", "Abuse Elevation Control Mechanism: Sudo/Sudoers",
        "Privilege Escalation / Defense Evasion",
        "https://attack.mitre.org/techniques/T1548/003/",
    ),
    "T1552.004": Technique(
        "T1552.004", "Unsecured Credentials: Private Keys",
        "Credential Access",
        "https://attack.mitre.org/techniques/T1552/004/",
    ),
    "T1562.001": Technique(
        "T1562.001", "Impair Defenses: Disable or Modify Tools",
        "Defense Evasion",
        "https://attack.mitre.org/techniques/T1562/001/",
    ),
    "T1563.001": Technique(
        "T1563.001", "Remote Service Session Hijacking: SSH Hijacking",
        "Lateral Movement",
        "https://attack.mitre.org/techniques/T1563/001/",
    ),
    "T1565.001": Technique(
        "T1565.001", "Data Manipulation: Stored Data Manipulation",
        "Impact",
        "https://attack.mitre.org/techniques/T1565/001/",
    ),
    "T1571": Technique(
        "T1571", "Non-Standard Port",
        "Command and Control",
        "https://attack.mitre.org/techniques/T1571/",
    ),
    "T1574.006": Technique(
        "T1574.006", "Hijack Execution Flow: Dynamic Linker Hijacking",
        "Persistence / Privilege Escalation / Defense Evasion",
        "https://attack.mitre.org/techniques/T1574/006/",
    ),
    "T1082": Technique(
        "T1082", "System Information Discovery",
        "Discovery",
        "https://attack.mitre.org/techniques/T1082/",
    ),
    "T1070.003": Technique(
        "T1070.003", "Indicator Removal: Clear Command History",
        "Defense Evasion",
        "https://attack.mitre.org/techniques/T1070/003/",
    ),
    "T1036": Technique(
        "T1036", "Masquerading",
        "Defense Evasion",
        "https://attack.mitre.org/techniques/T1036/",
    ),
}


def get(technique_id: str) -> str:
    """Return formatted technique string for display."""
    t = TECHNIQUES.get(technique_id)
    if t:
        return f"{t.id} — {t.name}"
    return technique_id


def get_tactic(technique_id: str) -> str:
    t = TECHNIQUES.get(technique_id)
    return t.tactic if t else "Unknown"


def get_url(technique_id: str) -> str:
    t = TECHNIQUES.get(technique_id)
    return t.url if t else f"https://attack.mitre.org/techniques/{technique_id}/"
