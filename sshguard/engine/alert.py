"""
Alert engine — creates, scores, deduplicates, and manages security alerts.
"""

import datetime
import hashlib
from typing import List, Dict, Optional
from dataclasses import dataclass, field, asdict


SEVERITY_SCORE = {"CRITICAL": 100, "HIGH": 60, "MEDIUM": 30, "LOW": 10, "INFO": 0}
CATEGORY_LABELS = {
    "SSH_HIJACK":          "SSH Hijacking",
    "PRIVILEGE_ESCALATION":"Privilege Escalation",
    "SUSPICIOUS_PROCESS":  "Suspicious Process",
    "NETWORK_ANOMALY":     "Network Anomaly",
    "FILE_INTEGRITY":      "File Integrity",
    "LATERAL_MOVEMENT":    "Lateral Movement",
    "PERSISTENCE":         "Persistence",
    "DEFENSE_EVASION":     "Defense Evasion",
    "CREDENTIAL_ACCESS":   "Credential Access",
    "DISCOVERY":           "Discovery",
}


@dataclass
class Alert:
    title:       str
    description: str
    severity:    str          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    category:    str          # from CATEGORY_LABELS keys
    technique:   str          # MITRE ATT&CK e.g. "T1563.001"
    source:      str          # module that generated it
    pid:         Optional[int] = None
    path:        Optional[str] = None
    extra:       Dict = field(default_factory=dict)
    timestamp:   str = field(default_factory=lambda: datetime.datetime.now().isoformat())
    id:          str = field(default="")
    score:       int = field(default=0)
    dismissed:   bool = False

    def __post_init__(self):
        self.score = SEVERITY_SCORE.get(self.severity, 0)
        if not self.id:
            raw = f"{self.category}:{self.title}:{self.pid}:{self.path}"
            self.id = hashlib.md5(raw.encode()).hexdigest()[:12]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["category_label"] = CATEGORY_LABELS.get(self.category, self.category)
        d["technique_url"] = f"https://attack.mitre.org/techniques/{self.technique.split(' ')[0].replace('.','/').rstrip('/')}/"
        return d


class AlertEngine:
    def __init__(self):
        self._alerts: List[Alert] = []
        self._seen_ids: set = set()

    def add(self, alert: Alert) -> bool:
        """Add an alert; deduplicate by ID. Returns True if new."""
        if alert.id in self._seen_ids:
            return False
        self._seen_ids.add(alert.id)
        self._alerts.append(alert)
        return True

    def add_many(self, alerts: List[Alert]) -> int:
        return sum(1 for a in alerts if self.add(a))

    def dismiss(self, alert_id: str) -> bool:
        for a in self._alerts:
            if a.id == alert_id:
                a.dismissed = True
                return True
        return False

    @property
    def all(self) -> List[Alert]:
        return [a for a in self._alerts if not a.dismissed]

    @property
    def critical(self) -> List[Alert]:
        return [a for a in self.all if a.severity == "CRITICAL"]

    @property
    def high(self) -> List[Alert]:
        return [a for a in self.all if a.severity == "HIGH"]

    @property
    def by_severity(self) -> List[Alert]:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        return sorted(self.all, key=lambda a: order.get(a.severity, 9))

    @property
    def total_score(self) -> int:
        return sum(a.score for a in self.all)

    def threat_level(self) -> str:
        score = self.total_score
        crit  = len(self.critical)
        hi    = len(self.high)
        if crit > 0 or score >= 200:  return "CRITICAL"
        if hi > 2  or score >= 100:   return "HIGH"
        if score >= 40:                return "MEDIUM"
        if score > 0:                  return "LOW"
        return "CLEAN"

    def stats(self) -> Dict[str, int]:
        all_a = self.all
        return {
            "total":    len(all_a),
            "critical": sum(1 for a in all_a if a.severity == "CRITICAL"),
            "high":     sum(1 for a in all_a if a.severity == "HIGH"),
            "medium":   sum(1 for a in all_a if a.severity == "MEDIUM"),
            "low":      sum(1 for a in all_a if a.severity == "LOW"),
            "score":    self.total_score,
        }

    def clear(self) -> None:
        self._alerts.clear()
        self._seen_ids.clear()

    def to_dicts(self) -> List[dict]:
        return [a.to_dict() for a in self.by_severity]


# ── Factory helpers ───────────────────────────────────────────────────────────

def make_alert(
    title: str,
    description: str,
    severity: str,
    category: str,
    technique: str,
    source: str,
    pid: int = None,
    path: str = None,
    **extra,
) -> Alert:
    return Alert(
        title=title, description=description,
        severity=severity, category=category,
        technique=technique, source=source,
        pid=pid, path=path, extra=extra,
    )
