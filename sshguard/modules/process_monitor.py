"""
Process Monitor
Detects suspicious processes using IOC matching, pattern analysis,
parent-child chain inspection, and resource anomaly detection.
MITRE ATT&CK: T1059, T1036, T1070
"""

import os
import re
import platform
from typing import List, Dict

from ..utils.sysutils import get_all_processes
from ..utils.colors import (
    green, red, yellow, cyan, magenta, dim, bold, white,
    severity_badge, rule, truncate,
)
from ..engine.alert import AlertEngine, make_alert
from ..intel import ioc, mitre

PLATFORM = platform.system()


# ── Risk scoring ─────────────────────────────────────────────────────────────

def _score_process(proc: Dict) -> tuple:
    """Return (severity, reasons[]) for a process."""
    name_l = proc.get("name", "").lower()
    cmd_l  = proc.get("cmd",  "").lower()
    user   = proc.get("user", "")
    cpu    = proc.get("cpu", 0.0)
    mem_kb = proc.get("mem_kb", 0)
    reasons = []

    # Direct IOC name match
    if name_l in ioc.SUSPICIOUS_PROCESS_NAMES:
        reasons.append(f"IOC match: '{proc['name']}'")

    # Command pattern matching
    for pattern in ioc.SUSPICIOUS_CMD_PATTERNS:
        if re.search(pattern, cmd_l, re.IGNORECASE):
            reasons.append(f"Suspicious cmd pattern: '{pattern}'")
            break

    # Running as root / SYSTEM with network-related command
    root_users = {"root", "system", "administrator"}
    if user.lower() in root_users:
        if any(kw in cmd_l for kw in ["curl", "wget", "python", "perl", "ruby", "nc ", "ncat"]):
            reasons.append(f"Root user running network tool")

    # Process masquerading (name contains spaces or unusual chars)
    if " " in proc.get("name", "") and PLATFORM != "Windows":
        reasons.append("Possible process name masquerade")

    # Executing from suspicious paths
    suspicious_paths = ["/tmp/", "/dev/shm/", "/var/tmp/", r"C:\Users\Public\\",
                        r"C:\Windows\Temp\\", r"C:\ProgramData\\"]
    for sp in suspicious_paths:
        if sp in cmd_l or sp.lower() in cmd_l:
            reasons.append(f"Executing from suspicious path: {sp}")
            break

    # High CPU from unexpected process
    if cpu > 90 and name_l not in {"systemd", "kernel", "init", "irq"}:
        reasons.append(f"Abnormally high CPU: {cpu}%")

    # Memory over 1 GB for unknown process
    if mem_kb > 1_000_000 and name_l not in {"chrome", "firefox", "java", "node", "python3"}:
        reasons.append(f"High memory usage: {mem_kb // 1024} MB")

    # Determine severity
    critical_patterns = [
        r"base64\s+-[dD]", r"/dev/shm/", r"\|\s*bash", r"\|\s*sh\s*$",
        r"exec\s+/bin/(sh|bash)", r">.*\/dev\/tcp\/",
        r"mimikatz", r"-enc\s+[A-Za-z0-9+/=]{20,}",
    ]
    for cp in critical_patterns:
        if re.search(cp, cmd_l, re.IGNORECASE):
            return "CRITICAL", reasons

    if len(reasons) >= 3:
        return "CRITICAL", reasons
    if len(reasons) == 2:
        return "HIGH", reasons
    if reasons:
        return "MEDIUM" if name_l in ioc.SUSPICIOUS_PROCESS_NAMES else "HIGH", reasons

    return "LOW", []


# ── Display ──────────────────────────────────────────────────────────────────

def _display(flagged: List[Dict]) -> None:
    from ..banner import section
    section("Process Monitor — Suspicious Process Detection", "[+]")
    print(
        f"  {dim('PID'):<9}{dim('Name'):<20}{dim('User'):<14}"
        f"{dim('CPU%'):<8}{dim('MEM(KB)'):<10}{dim('Risk'):<18}{dim('Reasons / Command')}"
    )
    print(f"  {dim(rule(100))}")

    if not flagged:
        print(f"  {green('No suspicious processes detected.')} {dim('(All clear)')}")
        return

    for p in flagged:
        sev   = p["severity"]
        badge = severity_badge(sev)
        color = red if sev in ("CRITICAL","HIGH") else yellow
        reasons_short = "; ".join(p["reasons"][:2])
        cmd_short = truncate(p["proc"]["cmd"], 50)
        display_info = reasons_short or cmd_short

        print(
            f"  {yellow(p['proc']['pid']):<18}"
            f"{color(p['proc']['name']):<20}"
            f"{cyan(p['proc']['user']):<14}"
            f"{dim(str(p['proc']['cpu'])):<8}"
            f"{dim(str(p['proc']['mem_kb'])):<10}"
            f"{badge:<27}"
            f"{dim(display_info)}"
        )
        if p["reasons"]:
            for r in p["reasons"]:
                print(f"  {' '*78}{dim('→')} {r}")

    print(dim(f"\n  [{len(flagged)} suspicious process(es) detected]"))


# ── Main module entry ─────────────────────────────────────────────────────────

def run(engine: AlertEngine) -> List[Dict]:
    """Run process monitor. Returns list of flagged process dicts."""
    all_procs = get_all_processes()
    flagged = []

    for proc in all_procs:
        severity, reasons = _score_process(proc)
        if severity == "LOW":
            continue

        entry = {"proc": proc, "severity": severity, "reasons": reasons}
        flagged.append(entry)

        # Choose MITRE technique
        cmd_l = proc.get("cmd", "").lower()
        if re.search(r"-enc|IEX|DownloadString|powershell", cmd_l, re.I):
            technique = mitre.get("T1059.001")
        elif re.search(r"base64|mkfifo|/dev/tcp", cmd_l):
            technique = mitre.get("T1059")
        elif re.search(r" " , proc.get("name", "")):
            technique = mitre.get("T1036")
        else:
            technique = mitre.get("T1059")

        reasons_str = "; ".join(reasons[:3])
        engine.add(make_alert(
            title=f"Suspicious Process: {proc['name']} (PID {proc['pid']})",
            description=(
                f"Process '{proc['name']}' (PID {proc['pid']}, user '{proc['user']}') "
                f"flagged: {reasons_str}. "
                f"Command: {truncate(proc['cmd'], 120)}"
            ),
            severity=severity,
            category="SUSPICIOUS_PROCESS",
            technique=technique,
            source="process_monitor",
            pid=int(proc["pid"]) if str(proc["pid"]).isdigit() else None,
        ))

    # Sort by severity
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    flagged.sort(key=lambda x: order.get(x["severity"], 9))
    _display(flagged)
    return flagged
