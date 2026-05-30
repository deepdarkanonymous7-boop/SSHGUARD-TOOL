"""
Lateral Movement Detector
Analyses SSH known_hosts, authorized_keys, bash/shell history,
recent logins (wtmp/utmp), and active SSH sessions for indicators
of lateral movement activity.
MITRE ATT&CK: T1021.004, T1098.004, T1552.004
"""

import os
import re
import glob
import platform
import subprocess
import datetime
from typing import List, Dict

from ..utils.colors import (
    green, red, yellow, cyan, magenta, dim, bold, white,
    severity_badge, rule, truncate,
)
from ..engine.alert import AlertEngine, make_alert
from ..intel import mitre

PLATFORM = platform.system()


# ── SSH known_hosts analysis ──────────────────────────────────────────────────

def _check_known_hosts() -> List[Dict]:
    """Parse known_hosts for external hosts."""
    findings = []
    if PLATFORM == "Windows":
        return findings

    known_hosts_paths = glob.glob(os.path.expanduser("~/.ssh/known_hosts"))
    known_hosts_paths += glob.glob("/root/.ssh/known_hosts")
    for home in glob.glob("/home/*"):
        p = os.path.join(home, ".ssh", "known_hosts")
        if os.path.exists(p):
            known_hosts_paths.append(p)

    external_hosts = set()
    for kh_path in known_hosts_paths:
        try:
            with open(kh_path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    host = line.split()[0].lstrip("[").split("]")[0]
                    # Hashed entries start with |1|
                    if host.startswith("|"):
                        continue
                    is_private = any(host.startswith(p) for p in
                                     ("127.", "10.", "192.168.", "172.", "::1", "localhost"))
                    if not is_private:
                        external_hosts.add(host)
        except (PermissionError, FileNotFoundError):
            continue

    if external_hosts:
        host_list = ", ".join(sorted(external_hosts)[:15])
        suffix = f" (+{len(external_hosts)-15} more)" if len(external_hosts) > 15 else ""
        findings.append({
            "check": "External SSH known_hosts entries",
            "detail": (
                f"SSH known_hosts contains {len(external_hosts)} external host(s): "
                f"{host_list}{suffix}. Review for unauthorized lateral movement history."
            ),
            "severity": "MEDIUM",
            "technique": "T1021.004",
        })

    return findings


# ── authorized_keys analysis ──────────────────────────────────────────────────

def _check_authorized_keys() -> List[Dict]:
    findings = []
    if PLATFORM == "Windows":
        return findings

    ak_paths = glob.glob("/root/.ssh/authorized_keys")
    for home in glob.glob("/home/*"):
        p = os.path.join(home, ".ssh", "authorized_keys")
        if os.path.exists(p):
            ak_paths.append(p)

    for ak_path in ak_paths:
        try:
            with open(ak_path) as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            if not lines:
                continue

            key_count = len(lines)
            # Check for unusual key types or options
            for line in lines:
                if line.startswith("command=") or line.startswith("no-"):
                    findings.append({
                        "check": f"Restricted SSH key in {ak_path}",
                        "detail": f"authorized_keys entry has forced command/restriction: {truncate(line, 80)}",
                        "severity": "MEDIUM",
                        "technique": "T1098.004",
                    })
                if "ecdsa-sk" in line or "sk-" in line.lower():
                    continue   # Security keys are fine
                if "from=" in line:
                    findings.append({
                        "check": f"Source-restricted key: {ak_path}",
                        "detail": f"Key with 'from=' restriction (may indicate targeted persistence): {truncate(line, 80)}",
                        "severity": "LOW",
                        "technique": "T1098.004",
                    })

            if key_count > 3:
                findings.append({
                    "check": f"Many authorized_keys: {ak_path}",
                    "detail": (
                        f"File '{ak_path}' contains {key_count} authorized keys. "
                        "Large key counts may indicate backdoor persistence."
                    ),
                    "severity": "MEDIUM" if key_count <= 10 else "HIGH",
                    "technique": "T1098.004",
                })

            # World-readable authorized_keys
            try:
                import stat as st_module
                stinfo = os.stat(ak_path)
                if stinfo.st_mode & st_module.S_IROTH:
                    findings.append({
                        "check": f"World-readable authorized_keys: {ak_path}",
                        "detail": f"'{ak_path}' is world-readable — all local users can see authorized keys.",
                        "severity": "HIGH",
                        "technique": "T1552.004",
                    })
            except Exception:
                pass

        except (PermissionError, FileNotFoundError):
            continue

    return findings


# ── Recent logins (last / wtmp) ───────────────────────────────────────────────

def _check_recent_logins() -> List[Dict]:
    findings = []
    if PLATFORM == "Windows":
        return _check_recent_logins_windows()

    try:
        out = subprocess.check_output(
            ["last", "-n", "20", "-F"],
            stderr=subprocess.DEVNULL, text=True, timeout=5,
        )
        external_logins = []
        for line in out.strip().splitlines():
            if not line or line.startswith("reboot") or line.startswith("wtmp"):
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            user = parts[0]
            tty  = parts[1]
            host = parts[2] if len(parts) > 2 else "?"

            # External IP login
            is_ip = re.match(r"\d+\.\d+\.\d+\.\d+", host)
            is_private = any(host.startswith(p) for p in ("127.", "10.", "192.168.", "172."))
            if is_ip and not is_private:
                external_logins.append(f"{user}@{host} (tty:{tty})")

        if external_logins:
            login_list = ", ".join(external_logins[:8])
            findings.append({
                "check": "External SSH logins detected",
                "detail": (
                    f"Recent logins from external IP addresses: {login_list}. "
                    "Verify all are authorized."
                ),
                "severity": "MEDIUM",
                "technique": "T1021.004",
            })
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        pass

    return findings


def _check_recent_logins_windows() -> List[Dict]:
    findings = []
    try:
        out = subprocess.check_output(
            ["powershell", "-Command",
             "Get-EventLog -LogName Security -InstanceId 4624,4625 -Newest 50 | "
             "Format-List TimeGenerated, EventID, Message"],
            stderr=subprocess.DEVNULL, text=True, timeout=10,
        )
        failed = out.count("4625")
        if failed > 5:
            findings.append({
                "check": "Multiple failed logins (Windows)",
                "detail": f"Detected {failed} recent failed login events (EventID 4625). Possible brute-force.",
                "severity": "HIGH",
                "technique": "T1078",
            })
    except Exception:
        pass
    return findings


# ── Shell history analysis ────────────────────────────────────────────────────

LATERAL_HISTORY_PATTERNS = [
    (r"ssh\s+(-[A-Za-z]+\s+)*\d+\.\d+\.\d+\.\d+", "SSH to external IP in history"),
    (r"scp\s+.*@\d+\.\d+\.\d+\.\d+", "SCP data transfer to external host"),
    (r"rsync\s+.*@", "rsync to remote host"),
    (r"ssh\s+-L\s+\d+:", "SSH local port forwarding"),
    (r"ssh\s+-R\s+\d+:", "SSH remote port forwarding"),
    (r"ssh\s+-D\s+\d+", "SSH dynamic port forwarding (SOCKS proxy)"),
    (r"ssh\s+-o\s+StrictHostKeyChecking=no", "SSH strict host checking disabled"),
    (r"ProxyJump|ProxyCommand", "SSH proxy jump / command in history"),
    (r"cat\s+.*authorized_keys", "Reading authorized_keys via history"),
    (r"echo\s+.*>>\s+.*authorized_keys", "Writing to authorized_keys"),
    (r"curl\s+.*\|\s*(bash|sh)", "Remote code execution via curl"),
    (r"wget\s+.*\|\s*(bash|sh)", "Remote code execution via wget"),
    (r"python.*http\.server|python.*SimpleHTTPServer", "Python HTTP server (file exfil)"),
]


def _check_shell_history() -> List[Dict]:
    findings = []
    if PLATFORM == "Windows":
        return findings

    history_paths = []
    for home_dir in [os.path.expanduser("~"), "/root"] + glob.glob("/home/*"):
        for hist_file in [".bash_history", ".zsh_history", ".sh_history", ".history"]:
            p = os.path.join(home_dir, hist_file)
            if os.path.exists(p):
                history_paths.append(p)

    for hist_path in history_paths:
        try:
            with open(hist_path, errors="replace") as f:
                content = f.read()
            for pattern, description in LATERAL_HISTORY_PATTERNS:
                matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                if matches:
                    sample = str(matches[0])[:80] if matches else ""
                    findings.append({
                        "check": f"History: {description}",
                        "detail": (
                            f"Found in '{hist_path}': {description}. "
                            f"Sample match: '{sample}'"
                        ),
                        "severity": "MEDIUM" if "forwarding" in description.lower() or "proxy" in description.lower() else "HIGH"
                                    if "authorized_keys" in description.lower() else "MEDIUM",
                        "technique": "T1021.004",
                    })
        except (PermissionError, FileNotFoundError):
            continue

    return findings


# ── Active SSH sessions ───────────────────────────────────────────────────────

def _check_active_ssh_sessions() -> List[Dict]:
    findings = []
    if PLATFORM == "Windows":
        return findings

    try:
        out = subprocess.check_output(
            ["who"], stderr=subprocess.DEVNULL, text=True, timeout=3,
        )
        sessions = []
        for line in out.strip().splitlines():
            parts = line.split()
            if len(parts) >= 5:
                host = parts[-1].strip("()")
                is_remote = re.match(r"\d+\.\d+\.\d+\.\d+", host) or ("." in host and not host.startswith("127"))
                if is_remote:
                    sessions.append(f"{parts[0]}@{host}")
        if sessions:
            session_list = ", ".join(sessions[:6])
            findings.append({
                "check": "Active remote SSH sessions",
                "detail": (
                    f"{len(sessions)} active SSH session(s) from remote hosts: {session_list}. "
                    "Verify all sessions are authorized."
                ),
                "severity": "LOW" if len(sessions) <= 2 else "MEDIUM",
                "technique": "T1021.004",
            })
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return findings


# ── Display ──────────────────────────────────────────────────────────────────

def _display(all_findings: List[Dict]) -> None:
    from ..banner import section
    section("Lateral Movement Detector — SSH & Credential Analysis", "[+]")
    print(f"  {dim('Check'):<48}{dim('Severity'):<18}{dim('Detail')}")
    print(f"  {dim(rule(105))}")

    if not all_findings:
        print(f"  {green('No lateral movement indicators detected.')}")
        return

    for f in all_findings:
        badge = severity_badge(f["severity"])
        check_disp  = truncate(f["check"], 46)
        detail_disp = truncate(f["detail"], 65)
        color = red if f["severity"] in ("CRITICAL","HIGH") else yellow
        print(f"  {color(check_disp):<57}{badge:<27}{dim(detail_disp)}")

    print(dim(f"\n  [{len(all_findings)} lateral movement indicator(s) found]"))


# ── Main module entry ─────────────────────────────────────────────────────────

def run(engine: AlertEngine) -> List[Dict]:
    all_findings: List[Dict] = []

    all_findings += _check_known_hosts()
    all_findings += _check_authorized_keys()
    all_findings += _check_recent_logins()
    all_findings += _check_shell_history()
    all_findings += _check_active_ssh_sessions()

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_findings.sort(key=lambda x: order.get(x.get("severity","LOW"), 9))

    for f in all_findings:
        technique_id = f.get("technique", "T1021.004")
        engine.add(make_alert(
            title=f"Lateral Movement: {f['check']}",
            description=f["detail"],
            severity=f["severity"],
            category="LATERAL_MOVEMENT",
            technique=mitre.get(technique_id),
            source="lateral_movement",
        ))

    _display(all_findings)
    return all_findings
