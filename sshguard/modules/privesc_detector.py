"""
Privilege Escalation Detector
Checks for sudo misconfigurations, writable system paths,
PATH hijacking opportunities, cron-based privesc, capabilities,
and LD_PRELOAD abuse vectors.
MITRE ATT&CK: T1548.003, T1053.003, T1574.006
"""

import os
import re
import glob
import stat
import platform
import subprocess
from typing import List, Dict, Tuple

from ..utils.colors import (
    green, red, yellow, cyan, magenta, dim, bold, white,
    severity_badge, rule, truncate,
)
from ..engine.alert import AlertEngine, make_alert
from ..intel import ioc, mitre

PLATFORM = platform.system()


# ── Sudo analysis ─────────────────────────────────────────────────────────────

def _check_sudo() -> List[Dict]:
    findings = []
    if PLATFORM == "Windows":
        return findings

    # Try sudo -l (non-interactive)
    try:
        out = subprocess.check_output(
            ["sudo", "-l", "-n"],
            stderr=subprocess.STDOUT, text=True, timeout=5,
        )
        for pattern in ioc.DANGEROUS_SUDO_PATTERNS:
            if pattern.lower() in out.lower():
                findings.append({
                    "check": "sudo misconfiguration",
                    "detail": f"Dangerous sudo rule detected: '{pattern}'",
                    "severity": "CRITICAL",
                    "technique": "T1548.003",
                })

        if "NOPASSWD" in out:
            findings.append({
                "check": "sudo NOPASSWD",
                "detail": "Current user can run sudo commands without a password.",
                "severity": "HIGH",
                "technique": "T1548.003",
            })
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # /etc/sudoers direct read
    for sudoers_path in ["/etc/sudoers"] + glob.glob("/etc/sudoers.d/*"):
        try:
            with open(sudoers_path) as f:
                content = f.read()
            for pattern in ioc.DANGEROUS_SUDO_PATTERNS:
                if pattern.lower() in content.lower():
                    # exclude comment lines
                    for line in content.splitlines():
                        if pattern.lower() in line.lower() and not line.strip().startswith("#"):
                            findings.append({
                                "check": f"sudoers: {os.path.basename(sudoers_path)}",
                                "detail": f"Dangerous rule in {sudoers_path}: {line.strip()[:100]}",
                                "severity": "CRITICAL",
                                "technique": "T1548.003",
                            })
                            break
        except (PermissionError, FileNotFoundError):
            pass

    return findings


# ── Cron analysis ─────────────────────────────────────────────────────────────

def _check_cron() -> List[Dict]:
    findings = []
    if PLATFORM == "Windows":
        return findings

    cron_paths = [
        "/etc/crontab",
        "/etc/cron.d/*",
        "/etc/cron.daily/*",
        "/etc/cron.hourly/*",
        "/etc/cron.weekly/*",
        "/var/spool/cron/*",
        "/var/spool/cron/crontabs/*",
    ]

    for pattern in cron_paths:
        for path in glob.glob(pattern):
            try:
                st = os.stat(path)
                # World-writable cron file
                if stat.S_IWOTH & st.st_mode:
                    findings.append({
                        "check": f"world-writable cron: {path}",
                        "detail": f"Cron file '{path}' is world-writable — can be modified for persistence/privesc.",
                        "severity": "CRITICAL",
                        "technique": "T1053.003",
                    })
                    continue

                with open(path) as f:
                    content = f.read()

                for line in content.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("#") or not stripped:
                        continue
                    # Check if the script being called is writable by others
                    parts = stripped.split()
                    for part in parts:
                        if os.path.isabs(part) and os.path.isfile(part):
                            try:
                                fst = os.stat(part)
                                if fst.st_mode & stat.S_IWOTH:
                                    findings.append({
                                        "check": f"writable cron script: {part}",
                                        "detail": (
                                            f"Cron job in '{path}' calls world-writable script '{part}'. "
                                            "Any user can modify this script and run code as the cron user."
                                        ),
                                        "severity": "CRITICAL",
                                        "technique": "T1053.003",
                                    })
                            except (PermissionError, FileNotFoundError):
                                pass
            except (PermissionError, FileNotFoundError):
                continue

    return findings


# ── PATH hijacking ────────────────────────────────────────────────────────────

def _check_path_hijacking() -> List[Dict]:
    findings = []
    if PLATFORM == "Windows":
        return findings

    path_dirs = os.environ.get("PATH", "").split(":")
    for d in path_dirs:
        if not d or not os.path.isdir(d):
            continue
        try:
            st = os.stat(d)
            # World-writable directory in PATH
            if st.st_mode & stat.S_IWOTH:
                findings.append({
                    "check": f"PATH hijacking: {d}",
                    "detail": (
                        f"Directory '{d}' in $PATH is world-writable. "
                        "An attacker can place a malicious binary here to intercept commands."
                    ),
                    "severity": "HIGH",
                    "technique": "T1574.006",
                })
            # Relative path in PATH (. or empty string)
            if d in (".", ""):
                findings.append({
                    "check": "relative PATH entry",
                    "detail": f"$PATH contains a relative entry ('{d}') — trivially exploitable for PATH hijacking.",
                    "severity": "CRITICAL",
                    "technique": "T1574.006",
                })
        except PermissionError:
            continue

    return findings


# ── LD_PRELOAD / ld.so.preload ────────────────────────────────────────────────

def _check_ld_preload() -> List[Dict]:
    findings = []
    if PLATFORM == "Windows":
        return findings

    # Environment-based
    ld_preload = os.environ.get("LD_PRELOAD", "")
    if ld_preload:
        findings.append({
            "check": "LD_PRELOAD set",
            "detail": f"LD_PRELOAD is set to: '{ld_preload}'. This can be used for shared library injection.",
            "severity": "HIGH",
            "technique": "T1574.006",
        })

    # /etc/ld.so.preload
    ld_so = "/etc/ld.so.preload"
    if os.path.exists(ld_so):
        try:
            with open(ld_so) as f:
                content = f.read().strip()
            if content:
                findings.append({
                    "check": "/etc/ld.so.preload not empty",
                    "detail": (
                        f"'/etc/ld.so.preload' exists and is non-empty: '{content[:80]}'. "
                        "This is a known rootkit / library injection indicator."
                    ),
                    "severity": "CRITICAL",
                    "technique": "T1574.006",
                })
        except PermissionError:
            pass

    return findings


# ── Linux capabilities ────────────────────────────────────────────────────────

def _check_capabilities() -> List[Dict]:
    findings = []
    if PLATFORM == "Windows":
        return findings

    try:
        out = subprocess.check_output(
            ["getcap", "-r", "/usr", "/bin", "/sbin"],
            stderr=subprocess.DEVNULL, text=True, timeout=10,
        )
        dangerous_caps = {"cap_setuid", "cap_setgid", "cap_dac_override",
                          "cap_sys_admin", "cap_net_raw", "cap_chown"}
        for line in out.strip().splitlines():
            lower_line = line.lower()
            for cap in dangerous_caps:
                if cap in lower_line:
                    findings.append({
                        "check": f"dangerous capability: {line.split()[0]}",
                        "detail": (
                            f"Binary '{line.split()[0]}' has dangerous Linux capability '{cap}' set. "
                            "Can be abused for privilege escalation."
                        ),
                        "severity": "HIGH",
                        "technique": "T1548.001",
                    })
                    break
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return findings


# ── History / HISTFILE ────────────────────────────────────────────────────────

def _check_history_evasion() -> List[Dict]:
    findings = []
    if PLATFORM == "Windows":
        return findings

    histfile = os.environ.get("HISTFILE", "")
    histsize = os.environ.get("HISTSIZE", "")
    histfilesize = os.environ.get("HISTFILESIZE", "")

    if histfile == "/dev/null":
        findings.append({
            "check": "HISTFILE=/dev/null",
            "detail": "Shell history is being discarded (HISTFILE=/dev/null). Possible anti-forensics.",
            "severity": "HIGH",
            "technique": "T1070.003",
        })
    if histsize == "0" or histfilesize == "0":
        findings.append({
            "check": "HISTSIZE=0 or HISTFILESIZE=0",
            "detail": "Shell history size set to 0 — commands are not being recorded.",
            "severity": "MEDIUM",
            "technique": "T1070.003",
        })

    return findings


# ── Display ──────────────────────────────────────────────────────────────────

def _display(all_findings: List[Dict]) -> None:
    from ..banner import section
    section("Privilege Escalation Detector", "[!]")
    print(f"  {dim('Check'):<45}{dim('Severity'):<18}{dim('Detail')}")
    print(f"  {dim(rule(105))}")

    if not all_findings:
        print(f"  {green('No privilege escalation vectors detected.')}")
        return

    for f in all_findings:
        badge = severity_badge(f["severity"])
        check_disp = truncate(f["check"], 43)
        detail_disp = truncate(f["detail"], 70)
        color = red if f["severity"] in ("CRITICAL","HIGH") else yellow
        print(f"  {color(check_disp):<54}{badge:<27}{dim(detail_disp)}")

    print(dim(f"\n  [{len(all_findings)} potential privilege escalation vector(s) found]"))


# ── Main module entry ─────────────────────────────────────────────────────────

def run(engine: AlertEngine) -> List[Dict]:
    all_findings: List[Dict] = []

    all_findings += _check_sudo()
    all_findings += _check_cron()
    all_findings += _check_path_hijacking()
    all_findings += _check_ld_preload()
    all_findings += _check_capabilities()
    all_findings += _check_history_evasion()

    # Sort critical first
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_findings.sort(key=lambda x: order.get(x.get("severity","LOW"), 9))

    for f in all_findings:
        technique_id = f.get("technique", "T1548.003")
        engine.add(make_alert(
            title=f"Privesc Vector: {f['check']}",
            description=f["detail"],
            severity=f["severity"],
            category="PRIVILEGE_ESCALATION",
            technique=mitre.get(technique_id),
            source="privesc_detector",
        ))

    _display(all_findings)
    return all_findings
