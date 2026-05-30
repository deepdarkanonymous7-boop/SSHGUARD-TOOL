"""
Banner, section headers and display helpers.
"""

import datetime
import platform
import os
from .utils.colors import (
    bold, dim, green, red, yellow, cyan, magenta, white,
    severity_badge, rule, Col, _c,
)

BANNER_ART = r"""
   ██████  ██████  ██   ██  ██████  ██    ██  █████  ██████  ██████
  ██      ██      ██   ██ ██       ██    ██ ██   ██ ██   ██ ██   ██
  ███████ ███████ ███████ ██   ███ ██    ██ ███████ ██████  ██   ██
       ██      ██ ██   ██ ██    ██ ██    ██ ██   ██ ██   ██ ██   ██
  ██████  ██████  ██   ██  ██████   ██████  ██   ██ ██   ██ ██████
"""

VERSION = "v2.0"

def print_banner(username: str = "", hostname_str: str = "", uptime_str: str = ""):
    now = datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    os_str = f"{platform.system()} {platform.release()}"

    print(_c(Col.BGREEN + Col.BOLD, BANNER_ART))

    # Info row
    print(
        f"  {green('SSHGuard')} {dim(VERSION)}"
        f"  {dim('|')}  Advanced Defensive SSH & System Monitor"
    )
    print()
    cols = [
        ("Host",     hostname_str or platform.node()),
        ("User",     username),
        ("OS",       os_str),
        ("Uptime",   uptime_str),
        ("Time",     now),
    ]
    line = "  "
    for k, v in cols:
        if v:
            line += dim(f"{k}: ") + cyan(v) + "   "
    print(line)
    print()
    print(f"  {dim(rule(74))}")
    print()


def section(title: str, icon: str = "[+]", color_fn=None) -> None:
    color_fn = color_fn or green
    print()
    print(f"  {color_fn(icon)} {bold(white(title))}")
    print(f"  {dim(rule(74))}")


def subsection(title: str) -> None:
    print(f"\n  {dim('›')} {cyan(title)}")


def print_alert_card(alert: dict) -> None:
    sev  = alert.get("severity", "MEDIUM")
    cat  = alert.get("category", "")
    tech = alert.get("technique", "")
    pid  = alert.get("pid")
    ts   = alert.get("timestamp", "")[:19].replace("T", " ")

    badge = severity_badge(sev)
    print(f"  {badge}  {bold(alert['title'])}")
    print(f"         {dim('→')} {alert['description']}")

    meta = []
    if cat:      meta.append(cyan(cat))
    if tech:     meta.append(magenta(tech))
    if pid:      meta.append(dim(f"PID:{pid}"))
    if ts:       meta.append(dim(ts))
    if meta:
        print(f"         {dim('|')} " + f"  {dim('|')}  ".join(meta))
    print()


def print_summary_box(alerts: list) -> None:
    critical = sum(1 for a in alerts if a.get("severity") == "CRITICAL")
    high     = sum(1 for a in alerts if a.get("severity") == "HIGH")
    medium   = sum(1 for a in alerts if a.get("severity") == "MEDIUM")
    low      = sum(1 for a in alerts if a.get("severity") == "LOW")

    width = 52
    print()
    print(f"  {dim('┌' + '─' * width + '┐')}")
    print(f"  {dim('│')} {'THREAT SUMMARY':^{width}} {dim('│')}")
    print(f"  {dim('├' + '─' * width + '┤')}")

    rows = [
        (red("CRITICAL"), str(critical)),
        (yellow("HIGH    "), str(high)),
        (cyan("MEDIUM  "), str(medium)),
        (green("LOW     "), str(low)),
    ]
    for label, val in rows:
        bar = "█" * int(val) if int(val) < 40 else "█" * 39 + "+"
        print(f"  {dim('│')}  {label}  {bold(val.rjust(3))}   {dim(bar):<40} {dim('│')}")

    print(f"  {dim('├' + '─' * width + '┤')}")
    total = len(alerts)
    overall = "CLEAN" if total == 0 else ("CRITICAL" if critical else ("HIGH" if high else "MEDIUM"))
    color_fn = green if overall == "CLEAN" else (red if overall in ("CRITICAL","HIGH") else yellow)
    print(f"  {dim('│')}  {'Overall Status':<20}  {color_fn(overall):<38} {dim('│')}")
    print(f"  {dim('└' + '─' * width + '┘')}")
    print()


def print_footer(scan_duration: float = 0.0) -> None:
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"  {dim(rule(74))}")
    print(f"  {dim(f'SSHGuard {VERSION}  ·  Scan completed at {ts}  ·  Duration: {scan_duration:.2f}s')}")
    print(f"  {dim('For defensive / educational use only. Unauthorized use is illegal.')}")
    print()
