"""
Network Connection Inspector
Analyses active network connections for C2 channels, suspicious ports,
unexpected outbound tunnels, and lateral movement indicators.
MITRE ATT&CK: T1571, T1041, T1021.004
"""

import re
import socket
import platform
from typing import List, Dict, Tuple

from ..utils.sysutils import get_network_connections
from ..utils.colors import (
    green, red, yellow, cyan, magenta, dim, bold, white,
    severity_badge, rule, truncate,
)
from ..engine.alert import AlertEngine, make_alert
from ..intel import ioc, mitre

PLATFORM = platform.system()

_DNS_CACHE: Dict[str, str] = {}


def _reverse_dns(ip: str) -> str:
    if not ip or ip in ("*", "0.0.0.0", "::", "::1"):
        return ""
    if ip in _DNS_CACHE:
        return _DNS_CACHE[ip]
    try:
        name = socket.gethostbyaddr(ip)[0]
        _DNS_CACHE[ip] = name
        return name
    except Exception:
        _DNS_CACHE[ip] = ""
        return ""


def _is_private(ip: str) -> bool:
    if not ip:
        return True
    for prefix in ("127.", "10.", "192.168.", "172.", "::1", "fe80", "0.0.0.0", "*"):
        if ip.startswith(prefix):
            return True
    return ip in ("", "*", "::")


def _extract_ip_port(addr: str) -> Tuple[str, int]:
    """Handle both IPv4 and IPv6 address strings like [::1]:8080 or 1.2.3.4:80."""
    if not addr or addr in ("*", "-"):
        return "", 0
    try:
        if addr.startswith("["):
            # IPv6: [::1]:port
            ip = addr.split("]")[0].lstrip("[")
            port_str = addr.split("]")[-1].lstrip(":")
        elif addr.count(":") == 1:
            ip, port_str = addr.rsplit(":", 1)
        else:
            # Pure IPv6 without port, or unknown format
            return addr, 0
        return ip, int(port_str) if port_str.isdigit() else 0
    except Exception:
        return addr, 0


def _assess_connection(conn: Dict) -> Tuple[str, List[str]]:
    flags = []
    risk  = "LOW"

    local_ip,  local_port  = _extract_ip_port(conn.get("local", ""))
    remote_ip, remote_port = _extract_ip_port(conn.get("peer",  ""))
    state = conn.get("state", "")

    # Suspicious remote port
    if remote_port in ioc.SUSPICIOUS_REMOTE_PORTS:
        flags.append(f"SUSPICIOUS_REMOTE_PORT:{remote_port}")
        risk = "CRITICAL"

    # Suspicious local listener
    if local_port in ioc.SUSPICIOUS_LOCAL_PORTS and state in ("LISTEN", "UNCONN"):
        flags.append(f"SUSPICIOUS_LOCAL_LISTENER:{local_port}")
        risk = "CRITICAL"

    # External established connection
    if not _is_private(remote_ip) and remote_ip and state == "ESTABLISHED":
        flags.append("EXTERNAL_CONN")
        if risk == "LOW":
            risk = "MEDIUM"

    # SSH outbound
    if remote_port == 22 and state == "ESTABLISHED":
        flags.append("SSH_OUTBOUND")
        if risk == "LOW":
            risk = "MEDIUM"

    # SSH inbound listener
    if local_port == 22 and state == "LISTEN":
        flags.append("SSH_LISTENER")

    # Unencrypted Telnet
    if remote_port == 23 or local_port == 23:
        flags.append("TELNET")
        if risk in ("LOW", "MEDIUM"):
            risk = "HIGH"

    # Reverse shell indicators — high remote port, established, external
    if (remote_port > 10000 and not _is_private(remote_ip)
            and state == "ESTABLISHED" and remote_port not in (443, 8443, 8080)):
        flags.append("HIGH_PORT_OUTBOUND")
        if risk == "LOW":
            risk = "MEDIUM"

    # Known malicious IP check
    for bad_ip in ioc.MALICIOUS_IPS:
        if remote_ip == bad_ip or remote_ip.startswith(bad_ip.split("/")[0].rsplit(".", 1)[0]):
            flags.append("KNOWN_MALICIOUS_IP")
            risk = "CRITICAL"
            break

    return risk, flags


def _display(conns_data: List[Dict]) -> None:
    from ..banner import section
    section("Network Inspector — Connection Anomaly Detection", "[+]")
    print(
        f"  {dim('Proto'):<7}{dim('State'):<14}{dim('Local'):<24}"
        f"{dim('Remote'):<26}{dim('Proc/PID'):<22}{dim('Risk'):<18}{dim('Flags')}"
    )
    print(f"  {dim(rule(105))}")

    shown_low = 0
    for c in conns_data:
        risk  = c["risk"]
        flags = c["flags"]
        flag_str = " ".join(f"[{f}]" for f in flags[:3])
        local_disp  = truncate(c["conn"].get("local", "?"), 22)
        remote_disp = truncate(c["conn"].get("peer", "?"), 24)
        proc_disp   = truncate(
            f"{c['conn'].get('proc','?')}/{c['conn'].get('pid','?')}", 20
        )

        if risk == "LOW":
            if shown_low >= 8:
                continue
            print(
                f"  {dim(c['conn'].get('proto','?')):<7}"
                f"{dim(c['conn'].get('state','?')):<14}"
                f"{dim(local_disp):<24}{dim(remote_disp):<26}"
                f"{dim(proc_disp):<22}{severity_badge(risk):<27}{dim(flag_str)}"
            )
            shown_low += 1
        else:
            color = red if risk in ("CRITICAL", "HIGH") else yellow
            rdns = _reverse_dns(c["conn"].get("peer", "").rsplit(":", 1)[0])
            rdns_str = f" ({dim(rdns)})" if rdns else ""
            print(
                f"  {yellow(c['conn'].get('proto','?')):<7}"
                f"{color(c['conn'].get('state','?')):<23}"
                f"{cyan(local_disp):<24}{red(remote_disp)}{rdns_str}"
                + " " * max(0, 26 - len(remote_disp))
                + f"{white(proc_disp):<22}{severity_badge(risk):<27}{magenta(flag_str)}"
            )

    flagged = sum(1 for c in conns_data if c["risk"] != "LOW")
    print(dim(f"\n  [{len(conns_data)} connection(s) analysed, {flagged} flagged]"))


def run(engine: AlertEngine) -> List[Dict]:
    raw_conns = get_network_connections()
    conns_data = []

    for conn in raw_conns:
        risk, flags = _assess_connection(conn)
        entry = {"conn": conn, "risk": risk, "flags": flags}
        conns_data.append(entry)

        if risk in ("CRITICAL", "HIGH"):
            remote_ip, remote_port = _extract_ip_port(conn.get("peer", ""))
            local_ip,  local_port  = _extract_ip_port(conn.get("local", ""))
            rdns = _reverse_dns(remote_ip) if remote_ip else ""

            if "SUSPICIOUS_REMOTE_PORT" in " ".join(flags) or "SUSPICIOUS_LOCAL_LISTENER" in " ".join(flags):
                technique = mitre.get("T1571")
            elif "SSH_OUTBOUND" in flags:
                technique = mitre.get("T1021.004")
            elif "TELNET" in flags:
                technique = mitre.get("T1041")
            else:
                technique = mitre.get("T1041")

            pid_raw = conn.get("pid", "")
            engine.add(make_alert(
                title=f"Suspicious Connection: {conn.get('peer','?')} [{conn.get('state','?')}]",
                description=(
                    f"Process '{conn.get('proc','?')}' (PID {pid_raw}) has an "
                    f"{conn.get('state','?')} {conn.get('proto','TCP')} connection "
                    f"to {conn.get('peer','?')}"
                    + (f" [{rdns}]" if rdns else "")
                    + f". Flags: {', '.join(flags)}"
                ),
                severity=risk,
                category="NETWORK_ANOMALY",
                technique=technique,
                source="network_monitor",
                pid=int(pid_raw) if str(pid_raw).isdigit() else None,
            ))

    # Sort: flagged first
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    conns_data.sort(key=lambda x: order.get(x["risk"], 9))
    _display(conns_data)
    return conns_data
