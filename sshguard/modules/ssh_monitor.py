"""
SSH Agent Socket Monitor
Detects live SSH agent sockets and identifies processes accessing them.
Defensive counterpart to SSHAgentJack / SSH hijacking attacks.
MITRE ATT&CK: T1563.001, T1552.004
"""

import os
import glob
import stat
import platform
import subprocess
from typing import List, Dict

from ..utils.colors import (
    green, red, yellow, cyan, magenta, dim, bold, white,
    severity_badge, rule, truncate,
)
from ..engine.alert import Alert, AlertEngine, make_alert
from ..intel import mitre

PLATFORM = platform.system()


# ── Socket discovery ─────────────────────────────────────────────────────────

def _find_sockets_linux() -> List[str]:
    sockets = []

    # Common search paths
    search_roots = ["/tmp", "/run/user", "/var/run"]
    home = os.path.expanduser("~")
    if home and home != "~":
        search_roots.append(os.path.join(home, ".ssh"))

    for base in search_roots:
        if not os.path.isdir(base):
            continue
        try:
            for root, dirs, files in os.walk(base):
                depth = root.count(os.sep) - base.count(os.sep)
                if depth >= 3:
                    dirs.clear()
                    continue
                for fname in files:
                    fpath = os.path.join(root, fname)
                    try:
                        st = os.stat(fpath)
                        if stat.S_ISSOCK(st.st_mode):
                            if fpath not in sockets:
                                sockets.append(fpath)
                    except (PermissionError, FileNotFoundError, OSError):
                        continue
        except PermissionError:
            continue

    # Glob patterns common to ssh-agent
    for pattern in [
        "/tmp/ssh-*/agent.*",
        "/run/user/*/ssh-agent.socket",
        "/run/user/*/keyring/ssh",
        "/tmp/.ssh-agent-*",
    ]:
        for match in glob.glob(pattern):
            if match not in sockets:
                sockets.append(match)

    return sockets


def _find_sockets_windows() -> List[str]:
    sockets = []
    pipe = r"\\.\pipe\openssh-ssh-agent"
    try:
        import win32file
        h = win32file.CreateFile(
            pipe, win32file.GENERIC_READ, 0, None,
            win32file.OPEN_EXISTING, 0, None,
        )
        win32file.CloseHandle(h)
        sockets.append(pipe)
    except Exception:
        if os.path.exists(pipe):
            sockets.append(pipe)
    return sockets


# ── Socket owner ─────────────────────────────────────────────────────────────

def _socket_owner(path: str) -> Dict:
    info = {"username": "unknown", "uid": -1, "permissions": "?", "size": 0}
    try:
        st = os.stat(path)
        info["uid"] = st.st_uid
        info["permissions"] = oct(stat.S_IMODE(st.st_mode))
        info["size"] = st.st_size
        try:
            import pwd
            info["username"] = pwd.getpwuid(st.st_uid).pw_name
        except Exception:
            info["username"] = str(st.st_uid)
    except Exception:
        pass
    return info


# ── Process access detection ─────────────────────────────────────────────────

def _accessing_pids(socket_path: str) -> List[Dict]:
    """Find PIDs that have open FDs pointing to this socket (Linux only)."""
    result = []
    seen = set()
    try:
        for fd_link in glob.glob("/proc/[0-9]*/fd/*"):
            try:
                target = os.readlink(fd_link)
                if socket_path in target:
                    pid = fd_link.split("/")[2]
                    if pid in seen:
                        continue
                    seen.add(pid)
                    name = _proc_name(pid)
                    user = _proc_user(pid)
                    cmd  = _proc_cmdline(pid)
                    result.append({"pid": pid, "name": name, "user": user, "cmdline": cmd})
            except (PermissionError, FileNotFoundError, OSError):
                continue
    except Exception:
        pass

    # Also use lsof as fallback/supplement if available
    try:
        out = subprocess.check_output(
            ["lsof", "-U", socket_path], stderr=subprocess.DEVNULL, text=True, timeout=3
        )
        for line in out.strip().splitlines()[1:]:
            parts = line.split()
            if len(parts) < 2:
                continue
            pid = parts[1]
            if pid not in seen:
                seen.add(pid)
                result.append({
                    "pid": pid,
                    "name": parts[0] if parts else "?",
                    "user": parts[2] if len(parts) > 2 else "?",
                    "cmdline": "",
                })
    except Exception:
        pass

    return result


def _proc_name(pid: str) -> str:
    try:
        with open(f"/proc/{pid}/comm") as f:
            return f.read().strip()
    except Exception:
        return "?"


def _proc_user(pid: str) -> str:
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("Uid:"):
                    uid = int(line.split()[1])
                    try:
                        import pwd
                        return pwd.getpwuid(uid).pw_name
                    except Exception:
                        return str(uid)
    except Exception:
        pass
    return "?"


def _proc_cmdline(pid: str) -> str:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read().replace(b"\x00", b" ").decode(errors="replace").strip()
    except Exception:
        return ""


# ── SSH key info ──────────────────────────────────────────────────────────────

def _detect_loaded_keys() -> List[Dict]:
    """Try to list keys loaded in ssh-agent via ssh-add -l."""
    keys = []
    try:
        out = subprocess.check_output(
            ["ssh-add", "-l"], stderr=subprocess.DEVNULL, text=True, timeout=3
        )
        for line in out.strip().splitlines():
            parts = line.split()
            if len(parts) >= 3:
                keys.append({
                    "bits":        parts[0],
                    "fingerprint": parts[1],
                    "comment":     " ".join(parts[2:]),
                    "type":        parts[-1].strip("()") if "(" in line else "unknown",
                })
    except Exception:
        pass
    return keys


# ── Risk assessment ──────────────────────────────────────────────────────────

def _assess_socket_risk(socket_path: str, owner: Dict, accessing: List[Dict]) -> str:
    if len(accessing) > 2:
        return "CRITICAL"
    if len(accessing) == 2:
        # Two PIDs accessing same socket — likely hijack
        return "HIGH"
    if owner.get("uid") == 0:
        return "HIGH"   # root-owned agent socket
    if "/dev/shm" in socket_path or "/tmp/." in socket_path:
        return "HIGH"
    return "LOW"


# ── Display ──────────────────────────────────────────────────────────────────

def _display(sockets_data: List[Dict]) -> None:
    from ..banner import section
    section("SSH Agent Socket Monitor", "[+]")
    print(
        f"  {dim('Socket Path'):<52}"
        f"  {dim('Owner'):<12}"
        f"  {dim('Risk'):<16}"
        f"  {dim('Accessing PIDs')}"
    )
    print(f"  {dim(rule(90))}")

    if not sockets_data:
        print(f"  {dim('No SSH agent sockets found on this system.')}")
        print(f"  {dim('Try: eval $(ssh-agent) && ssh-add')}")
        return

    for s in sockets_data:
        path_disp = truncate(s["path"], 50)
        owner     = s["owner"]["username"]
        risk      = s["risk"]
        badge     = severity_badge(risk)

        pids_disp = []
        for p in s["accessing"][:4]:
            pids_disp.append(f"{yellow(p['pid'])}({dim(p['name'])})")
        if len(s["accessing"]) > 4:
            pids_disp.append(dim(f"+{len(s['accessing'])-4} more"))
        pids_str = "  ".join(pids_disp) if pids_disp else dim("none")

        row_color = red if risk in ("CRITICAL", "HIGH") else (yellow if risk == "MEDIUM" else dim)
        print(f"  {row_color(path_disp):<61}  {cyan(owner):<12}  {badge:<25}  {pids_str}")

    # Loaded keys
    keys = _detect_loaded_keys()
    if keys:
        print()
        print(f"  {dim('Loaded SSH Keys:')}")
        for k in keys:
            print(f"    {green(k.get('fingerprint','?'))}  {dim(k.get('type','?'))}  {dim(k.get('comment',''))}")

    print(dim(f"\n  [{len(sockets_data)} socket(s) found]"))


# ── Main module entry ─────────────────────────────────────────────────────────

def run(engine: AlertEngine) -> List[Dict]:
    """Run SSH socket monitor. Returns list of socket data dicts."""
    if PLATFORM == "Windows":
        paths = _find_sockets_windows()
    else:
        paths = _find_sockets_linux()

    sockets_data = []
    for path in paths:
        owner     = _socket_owner(path)
        accessing = _accessing_pids(path) if PLATFORM != "Windows" else []
        risk      = _assess_socket_risk(path, owner, accessing)

        entry = {
            "path":      path,
            "owner":     owner,
            "accessing": accessing,
            "risk":      risk,
        }
        sockets_data.append(entry)

        # Generate alerts
        if len(accessing) > 1:
            pids = ", ".join(p["pid"] for p in accessing[:6])
            names = ", ".join(p["name"] for p in accessing[:4])
            engine.add(make_alert(
                title=f"SSH Agent Socket Hijack — {os.path.basename(path)}",
                description=(
                    f"Socket '{path}' (owner: {owner['username']}) is being accessed by "
                    f"{len(accessing)} concurrent processes: PIDs [{pids}] ({names}). "
                    "This is the signature of SSH agent hijacking / credential theft."
                ),
                severity="CRITICAL" if len(accessing) > 2 else "HIGH",
                category="SSH_HIJACK",
                technique=mitre.get("T1563.001"),
                source="ssh_monitor",
                pid=int(accessing[0]["pid"]) if accessing and accessing[0]["pid"].isdigit() else None,
                path=path,
            ))
        elif risk == "HIGH":
            engine.add(make_alert(
                title=f"High-Risk SSH Agent Socket",
                description=(
                    f"Socket '{path}' owned by root (uid=0) or in suspicious location. "
                    "Root-owned agent sockets can be leveraged for privilege escalation."
                ),
                severity="HIGH",
                category="SSH_HIJACK",
                technique=mitre.get("T1552.004"),
                source="ssh_monitor",
                path=path,
            ))

    _display(sockets_data)
    return sockets_data
