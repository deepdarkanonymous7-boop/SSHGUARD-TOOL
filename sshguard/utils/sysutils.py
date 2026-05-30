import os
import glob
import stat
import platform
import subprocess
import datetime
from typing import Optional, List, Dict


PLATFORM = platform.system()   # Linux | Windows | Darwin




def get_process_name(pid: str) -> str:
    try:
        if PLATFORM == "Windows":
            out = subprocess.check_output(
                ["tasklist", "/fi", f"PID eq {pid}", "/fo", "csv", "/nh"],
                stderr=subprocess.DEVNULL, text=True, timeout=3,
            )
            parts = out.strip().split(",")
            return parts[0].strip('"') if parts else "unknown"
        elif PLATFORM == "Darwin":
            out = subprocess.check_output(
                ["ps", "-p", pid, "-o", "comm="],
                stderr=subprocess.DEVNULL, text=True, timeout=3,
            )
            return out.strip() or "unknown"
        else:
            comm = f"/proc/{pid}/comm"
            if os.path.exists(comm):
                with open(comm) as f:
                    return f.read().strip()
            cmdline = f"/proc/{pid}/cmdline"
            if os.path.exists(cmdline):
                with open(cmdline, "rb") as f:
                    return f.read().split(b"\x00")[0].decode(errors="replace")
    except Exception:
        pass
    return "unknown"


def get_process_cmdline(pid: str) -> str:
    try:
        if PLATFORM == "Darwin":
            out = subprocess.check_output(
                ["ps", "-p", pid, "-o", "command="],
                stderr=subprocess.DEVNULL, text=True, timeout=3,
            )
            return out.strip()
        elif PLATFORM != "Windows":
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                return f.read().replace(b"\x00", b" ").decode(errors="replace").strip()
        else:
            out = subprocess.check_output(
                ["wmic", "process", "where", f"ProcessId={pid}", "get", "CommandLine", "/format:value"],
                stderr=subprocess.DEVNULL, text=True, timeout=5,
            )
            for line in out.splitlines():
                if line.startswith("CommandLine="):
                    return line.split("=", 1)[1].strip()
    except Exception:
        pass
    return ""


def get_process_user(pid: str) -> str:
    try:
        if PLATFORM == "Darwin":
            out = subprocess.check_output(
                ["ps", "-p", pid, "-o", "user="],
                stderr=subprocess.DEVNULL, text=True, timeout=3,
            )
            return out.strip() or "unknown"
        elif PLATFORM != "Windows":
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
    return os.environ.get("USERNAME", os.environ.get("USER", "unknown"))


def get_process_parent(pid: str) -> Optional[str]:
    try:
        if PLATFORM == "Darwin":
            out = subprocess.check_output(
                ["ps", "-p", pid, "-o", "ppid="],
                stderr=subprocess.DEVNULL, text=True, timeout=3,
            )
            return out.strip() or None
        elif PLATFORM != "Windows":
            with open(f"/proc/{pid}/status") as f:
                for line in f:
                    if line.startswith("PPid:"):
                        return line.split()[1]
    except Exception:
        pass
    return None


def list_pids() -> List[str]:
    if PLATFORM == "Darwin":
        try:
            out = subprocess.check_output(
                ["ps", "-e", "-o", "pid="],
                stderr=subprocess.DEVNULL, text=True, timeout=5,
            )
            return [p.strip() for p in out.strip().splitlines() if p.strip().isdigit()]
        except Exception:
            return []
    elif PLATFORM != "Windows":
        return [
            d for d in os.listdir("/proc")
            if d.isdigit() and os.path.isdir(f"/proc/{d}")
        ]
    try:
        out = subprocess.check_output(
            ["tasklist", "/fo", "csv", "/nh"],
            stderr=subprocess.DEVNULL, text=True, timeout=10,
        )
        pids = []
        for line in out.strip().splitlines():
            parts = line.split(",")
            if len(parts) >= 2:
                pids.append(parts[1].strip('"'))
        return pids
    except Exception:
        return []


def get_all_processes() -> List[Dict]:
    procs = []
    if PLATFORM == "Darwin":
        try:
            out = subprocess.check_output(
                ["ps", "-e", "-o", "pid=,ppid=,user=,pcpu=,rss=,comm="],
                stderr=subprocess.DEVNULL, text=True, timeout=10,
            )
            for line in out.strip().splitlines():
                parts = line.split(None, 5)
                if len(parts) < 6:
                    continue
                pid, ppid, user, cpu, rss, name = parts
                cmd = get_process_cmdline(pid)
                procs.append({
                    "pid": pid, "name": name.strip(), "user": user,
                    "cmd": cmd, "ppid": ppid,
                    "cpu": float(cpu) if cpu.replace(".", "").isdigit() else 0.0,
                    "mem_kb": int(rss) if rss.isdigit() else 0,
                })
        except Exception:
            pass
    elif PLATFORM != "Windows":
        for pid in list_pids():
            try:
                name = get_process_name(pid)
                user = get_process_user(pid)
                cmd  = get_process_cmdline(pid)
                ppid = get_process_parent(pid)

                # CPU/mem from /proc/PID/stat
                cpu_pct = 0.0
                mem_kb  = 0
                try:
                    with open(f"/proc/{pid}/stat") as f:
                        parts = f.read().split()
                    utime = int(parts[13]) if len(parts) > 13 else 0
                    stime = int(parts[14]) if len(parts) > 14 else 0
                    rss   = int(parts[23]) if len(parts) > 24 else 0
                    cpu_pct = round((utime + stime) / max(os.sysconf("SC_CLK_TCK"), 1), 2)
                    mem_kb  = rss * os.sysconf("SC_PAGE_SIZE") // 1024
                except Exception:
                    pass

                procs.append({
                    "pid": pid, "name": name, "user": user,
                    "cmd": cmd, "ppid": ppid or "?",
                    "cpu": cpu_pct, "mem_kb": mem_kb,
                })
            except Exception:
                continue
    else:
        try:
            out = subprocess.check_output(
                ["wmic", "process", "get",
                 "ProcessId,Name,CommandLine,ParentProcessId,WorkingSetSize", "/format:csv"],
                stderr=subprocess.DEVNULL, text=True, timeout=15,
            )
            for line in out.strip().splitlines()[2:]:
                parts = line.split(",")
                if len(parts) < 5:
                    continue
                procs.append({
                    "pid":   parts[4].strip(),
                    "name":  parts[2].strip(),
                    "user":  os.environ.get("USERNAME", "SYSTEM"),
                    "cmd":   parts[1].strip(),
                    "ppid":  parts[3].strip(),
                    "cpu":   0.0,
                    "mem_kb": int(parts[0].strip() or 0) // 1024,
                })
        except Exception:
            pass
    return procs


# ── Network helpers ──────────────────────────────────────────────────────────

def get_network_connections() -> List[Dict]:
    conns = []
    if PLATFORM != "Windows":
        # Try ss first (more reliable)
        try:
            out = subprocess.check_output(
                ["ss", "-tupnH"], stderr=subprocess.DEVNULL, text=True, timeout=5,
            )
            for line in out.strip().splitlines():
                parts = line.split()
                if len(parts) < 5:
                    continue
                proto = parts[0]
                state = parts[1]
                local = parts[4] if len(parts) > 4 else "?"
                peer  = parts[5] if len(parts) > 5 else "*"
                pid_info = " ".join(parts[6:]) if len(parts) > 6 else ""
                pid, proc = _parse_ss_pid_info(pid_info)
                conns.append({
                    "proto": proto, "state": state, "local": local,
                    "peer": peer, "pid": pid, "proc": proc,
                })
        except FileNotFoundError:
            _fallback_netstat_linux(conns)
        except Exception:
            _fallback_netstat_linux(conns)
    else:
        try:
            out = subprocess.check_output(
                ["netstat", "-nao"], stderr=subprocess.DEVNULL, text=True, timeout=10,
            )
            for line in out.strip().splitlines()[4:]:
                parts = line.split()
                if len(parts) < 4:
                    continue
                pid  = parts[4] if len(parts) > 4 else "?"
                proc = get_process_name(pid) if pid.isdigit() else "?"
                conns.append({
                    "proto": parts[0], "local": parts[1], "peer": parts[2],
                    "state": parts[3], "pid": pid, "proc": proc,
                })
        except Exception:
            pass
    return conns


def _parse_ss_pid_info(info: str):
    pid, proc = "", ""
    for chunk in info.replace("(", "").replace(")", "").split(","):
        chunk = chunk.strip()
        if chunk.startswith("pid="):
            pid = chunk.split("=")[1]
        if chunk.startswith('"') or chunk.startswith("users:"):
            proc = chunk.strip('"').replace("users:", "")
    return pid, proc


def _fallback_netstat_linux(conns):
    try:
        out = subprocess.check_output(
            ["netstat", "-tupn"], stderr=subprocess.DEVNULL, text=True, timeout=5,
        )
        for line in out.strip().splitlines()[2:]:
            parts = line.split()
            if len(parts) < 6:
                continue
            pid_proc = parts[-1] if "/" in parts[-1] else "-/-"
            pid, proc = (pid_proc.split("/", 1) + ["?"])[:2]
            conns.append({
                "proto": parts[0], "state": parts[5] if len(parts) > 5 else "?",
                "local": parts[3], "peer": parts[4],
                "pid": pid, "proc": proc.strip(),
            })
    except Exception:
        pass


# ── File helpers ─────────────────────────────────────────────────────────────

def file_owner(path: str) -> str:
    try:
        st = os.stat(path)
        try:
            import pwd
            return pwd.getpwuid(st.st_uid).pw_name
        except Exception:
            return str(st.st_uid)
    except Exception:
        return "unknown"


def file_permissions(path: str) -> str:
    try:
        st = os.stat(path)
        return oct(stat.S_IMODE(st.st_mode))
    except Exception:
        return "?"


def file_mtime(path: str) -> str:
    try:
        t = os.path.getmtime(path)
        return datetime.datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "N/A"


def is_suid(path: str) -> bool:
    try:
        return bool(os.stat(path).st_mode & stat.S_ISUID)
    except Exception:
        return False


# ── Misc ──────────────────────────────────────────────────────────────────────

def uptime_str() -> str:
    try:
        if PLATFORM == "Darwin":
            out = subprocess.check_output(
                ["sysctl", "-n", "kern.boottime"],
                stderr=subprocess.DEVNULL, text=True, timeout=3,
            )
            # Output: { sec = 1234567890, usec = 0 } ...
            import re
            match = re.search(r"sec\s*=\s*(\d+)", out)
            if match:
                boot_ts = int(match.group(1))
                seconds = datetime.datetime.now().timestamp() - boot_ts
            else:
                return "N/A"
        elif PLATFORM != "Windows":
            with open("/proc/uptime") as f:
                seconds = float(f.read().split()[0])
        else:
            import ctypes
            seconds = ctypes.windll.kernel32.GetTickCount64() / 1000  # type: ignore[attr-defined]  # noqa: F821
        d = int(seconds // 86400)
        h = int((seconds % 86400) // 3600)
        m = int((seconds % 3600) // 60)
        s = int(seconds % 60)
        parts = []
        if d: parts.append(f"{d}d")
        if h: parts.append(f"{h}h")
        if m: parts.append(f"{m}m")
        parts.append(f"{s}s")
        return " ".join(parts)
    except Exception:
        return "N/A"


def current_user() -> str:
    try:
        if PLATFORM != "Windows":
            import pwd
            return pwd.getpwuid(os.getuid()).pw_name
        return os.environ.get("USERNAME", "unknown")
    except Exception:
        return "unknown"


def hostname() -> str:
    try:
        import socket
        return socket.gethostname()
    except Exception:
        return "unknown"