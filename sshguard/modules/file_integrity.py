"""
File Integrity Monitor (FIM)
SHA-256 + MD5 dual-hash baseline comparison for critical system files.
Detects modifications, missing files, unexpected permission changes,
and SUID/SGID anomalies.
MITRE ATT&CK: T1565.001, T1574.006, T1548.001
"""

import os
import glob
import json
import stat
import hashlib
import platform
import datetime
from typing import List, Dict, Optional, Tuple

from ..utils.colors import (
    green, red, yellow, cyan, magenta, dim, bold, white,
    severity_badge, status_badge, rule, truncate,
)
from ..engine.alert import AlertEngine, make_alert
from ..intel import ioc, mitre

PLATFORM = platform.system()


# ── Hashing ──────────────────────────────────────────────────────────────────

def _hash_file(path: str) -> Tuple[str, str]:
    """Return (sha256, md5) hex digests, or error strings."""
    sha = hashlib.sha256()
    md5 = hashlib.md5()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha.update(chunk)
                md5.update(chunk)
        return sha.hexdigest(), md5.hexdigest()
    except PermissionError:
        return "PERMISSION_DENIED", "PERMISSION_DENIED"
    except FileNotFoundError:
        return "MISSING", "MISSING"
    except Exception as e:
        return f"ERROR", f"ERROR"


# ── Baseline management ───────────────────────────────────────────────────────

def _load_baseline(path: str) -> Dict:
    if os.path.exists(path):
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_baseline(path: str, data: Dict) -> None:
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


# ── File metadata ─────────────────────────────────────────────────────────────

def _get_file_meta(path: str) -> Dict:
    meta = {
        "exists": False, "size": 0, "permissions": "?",
        "owner": "?", "mtime": "N/A",
        "is_suid": False, "is_sgid": False, "is_world_writable": False,
    }
    try:
        st = os.stat(path)
        meta["exists"]     = True
        meta["size"]       = st.st_size
        meta["permissions"] = oct(stat.S_IMODE(st.st_mode))
        meta["mtime"]      = datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        meta["is_suid"]    = bool(st.st_mode & stat.S_ISUID)
        meta["is_sgid"]    = bool(st.st_mode & stat.S_ISGID)
        meta["is_world_writable"] = bool(st.st_mode & stat.S_IWOTH)
        try:
            import pwd
            meta["owner"] = pwd.getpwuid(st.st_uid).pw_name
        except Exception:
            meta["owner"] = str(st.st_uid)
    except FileNotFoundError:
        meta["exists"] = False
    except PermissionError:
        meta["exists"] = True
        meta["permissions"] = "NO_ACCESS"
    return meta


# ── SUID/SGID binary scan ─────────────────────────────────────────────────────

def _find_suid_sgid_binaries(search_roots: List[str] = None) -> List[Dict]:
    if PLATFORM == "Windows":
        return []
    if search_roots is None:
        search_roots = ["/usr", "/bin", "/sbin", "/usr/local"]

    found = []
    for root in search_roots:
        if not os.path.isdir(root):
            continue
        try:
            for dirpath, _, filenames in os.walk(root):
                for fname in filenames:
                    fpath = os.path.join(dirpath, fname)
                    try:
                        st = os.stat(fpath)
                        if not (st.st_mode & (stat.S_ISUID | stat.S_ISGID)):
                            continue
                        is_expected = fpath in ioc.EXPECTED_SUID_BINARIES
                        found.append({
                            "path":        fpath,
                            "suid":        bool(st.st_mode & stat.S_ISUID),
                            "sgid":        bool(st.st_mode & stat.S_ISGID),
                            "permissions": oct(stat.S_IMODE(st.st_mode)),
                            "expected":    is_expected,
                        })
                    except (PermissionError, FileNotFoundError, OSError):
                        continue
        except PermissionError:
            continue
    return found


# ── Display ──────────────────────────────────────────────────────────────────

def _display(checks: List[Dict], suid_bins: List[Dict]) -> None:
    from ..banner import section

    # ── File integrity table
    section("File Integrity Monitor — Critical File Checksums", "[+]")
    print(
        f"  {dim('File Path'):<55}{dim('Status'):<14}"
        f"{dim('Perms'):<10}{dim('Owner'):<12}{dim('SHA256 (prefix)'):<20}{dim('Modified')}"
    )
    print(f"  {dim(rule(120))}")

    for c in checks:
        path_disp = truncate(c["path"], 53)
        status    = c["status"]
        sbadge    = status_badge(status)
        sev_color = red if status in ("MODIFIED", "MISSING") else (yellow if status == "NO ACCESS" else green)

        sha_disp = truncate(c.get("sha256", "?"), 18) if c.get("sha256") else "?"
        perms    = c["meta"].get("permissions", "?")
        owner    = c["meta"].get("owner", "?")
        mtime    = c["meta"].get("mtime", "N/A")

        # Flag world-writable / unexpected perms
        perm_warn = ""
        if c["meta"].get("is_world_writable"):
            perm_warn = red(" [WORLD-WRITABLE!]")
        elif c["meta"].get("is_suid"):
            perm_warn = yellow(" [SUID]")

        print(
            f"  {sev_color(path_disp):<64}"
            f"{sbadge:<23}"
            f"{dim(perms):<10}"
            f"{cyan(owner):<12}"
            f"{dim(sha_disp):<20}"
            f"{dim(mtime)}"
            f"{perm_warn}"
        )

    modified = sum(1 for c in checks if c["status"] == "MODIFIED")
    missing  = sum(1 for c in checks if c["status"] == "MISSING")

    if modified == 0 and missing == 0:
        print(f"\n  {green('[OK] All monitored files match their baseline.')}")
    else:
        if modified:
            print(f"\n  {red(f'[!!] {modified} file(s) have been MODIFIED since last scan!')}")
        if missing:
            print(f"  {yellow(f'[!]  {missing} expected file(s) are MISSING.')}")

    # ── SUID/SGID table
    unexpected = [b for b in suid_bins if not b["expected"]]
    if unexpected:
        print()
        section("SUID/SGID Anomaly Detection", "[!]")
        print(f"  {dim('Binary Path'):<55}{dim('SUID'):<8}{dim('SGID'):<8}{dim('Perms'):<12}{dim('Status')}")
        print(f"  {dim(rule(90))}")
        for b in unexpected[:20]:
            print(
                f"  {red(truncate(b['path'],53)):<63}"
                f"  {red('YES') if b['suid'] else dim('no'):<15}"
                f"  {yellow('YES') if b['sgid'] else dim('no'):<15}"
                f"  {dim(b['permissions']):<12}"
                f"  {red('[UNEXPECTED SUID/SGID]')}"
            )
        print(dim(f"\n  [{len(unexpected)} unexpected SUID/SGID binaries found]"))
    elif suid_bins:
        print(f"\n  {green('[OK] All SUID/SGID binaries are within expected whitelist.')}")


# ── Main module entry ─────────────────────────────────────────────────────────

def run(engine: AlertEngine, baseline_file: str, reset: bool = False, scan_suid: bool = True) -> List[Dict]:
    system   = PLATFORM if PLATFORM in ioc.CRITICAL_FILES else "Linux"
    file_defs = ioc.CRITICAL_FILES.get(system, [])
    baseline = {} if reset else _load_baseline(baseline_file)
    new_baseline = {}
    checks = []

    for fdef in file_defs:
        path      = fdef["path"]
        risk_def  = fdef["risk"]
        desc      = fdef["desc"]
        meta      = _get_file_meta(path)

        if not meta["exists"] and meta["permissions"] != "NO_ACCESS":
            sha256, md5 = "MISSING", "MISSING"
            status = "MISSING"
        elif meta["permissions"] == "NO_ACCESS":
            sha256, md5 = "NO_ACCESS", "NO_ACCESS"
            status = "NO ACCESS"
        else:
            sha256, md5 = _hash_file(path)
            if sha256 in ("ERROR", "PERMISSION_DENIED"):
                status = "NO ACCESS"
            elif path not in baseline:
                status = "NEW"
                new_baseline[path] = {"sha256": sha256, "md5": md5}
            elif baseline[path].get("sha256") != sha256:
                status = "MODIFIED"
                new_baseline[path] = {"sha256": sha256, "md5": md5}
            else:
                status = "OK"
                new_baseline[path] = baseline[path]

        # World-writable critical file is itself an issue
        if status == "OK" and meta.get("is_world_writable"):
            status = "MODIFIED"   # treat as modified for alerting purposes

        entry = {
            "path": path, "status": status, "sha256": sha256,
            "md5": md5, "meta": meta, "risk": risk_def, "desc": desc,
        }
        checks.append(entry)

        # Generate alerts
        if status == "MODIFIED":
            old_sha = baseline.get(path, {}).get("sha256", "unknown")
            engine.add(make_alert(
                title=f"File Modified: {os.path.basename(path)}",
                description=(
                    f"Critical file '{path}' ({desc}) has been modified. "
                    f"Old hash: {old_sha[:16]}... → New hash: {sha256[:16]}..."
                    + (" [WORLD-WRITABLE permissions detected]" if meta.get("is_world_writable") else "")
                ),
                severity="CRITICAL",
                category="FILE_INTEGRITY",
                technique=mitre.get("T1565.001"),
                source="file_integrity",
                path=path,
            ))
        elif status == "MISSING":
            engine.add(make_alert(
                title=f"Critical File Missing: {os.path.basename(path)}",
                description=f"Expected critical file '{path}' ({desc}) is missing or has been deleted.",
                severity="HIGH" if risk_def in ("CRITICAL","HIGH") else "MEDIUM",
                category="FILE_INTEGRITY",
                technique=mitre.get("T1565.001"),
                source="file_integrity",
                path=path,
            ))

    # Persist updated baseline
    if new_baseline:
        merged = {**baseline, **new_baseline}
        _save_baseline(baseline_file, merged)

    # SUID/SGID scan
    suid_bins: List[Dict] = []
    if scan_suid and PLATFORM != "Windows":
        suid_bins = _find_suid_sgid_binaries()
        unexpected = [b for b in suid_bins if not b["expected"]]
        for b in unexpected[:10]:   # cap alerts
            engine.add(make_alert(
                title=f"Unexpected SUID Binary: {os.path.basename(b['path'])}",
                description=(
                    f"Binary '{b['path']}' has {'SUID' if b['suid'] else ''}"
                    f"{'/' if b['suid'] and b['sgid'] else ''}{'SGID' if b['sgid'] else ''} "
                    f"bit set and is not in the known-good whitelist. "
                    f"Could be used for privilege escalation."
                ),
                severity="HIGH",
                category="PRIVILEGE_ESCALATION",
                technique=mitre.get("T1548.001"),
                source="file_integrity",
                path=b["path"],
            ))

    _display(checks, suid_bins)
    return checks
