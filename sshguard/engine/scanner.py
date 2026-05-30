"""
Scanner — orchestrates all SSHGuard modules and aggregates results.
"""

import time
import datetime
import platform
import os
from typing import Dict, Any, List, Optional

from .alert import AlertEngine
from .reporter import Reporter
from ..config import Config
from ..utils.sysutils import uptime_str, current_user, hostname
from ..utils import colors as col
from ..banner import (
    print_banner, print_alert_card, print_summary_box, print_footer,
)


class Scanner:
    def __init__(self, config: Config):
        self.config   = config
        self.engine   = AlertEngine()
        self.reporter = Reporter(config.report_dir)
        self._results: Dict[str, Any] = {}

    def run(
        self,
        modules: str = "all",
        reset_baseline: bool = False,
        export: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Run the selected modules and return a full results dict.

        modules: "all" | "ssh" | "proc" | "net" | "files" | "privesc" | "lateral"
                 or comma-separated combination: "ssh,proc,net"
        """
        self.engine.clear()
        started = datetime.datetime.now()
        t0 = time.time()

        # Show banner
        user = current_user()
        host = hostname()
        up   = uptime_str()
        print_banner(username=user, hostname_str=host, uptime_str=up)

        selected = {m.strip() for m in modules.split(",")} if "," in modules else {modules}
        run_all  = "all" in selected

        # ── SSH Agent Monitor ────────────────────────────────────────────────
        ssh_data = []
        if run_all or "ssh" in selected:
            if self.config.module_enabled("ssh"):
                from ..modules import ssh_monitor
                ssh_data = ssh_monitor.run(self.engine)

        # ── Process Monitor ──────────────────────────────────────────────────
        proc_data = []
        if run_all or "proc" in selected:
            if self.config.module_enabled("processes"):
                from ..modules import process_monitor
                proc_data = process_monitor.run(self.engine)

        # ── Network Inspector ────────────────────────────────────────────────
        net_data = []
        if run_all or "net" in selected:
            if self.config.module_enabled("network"):
                from ..modules import network_monitor
                net_data = network_monitor.run(self.engine)

        # ── File Integrity Monitor ───────────────────────────────────────────
        file_data = []
        if run_all or "files" in selected:
            if self.config.module_enabled("files"):
                from ..modules import file_integrity
                file_data = file_integrity.run(
                    self.engine,
                    baseline_file=self.config.baseline_file,
                    reset=reset_baseline,
                )

        # ── Privilege Escalation Detector ────────────────────────────────────
        privesc_data = []
        if run_all or "privesc" in selected:
            if self.config.module_enabled("privesc"):
                from ..modules import privesc_detector
                privesc_data = privesc_detector.run(self.engine)

        # ── Lateral Movement Detector ────────────────────────────────────────
        lateral_data = []
        if run_all or "lateral" in selected:
            if self.config.module_enabled("lateral"):
                from ..modules import lateral_movement
                lateral_data = lateral_movement.run(self.engine)

        # ── Alert Summary ─────────────────────────────────────────────────────
        from ..banner import section
        section("Security Alert Summary", "[!]",
                color_fn=(col.red if self.engine.critical else col.yellow
                           if self.engine.high else col.green))

        alerts = self.engine.by_severity
        if alerts:
            for a in alerts:
                print_alert_card(a.to_dict())
        else:
            print(f"  {col.green('[OK] No active threats detected on this system.')}\n")

        print_summary_box([a.to_dict() for a in self.engine.all])

        duration = round(time.time() - t0, 2)
        print_footer(scan_duration=duration)

        # ── Build results dict ─────────────────────────────────────────────────
        results: Dict[str, Any] = {
            "host":         host,
            "user":         user,
            "os":           f"{platform.system()} {platform.release()}",
            "started_at":   started.isoformat(),
            "duration_sec": duration,
            "threat_level": self.engine.threat_level(),
            "stats":        self.engine.stats(),
            "alerts":       self.engine.to_dicts(),
            "ssh_sockets":  _flatten_ssh(ssh_data),
            "processes":    _flatten_procs(proc_data),
            "connections":  _flatten_conns(net_data),
            "file_checks":  _flatten_files(file_data),
        }
        self._results = results

        # ── Export ────────────────────────────────────────────────────────────
        if export:
            self._export(results, export)

        return results

    def _export(self, results: Dict, formats: List[str]) -> None:
        paths = []
        for fmt in formats:
            fmt = fmt.lower().strip()
            if fmt == "json":
                p = self.reporter.save_json(results)
                paths.append(p)
            elif fmt == "html":
                p = self.reporter.save_html(results)
                paths.append(p)
            elif fmt in ("txt", "text"):
                p = self.reporter.save_txt(results)
                paths.append(p)

        if paths:
            print()
            from ..banner import section
            section("Reports Exported", "[>]")
            for p in paths:
                print(f"  {col.cyan('→')} {p}")
            print()

    @property
    def threat_level(self) -> str:
        return self.engine.threat_level()

    @property
    def alert_count(self) -> int:
        return len(self.engine.all)


# ── Data flattening helpers ───────────────────────────────────────────────────

def _flatten_ssh(data: List) -> List[Dict]:
    rows = []
    for s in data:
        owner = s.get("owner", {})
        rows.append({
            "path":         s.get("path", ""),
            "owner":        owner.get("username", "?"),
            "permissions":  owner.get("permissions", "?"),
            "risk":         s.get("risk", "?"),
            "accessing_pids": ",".join(p["pid"] for p in s.get("accessing", [])),
        })
    return rows


def _flatten_procs(data: List) -> List[Dict]:
    rows = []
    for item in data:
        p = item.get("proc", {})
        rows.append({
            "pid":      p.get("pid", "?"),
            "name":     p.get("name", "?"),
            "user":     p.get("user", "?"),
            "severity": item.get("severity", "?"),
            "reasons":  "; ".join(item.get("reasons", [])[:2]),
            "command":  p.get("cmd", "")[:100],
        })
    return rows


def _flatten_conns(data: List) -> List[Dict]:
    rows = []
    for item in data:
        c = item.get("conn", {})
        rows.append({
            "proto":   c.get("proto", "?"),
            "state":   c.get("state", "?"),
            "local":   c.get("local", "?"),
            "remote":  c.get("peer", "?"),
            "process": f"{c.get('proc','?')}/{c.get('pid','?')}",
            "risk":    item.get("risk", "?"),
            "flags":   ", ".join(item.get("flags", [])),
        })
    return rows


def _flatten_files(data: List) -> List[Dict]:
    rows = []
    for f in data:
        meta = f.get("meta", {})
        rows.append({
            "path":         f.get("path", "?"),
            "status":       f.get("status", "?"),
            "sha256":       f.get("sha256", "?")[:20] + "..." if f.get("sha256") else "?",
            "permissions":  meta.get("permissions", "?"),
            "owner":        meta.get("owner", "?"),
            "modified":     meta.get("mtime", "?"),
            "world_write":  "YES" if meta.get("is_world_writable") else "no",
        })
    return rows
