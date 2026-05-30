"""
Report generation — JSON, HTML, and plain-text exports.
"""

import os
import json
import datetime
import platform
from typing import List, Dict, Any


class Reporter:
    def __init__(self, report_dir: str = "./reports"):
        self.report_dir = report_dir
        os.makedirs(report_dir, exist_ok=True)

    def _timestamp(self) -> str:
        return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    def _base_path(self, ext: str) -> str:
        return os.path.join(self.report_dir, f"sshguard_report_{self._timestamp()}.{ext}")

    # ── JSON ─────────────────────────────────────────────────────────────────

    def save_json(self, scan_data: Dict[str, Any]) -> str:
        path = self._base_path("json")
        with open(path, "w") as f:
            json.dump(scan_data, f, indent=2, default=str)
        return path

    # ── Plain text ────────────────────────────────────────────────────────────

    def save_txt(self, scan_data: Dict[str, Any]) -> str:
        path = self._base_path("txt")
        lines = []

        def ln(s=""):
            lines.append(s)

        ln("=" * 74)
        ln(" SSHGuard v2.0 — Scan Report")
        ln("=" * 74)
        ln(f"  Host        : {scan_data.get('host', 'N/A')}")
        ln(f"  OS          : {scan_data.get('os', platform.system())}")
        ln(f"  User        : {scan_data.get('user', 'N/A')}")
        ln(f"  Started     : {scan_data.get('started_at', 'N/A')}")
        ln(f"  Duration    : {scan_data.get('duration_sec', 0):.2f}s")
        ln(f"  Threat Level: {scan_data.get('threat_level', 'N/A')}")
        ln()

        stats = scan_data.get("stats", {})
        ln("  ALERT SUMMARY")
        ln("  " + "-" * 40)
        ln(f"    CRITICAL : {stats.get('critical', 0)}")
        ln(f"    HIGH     : {stats.get('high', 0)}")
        ln(f"    MEDIUM   : {stats.get('medium', 0)}")
        ln(f"    LOW      : {stats.get('low', 0)}")
        ln(f"    Total    : {stats.get('total', 0)}")
        ln(f"    Score    : {stats.get('score', 0)}")
        ln()

        alerts = scan_data.get("alerts", [])
        if alerts:
            ln("  ALERTS")
            ln("  " + "-" * 70)
            for a in alerts:
                ln(f"  [{a.get('severity')}] {a.get('title')}")
                ln(f"    → {a.get('description')}")
                ln(f"    Category : {a.get('category_label', a.get('category'))}")
                ln(f"    MITRE    : {a.get('technique')}")
                if a.get("pid"):
                    ln(f"    PID      : {a.get('pid')}")
                if a.get("path"):
                    ln(f"    Path     : {a.get('path')}")
                ln()

        for module_key in ("ssh_sockets", "processes", "connections", "file_checks"):
            items = scan_data.get(module_key)
            if items is None:
                continue
            ln(f"  {module_key.upper().replace('_', ' ')}")
            ln("  " + "-" * 70)
            for item in items:
                if isinstance(item, dict):
                    for k, v in item.items():
                        ln(f"    {k:<20} {v}")
                    ln()

        ln("=" * 74)
        ln("  SSHGuard — Defensive use only.")
        ln("=" * 74)

        with open(path, "w") as f:
            f.write("\n".join(lines))
        return path

    # ── HTML ─────────────────────────────────────────────────────────────────

    def save_html(self, scan_data: Dict[str, Any]) -> str:
        path = self._base_path("html")

        SEV_COLORS = {
            "CRITICAL": "#ff4444",
            "HIGH":     "#ff9900",
            "MEDIUM":   "#00ccff",
            "LOW":      "#33ff66",
            "INFO":     "#888888",
            "CLEAN":    "#33ff66",
        }

        alerts = scan_data.get("alerts", [])
        stats  = scan_data.get("stats", {})
        threat = scan_data.get("threat_level", "CLEAN")
        tc     = SEV_COLORS.get(threat, "#888")

        def alert_cards_html():
            if not alerts:
                return '<p style="color:#33ff66">No alerts — system clean.</p>'
            rows = []
            for a in alerts:
                sc = SEV_COLORS.get(a.get("severity", "LOW"), "#888")
                rows.append(f"""
                <div class="alert-card" style="border-left:4px solid {sc}">
                  <div class="alert-header">
                    <span class="badge" style="background:{sc}">{a.get('severity')}</span>
                    <strong>{a.get('title','')}</strong>
                    <span class="ts">{a.get('timestamp','')[:19]}</span>
                  </div>
                  <div class="alert-body">
                    <p>{a.get('description','')}</p>
                    <span class="tag">{a.get('category_label','')}</span>
                    <span class="tag mitre">{a.get('technique','')}</span>
                    {'<span class="tag">PID: ' + str(a.get("pid")) + '</span>' if a.get("pid") else ''}
                    {'<span class="tag">Path: ' + str(a.get("path")) + '</span>' if a.get("path") else ''}
                  </div>
                </div>""")
            return "\n".join(rows)

        def table_html(items, title):
            if not items:
                return ""
            if not isinstance(items[0], dict):
                return ""
            headers = list(items[0].keys())
            rows = []
            for item in items:
                cells = "".join(f"<td>{item.get(h,'')}</td>" for h in headers)
                rows.append(f"<tr>{cells}</tr>")
            ths = "".join(f"<th>{h}</th>" for h in headers)
            return f"""
            <div class="section">
              <h2>{title}</h2>
              <table>
                <thead><tr>{ths}</tr></thead>
                <tbody>{''.join(rows)}</tbody>
              </table>
            </div>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SSHGuard Report — {scan_data.get('host','')}</title>
<style>
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ background:#0d0d0d; color:#ccc; font-family:'Courier New',monospace; font-size:13px; }}
  .container {{ max-width:1100px; margin:0 auto; padding:32px 16px; }}
  header {{ border-bottom:1px solid #222; padding-bottom:24px; margin-bottom:32px; }}
  header h1 {{ color:#00ff88; font-size:22px; letter-spacing:2px; }}
  header p {{ color:#555; margin-top:4px; }}
  .meta {{ display:flex; flex-wrap:wrap; gap:24px; margin-top:16px; }}
  .meta-item {{ background:#111; border:1px solid #1e1e1e; border-radius:4px; padding:10px 16px; }}
  .meta-item label {{ color:#555; font-size:11px; display:block; }}
  .meta-item span {{ color:#ccc; font-size:14px; }}
  .threat-level {{ color:{tc}; font-size:18px; font-weight:bold; }}
  .section {{ margin-bottom:40px; }}
  .section h2 {{ color:#00ff88; font-size:13px; letter-spacing:1px; text-transform:uppercase;
                 border-bottom:1px solid #1a1a1a; padding-bottom:8px; margin-bottom:16px; }}
  .alert-card {{ background:#111; border:1px solid #1e1e1e; border-radius:4px;
                 margin-bottom:12px; padding:12px 16px; }}
  .alert-header {{ display:flex; align-items:center; gap:10px; margin-bottom:6px; }}
  .badge {{ padding:2px 8px; border-radius:3px; color:#000; font-weight:bold;
            font-size:11px; text-transform:uppercase; }}
  .alert-body p {{ color:#aaa; margin:4px 0 8px; }}
  .tag {{ background:#1a1a1a; border:1px solid #333; border-radius:3px;
          padding:2px 7px; font-size:11px; color:#777; margin-right:6px; }}
  .mitre {{ color:#9966ff; border-color:#9966ff33; }}
  .ts {{ margin-left:auto; color:#444; font-size:11px; }}
  table {{ width:100%; border-collapse:collapse; }}
  th,td {{ text-align:left; padding:7px 10px; border-bottom:1px solid #1a1a1a; font-size:12px; }}
  th {{ color:#00ff88; background:#0d0d0d; }}
  tr:hover {{ background:#111; }}
  .stats-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:12px; margin-bottom:32px; }}
  .stat-card {{ background:#111; border:1px solid #1e1e1e; border-radius:4px; padding:16px; text-align:center; }}
  .stat-num {{ font-size:28px; font-weight:bold; }}
  .stat-label {{ color:#555; font-size:11px; margin-top:4px; }}
  footer {{ border-top:1px solid #1a1a1a; padding-top:20px; color:#333; text-align:center; font-size:11px; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>SSHGuard v2.0 — Security Scan Report</h1>
    <p>Defensive SSH &amp; System Monitor</p>
    <div class="meta">
      <div class="meta-item"><label>Host</label><span>{scan_data.get('host','N/A')}</span></div>
      <div class="meta-item"><label>OS</label><span>{scan_data.get('os','N/A')}</span></div>
      <div class="meta-item"><label>User</label><span>{scan_data.get('user','N/A')}</span></div>
      <div class="meta-item"><label>Scan Time</label><span>{scan_data.get('started_at','N/A')[:19]}</span></div>
      <div class="meta-item"><label>Duration</label><span>{scan_data.get('duration_sec',0):.2f}s</span></div>
      <div class="meta-item"><label>Threat Level</label><span class="threat-level">{threat}</span></div>
    </div>
  </header>

  <div class="stats-grid">
    <div class="stat-card"><div class="stat-num" style="color:#ff4444">{stats.get('critical',0)}</div><div class="stat-label">CRITICAL</div></div>
    <div class="stat-card"><div class="stat-num" style="color:#ff9900">{stats.get('high',0)}</div><div class="stat-label">HIGH</div></div>
    <div class="stat-card"><div class="stat-num" style="color:#00ccff">{stats.get('medium',0)}</div><div class="stat-label">MEDIUM</div></div>
    <div class="stat-card"><div class="stat-num" style="color:#33ff66">{stats.get('low',0)}</div><div class="stat-label">LOW</div></div>
    <div class="stat-card"><div class="stat-num" style="color:#aaa">{stats.get('total',0)}</div><div class="stat-label">TOTAL</div></div>
    <div class="stat-card"><div class="stat-num" style="color:#9966ff">{stats.get('score',0)}</div><div class="stat-label">RISK SCORE</div></div>
  </div>

  <div class="section">
    <h2>Security Alerts</h2>
    {alert_cards_html()}
  </div>

  {table_html(scan_data.get('ssh_sockets',[]), 'SSH Agent Sockets')}
  {table_html(scan_data.get('processes',[]), 'Flagged Processes')}
  {table_html(scan_data.get('connections',[]), 'Network Connections')}
  {table_html(scan_data.get('file_checks',[]), 'File Integrity')}

  <footer>
    SSHGuard v2.0 — Defensive use only. Unauthorized use is prohibited.
  </footer>
</div>
</body>
</html>"""

        with open(path, "w") as f:
            f.write(html)
        return path
