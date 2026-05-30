# SSHGuard v2.0 — Advanced Defensive SSH & System Monitor


<img width="1174" height="682" alt="Screenshot 2026-05-30 alle 21 14 17" src="https://github.com/user-attachments/assets/8fccfbf6-b36d-483a-a079-be9bf5489d0c" />


A multi-module, professional-grade Python security tool for defensive monitoring
of SSH agent activity, suspicious processes, network anomalies, file integrity,
privilege escalation vectors, and lateral movement indicators.

Inspired by SSHAgentJack and similar red-team research — but built for defense.

---

## Features

| Module | What it detects |
|--------|----------------|
| **SSH Monitor** | Live SSH agent sockets, concurrent socket access (hijacking), root-owned sockets, loaded key inventory |
| **Process Monitor** | Suspicious process names (IOC match), dangerous command patterns (reverse shells, encoded payloads), masquerading, execution from `/tmp`/`/dev/shm` |
| **Network Inspector** | C2 ports, unexpected outbound connections, SSH tunnels, Telnet, known-bad IP matching, reverse DNS |
| **File Integrity (FIM)** | SHA-256 + MD5 baseline comparison for 18+ critical system files, world-writable detection, SUID/SGID anomaly scan |
| **Privilege Escalation** | `sudo` misconfigurations, writable cron jobs, PATH hijacking, LD_PRELOAD abuse, dangerous Linux capabilities, history evasion |
| **Lateral Movement** | SSH `known_hosts` analysis, `authorized_keys` audit, shell history scan, `wtmp`/`who` session analysis |

---

## Requirements

- **Python 3.7+** — zero external dependencies required
- Works on **Linux, macOS, Windows**
- Optional: `psutil`, `pyyaml` (see `requirements.txt`)

---

## Quick Start

### Linux / macOS

```bash
# Full scan (recommended: run as root for maximum coverage)
sudo python3 sshguard.py

# Or use the launcher
chmod +x run_linux.sh
sudo ./run_linux.sh

# SSH hijack detection only
python3 sshguard.py --module ssh

# Watch mode — rescan every 15 seconds
python3 sshguard.py --watch --interval 15

# Export JSON + HTML report
python3 sshguard.py --export json,html
```

### Windows

```cmd
# Double-click run_windows.bat for a quick scan
# Or from cmd:
python sshguard.py --module ssh,proc,net

# PowerShell:
.\run_windows.ps1 --watch --interval 30
```

---

## CLI Reference

```
python sshguard.py [OPTIONS]

Options:
  -m, --module MODULE     Modules to run (default: all)
                          Choices: all, ssh, proc, net, files, privesc, lateral
                          Combine: ssh,proc,net

  -w, --watch             Continuous monitoring mode
  -i, --interval SECONDS  Watch interval in seconds (default: 10)

  -e, --export FORMAT     Export report: json, html, txt (or comma-combined)
      --reset-baseline    Reset FIM baseline (re-hash all files)

  -c, --config PATH       Path to config.yaml

      --no-color          Disable ANSI colors
  -q, --quiet             Suppress banner
  -V, --version           Show version
  -h, --help              Show help
```

---

## Module Details

### SSH Monitor (`--module ssh`)
Finds all SSH agent sockets (`/tmp/ssh-*/agent.*`, `/run/user/*/ssh-agent.socket`, etc.)
and checks which processes have open file descriptors pointing to each socket.
Multiple concurrent PIDs accessing the same socket is the signature of
**SSH agent hijacking** (as demonstrated by tools like SSHAgentJack).

### File Integrity Monitor (`--module files`)
On first run, hashes 18+ critical files (e.g. `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`,
`/root/.ssh/authorized_keys`) and saves a SHA-256/MD5 baseline to `.sshguard_baseline.json`.
On subsequent runs, it compares current hashes against the baseline and flags modifications.
Use `--reset-baseline` to rebuild the baseline after intentional changes.

### Privilege Escalation Detector (`--module privesc`)
Checks:
- `sudo -l` for NOPASSWD and wildcard rules
- `/etc/sudoers` and `/etc/sudoers.d/*` for dangerous patterns
- World-writable cron files and cron-called scripts
- `$PATH` for writable directories and relative entries
- `$LD_PRELOAD` and `/etc/ld.so.preload` (rootkit indicator)
- Linux capabilities (`getcap`) for dangerous bits

### Lateral Movement Detector (`--module lateral`)
Analyses:
- `~/.ssh/known_hosts` for external hosts
- `authorized_keys` across all users
- `last` / `wtmp` for logins from external IPs
- `.bash_history`, `.zsh_history` for SSH tunneling, SCP, curl|bash patterns
- Active sessions via `who`

---

## MITRE ATT&CK Coverage

| Technique | Name | Module |
|-----------|------|--------|
| T1563.001 | SSH Hijacking | ssh_monitor |
| T1548.001 | Setuid/Setgid | file_integrity |
| T1548.003 | Sudo/Sudoers Abuse | privesc_detector |
| T1552.004 | Unsecured Private Keys | lateral_movement |
| T1053.003 | Cron Persistence | privesc_detector |
| T1059 | Command and Scripting Interpreter | process_monitor |
| T1571 | Non-Standard Port | network_monitor |
| T1021.004 | SSH Lateral Movement | lateral_movement |
| T1098.004 | SSH Authorized Keys | lateral_movement |
| T1070.003 | Clear Command History | privesc_detector |
| T1574.006 | Dynamic Linker Hijacking | privesc_detector |
| T1565.001 | Stored Data Manipulation | file_integrity |

---

## Configuration

Edit `config.yaml` to customize:

```yaml
watch_interval: 10        # seconds between scans in --watch mode
modules:
  ssh: true
  processes: true
  network: true
  files: true
  privesc: true
  lateral: true
baseline_file: .sshguard_baseline.json
report_dir: ./reports
```

---

## Output

SSHGuard exits with:
- `0` — system clean, no threats
- `1` — one or more threats detected

This makes it suitable for use in cron jobs or monitoring pipelines:

```bash
# Alert if threats found
python3 sshguard.py --no-color --quiet || echo "ALERT: threats detected" | mail -s "SSHGuard" admin@example.com
```

---

## Project Structure

```
sshguard-tool/
├── sshguard.py                  ← CLI entry point
├── config.yaml                  ← user configuration
├── requirements.txt
├── run_linux.sh / run_windows.bat / run_windows.ps1
└── sshguard/
    ├── banner.py                ← ASCII art, display helpers
    ├── config.py                ← configuration loader
    ├── modules/
    │   ├── ssh_monitor.py       ← SSH agent hijack detection
    │   ├── process_monitor.py   ← suspicious process analysis
    │   ├── network_monitor.py   ← network connection inspection
    │   ├── file_integrity.py    ← FIM with SHA-256 baseline
    │   ├── privesc_detector.py  ← privilege escalation vectors
    │   └── lateral_movement.py  ← lateral movement analysis
    ├── engine/
    │   ├── alert.py             ← alert dataclass, scoring, dedup
    │   ├── reporter.py          ← JSON / HTML / TXT export
    │   └── scanner.py           ← module orchestrator
    ├── utils/
    │   ├── colors.py            ← ANSI colors, badges, formatting
    │   └── sysutils.py          ← cross-platform OS utilities
    └── intel/
        ├── ioc.py               ← IOC definitions (names, ports, patterns)
        └── mitre.py             ← MITRE ATT&CK technique mappings
```

---

## Legal Notice

SSHGuard is designed exclusively for **defensive security monitoring** on systems
you own or have explicit written authorisation to test.
Unauthorised use against systems you do not own is illegal and unethical.
