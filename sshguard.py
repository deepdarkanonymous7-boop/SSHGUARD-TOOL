#!/usr/bin/env python3
"""
SSHGuard v2.0 — Advanced Defensive SSH & System Security Monitor
Usage: python sshguard.py [options]
"""

import sys
import os
import time
import argparse
import platform

# Ensure the tool root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sshguard import __version__
from sshguard.config import Config
from sshguard.engine.scanner import Scanner
from sshguard.utils.colors import disable_color, bold, green, red, yellow, cyan, dim


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="sshguard",
        description=(
            "SSHGuard v2.0 — Advanced Defensive SSH & System Security Monitor\n"
            "Detects SSH hijacking, suspicious processes, network anomalies,\n"
            "file integrity violations, privilege escalation vectors and lateral movement.\n"
            "\nFor defensive / educational use only. Unauthorized use is prohibited."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sshguard.py                          # Full scan, all modules
  python sshguard.py --module ssh             # SSH sockets only
  python sshguard.py --module ssh,proc,net    # SSH + Processes + Network
  python sshguard.py --watch --interval 30    # Continuous monitoring every 30s
  python sshguard.py --export json,html       # Export report to JSON + HTML
  python sshguard.py --reset-baseline         # Reset file integrity baseline
  python sshguard.py --no-color               # Disable ANSI colors (pipes/logs)
  python sshguard.py --quiet                  # Suppress banner; alerts only
        """,
    )

    p.add_argument(
        "--module", "-m",
        default="all",
        metavar="MODULE",
        help=(
            "Comma-separated list of modules to run. "
            "Choices: all, ssh, proc, net, files, privesc, lateral. "
            "Default: all"
        ),
    )
    p.add_argument(
        "--watch", "-w",
        action="store_true",
        help="Run continuously (watch mode), repeating scans at --interval seconds.",
    )
    p.add_argument(
        "--interval", "-i",
        type=int,
        default=None,
        metavar="SECONDS",
        help="Seconds between scans in --watch mode (overrides config). Default: 10.",
    )
    p.add_argument(
        "--export", "-e",
        default=None,
        metavar="FORMAT",
        help="Export report(s) after scan. Comma-separated: json, html, txt.",
    )
    p.add_argument(
        "--reset-baseline",
        action="store_true",
        help="Reset the file integrity baseline (forces all files to be re-hashed).",
    )
    p.add_argument(
        "--config", "-c",
        default=None,
        metavar="PATH",
        help="Path to config.yaml (default: config.yaml in tool directory).",
    )
    p.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes (useful for piping or log files).",
    )
    p.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress banner; print minimal output (still shows alerts).",
    )
    p.add_argument(
        "--version", "-V",
        action="version",
        version=f"SSHGuard {__version__}",
    )
    return p.parse_args()


def _check_python_version() -> None:
    if sys.version_info < (3, 7):
        print(f"[ERROR] SSHGuard requires Python 3.7+. You are running {sys.version}.")
        sys.exit(1)


def _check_privilege_hint() -> None:
    """Inform user if running without root (some checks need it)."""
    if platform.system() != "Windows":
        if os.geteuid() != 0:
            print(
                f"  {yellow('[HINT]')} {dim('Running as non-root. Some checks (SUID scan, shadow file, /proc FD access)')}\n"
                f"         {dim('may be incomplete. Run with sudo for full coverage.')}\n"
            )


def _run_once(scanner: Scanner, args: argparse.Namespace) -> int:
    """Single scan pass. Returns 0 if clean, 1 if threats found."""
    export_fmts = [f.strip() for f in args.export.split(",")] if args.export else None

    results = scanner.run(
        modules=args.module,
        reset_baseline=args.reset_baseline,
        export=export_fmts,
    )

    return 0 if results.get("threat_level") == "CLEAN" else 1


def main() -> None:
    _check_python_version()
    args = _parse_args()

    if args.no_color:
        disable_color()

    config = Config(path=args.config)
    scanner = Scanner(config)

    if not args.quiet:
        _check_privilege_hint()

    if args.watch:
        interval = args.interval or config.get("watch_interval", 10)
        print(
            f"  {green('[WATCH MODE]')} Scanning every {bold(str(interval))} seconds. "
            f"Press {bold('Ctrl+C')} to stop.\n"
        )
        scan_count = 0
        try:
            while True:
                scan_count += 1
                print(f"\n  {dim(f'─── Scan #{scan_count} ─' + '─' * 50)}")
                _run_once(scanner, args)
                # Clear dedup so alerts fire again next cycle
                scanner.engine.clear()
                print(f"  {dim(f'Next scan in {interval}s...')}\n")
                time.sleep(interval)
        except KeyboardInterrupt:
            print(f"\n  {yellow('[STOPPED]')} SSHGuard watch mode terminated by user.")
            sys.exit(0)
    else:
        exit_code = _run_once(scanner, args)
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
