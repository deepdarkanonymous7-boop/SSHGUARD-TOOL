#!/usr/bin/env bash
# SSHGuard v2.0 — Linux / macOS Launcher
# Usage: ./run_linux.sh [sshguard options]
# Example: ./run_linux.sh --watch --interval 15 --export json,html

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check Python 3.7+
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] python3 not found. Install Python 3.7+ and try again."
    exit 1
fi

PY_VER=$(python3 -c "import sys; print(sys.version_info >= (3,7))")
if [[ "$PY_VER" != "True" ]]; then
    echo "[ERROR] SSHGuard requires Python 3.7+."
    exit 1
fi

# Check if running as root for full coverage
if [[ "$EUID" -ne 0 ]]; then
    echo ""
    echo "  [HINT] Running without root. Some checks will be limited."
    echo "         For full coverage: sudo ./run_linux.sh $*"
    echo ""
fi

python3 sshguard.py "$@"
