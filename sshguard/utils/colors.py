"""
Terminal color utilities — ANSI codes with Windows support.
"""

import sys
import platform
import os

_PLATFORM = platform.system()
_COLOR_ENABLED = True


def _enable_windows_vt():
    if _PLATFORM == "Windows":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return True


_COLOR_ENABLED = _enable_windows_vt() and (
    hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
    or os.environ.get("FORCE_COLOR") == "1"
)


class Col:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    ITALIC  = "\033[3m"
    UNDER   = "\033[4m"
    BLINK   = "\033[5m"

    BLACK   = "\033[30m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN    = "\033[36m"
    WHITE   = "\033[37m"

    BRED    = "\033[91m"
    BGREEN  = "\033[92m"
    BYELLOW = "\033[93m"
    BBLUE   = "\033[94m"
    BMAGENTA= "\033[95m"
    BCYAN   = "\033[96m"
    BWHITE  = "\033[97m"

    BG_BLACK  = "\033[40m"
    BG_RED    = "\033[41m"
    BG_GREEN  = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE   = "\033[44m"


def _c(code: str, text: str) -> str:
    if _COLOR_ENABLED:
        return f"{code}{text}{Col.RESET}"
    return text


def disable_color():
    global _COLOR_ENABLED
    _COLOR_ENABLED = False


def bold(t):     return _c(Col.BOLD, t)
def dim(t):      return _c(Col.DIM, t)
def red(t):      return _c(Col.BRED, t)
def green(t):    return _c(Col.BGREEN, t)
def yellow(t):   return _c(Col.BYELLOW, t)
def cyan(t):     return _c(Col.BCYAN, t)
def magenta(t):  return _c(Col.BMAGENTA, t)
def white(t):    return _c(Col.BWHITE, t)
def blue(t):     return _c(Col.BBLUE, t)
def bred(t):     return _c(Col.BG_RED + Col.BWHITE + Col.BOLD, t)


SEVERITY_COLORS = {
    "CRITICAL": lambda t: _c(Col.BRED + Col.BOLD,    t),
    "HIGH":     lambda t: _c(Col.BYELLOW + Col.BOLD, t),
    "MEDIUM":   lambda t: _c(Col.BCYAN,               t),
    "LOW":      lambda t: _c(Col.BGREEN,               t),
    "INFO":     lambda t: _c(Col.DIM,                  t),
}

STATUS_COLORS = {
    "OK":          lambda t: _c(Col.BGREEN, t),
    "MODIFIED":    lambda t: _c(Col.BRED + Col.BOLD, t),
    "MISSING":     lambda t: _c(Col.BYELLOW, t),
    "NO ACCESS":   lambda t: _c(Col.DIM, t),
    "NEW":         lambda t: _c(Col.BCYAN, t),
    "UNKNOWN":     lambda t: _c(Col.DIM, t),
}


def severity_badge(level: str) -> str:
    level = level.upper()
    pad = max(0, 8 - len(level))
    label = f"[{level}]" + " " * pad
    fn = SEVERITY_COLORS.get(level, lambda t: t)
    return fn(label)


def status_badge(status: str) -> str:
    fn = STATUS_COLORS.get(status.upper(), lambda t: t)
    return fn(status)


def rule(width: int = 74, char: str = "─") -> str:
    return dim(char * width)


def header(title: str, icon: str = "[+]") -> str:
    line = "─" * 74
    return (
        f"\n  {green(icon)} {bold(white(title))}\n"
        f"  {dim(line)}"
    )


def print_kv(key: str, value: str, width: int = 22) -> None:
    print(f"  {dim(key.ljust(width))} {value}")


def truncate(s: str, max_len: int = 60) -> str:
    return s if len(s) <= max_len else s[: max_len - 3] + "..."
