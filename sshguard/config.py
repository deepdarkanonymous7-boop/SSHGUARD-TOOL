"""
Configuration loader — reads config.yaml if present, falls back to defaults.
"""

import os
import platform
from typing import Any, Dict

_PLATFORM = platform.system()

# ── Defaults ──────────────────────────────────────────────────────────────────
DEFAULTS: Dict[str, Any] = {
    "watch_interval": 10,            # seconds between scans in --watch mode
    "max_processes_shown": 50,       # max process rows to display
    "max_connections_shown": 40,     # max connection rows to display
    "baseline_file": ".sshguard_baseline.json",
    "report_dir": "./reports",
    "log_file": None,                # set to a path to enable file logging
    "color": True,
    "modules": {
        "ssh": True,
        "processes": True,
        "network": True,
        "files": True,
        "privesc": True,
        "lateral": True,
    },
    "thresholds": {
        "cpu_high_pct": 80.0,        # flag process if CPU > this
        "cpu_critical_pct": 95.0,
        "mem_high_mb": 500,
        "conn_external_risk": "MEDIUM",
    },
}


class Config:
    def __init__(self, path: str = None):
        self._data: Dict[str, Any] = dict(DEFAULTS)
        self._path = path or os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "config.yaml"
        )
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self._path):
            return
        try:
            # Use PyYAML if available, else simple key: value parser
            try:
                import yaml  # type: ignore
                with open(self._path) as f:
                    data = yaml.safe_load(f)
                if isinstance(data, dict):
                    self._deep_update(self._data, data)
            except ImportError:
                self._load_simple(self._path)
        except Exception as e:
            pass   # silently fall back to defaults

    def _load_simple(self, path: str) -> None:
        """Minimal YAML-ish key: value parser (no deps)."""
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" in line:
                    k, _, v = line.partition(":")
                    k = k.strip()
                    v = v.strip()
                    if v.lower() in ("true", "yes"):
                        v = True
                    elif v.lower() in ("false", "no"):
                        v = False
                    elif v.isdigit():
                        v = int(v)
                    if k in self._data:
                        self._data[k] = v

    def _deep_update(self, base: dict, override: dict) -> None:
        for k, v in override.items():
            if isinstance(v, dict) and isinstance(base.get(k), dict):
                self._deep_update(base[k], v)
            else:
                base[k] = v

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def module_enabled(self, name: str) -> bool:
        return self._data.get("modules", {}).get(name, True)

    @property
    def baseline_file(self) -> str:
        bf = self._data.get("baseline_file", ".sshguard_baseline.json")
        if not os.path.isabs(bf):
            bf = os.path.join(os.path.dirname(os.path.dirname(__file__)), bf)
        return bf

    @property
    def report_dir(self) -> str:
        rd = self._data.get("report_dir", "./reports")
        if not os.path.isabs(rd):
            rd = os.path.join(os.path.dirname(os.path.dirname(__file__)), rd)
        return rd
