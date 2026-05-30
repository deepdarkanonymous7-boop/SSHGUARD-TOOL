"""
IOC (Indicators of Compromise) definitions.
Extend these lists with your own threat intelligence feeds.
"""

# ── Suspicious process names ──────────────────────────────────────────────────
SUSPICIOUS_PROCESS_NAMES = {
    # Network tools often abused
    "ncat", "netcat", "nc", "nc.exe", "ncat.exe",
    "socat", "socat.exe",
    "nmap", "masscan", "zmap",
    # Exploitation frameworks
    "msfconsole", "msfvenom", "msfpayload", "msfrpc",
    "armitage",
    # Password crackers
    "hydra", "hydra.exe", "medusa",
    "john", "john.exe", "johntheripper",
    "hashcat", "hashcat.exe",
    # Windows-specific offensive
    "mimikatz", "mimikatz.exe",
    "wce.exe", "fgdump.exe",
    "pwdump", "pwdump7.exe",
    # Scripting interpreters often used in payloads
    "powershell", "powershell.exe", "pwsh", "pwsh.exe",
    "wscript", "wscript.exe", "cscript", "cscript.exe",
    "mshta", "mshta.exe",
    # LOLBins
    "regsvr32", "regsvr32.exe",
    "certutil", "certutil.exe",
    "bitsadmin", "bitsadmin.exe",
    "wmic", "wmic.exe",
    "schtasks", "schtasks.exe",
    "at.exe",
    "rundll32", "rundll32.exe",
    "regasm", "regasm.exe",
    "msiexec", "msiexec.exe",
    # Tunneling / proxy
    "chisel", "ligolo", "frpc", "frps", "ngrok",
    "plink", "plink.exe",
    # Scanning
    "sqlmap",
    # SSH abuse
    "sshpass",
}

# ── Suspicious command fragments (regex-ready) ────────────────────────────────
SUSPICIOUS_CMD_PATTERNS = [
    # In-memory execution
    r"base64\s+-[dD]",
    r"/dev/shm/",
    r"/tmp/\.",               # hidden files in /tmp
    r"chmod\s+\+x\s+/tmp",
    r"curl\s.*\|\s*bash",
    r"wget\s.*\|\s*bash",
    r"\|\s*sh\s*$",
    r"\|\s*python",
    r"exec\s+/bin/(sh|bash|dash|zsh)",
    # Reverse shells
    r"mkfifo",
    r"/bin/(bash|sh)\s+-i",
    r">.*\/dev\/tcp\/",       # bash /dev/tcp redirect
    r"python.*socket.*connect",
    r"perl.*socket.*connect",
    r"ruby.*TCPSocket",
    # PowerShell attacks
    r"-enc\s+[A-Za-z0-9+/=]{20,}",   # base64 encoded payload
    r"-EncodedCommand",
    r"IEX\s*\(",
    r"Invoke-Expression",
    r"DownloadString",
    r"Net\.WebClient",
    r"Bypass\s+-File",
    # Credential theft
    r"lsass",
    r"sekurlsa",
    r"pass-the-hash",
    r"mimikatz",
    # Persistence
    r"schtasks\s+/create",
    r"crontab\s+-",
    r"echo.*>>.*\.bashrc",
    r"echo.*>>.*authorized_keys",
]

# ── Suspicious environment variables ─────────────────────────────────────────
SUSPICIOUS_ENV_VARS = [
    "HISTFILE=/dev/null",     # disabling history
    "HISTSIZE=0",
    "HISTFILESIZE=0",
]

# ── Suspicious open ports (local listeners) ───────────────────────────────────
SUSPICIOUS_LOCAL_PORTS = {
    4444,   # Metasploit default
    4445,
    4446,
    1337,   # l33t
    31337,  # Back Orifice / Elite
    8888,
    9999,
    6666, 6667, 6668, 6669,   # IRC (often used by botnets)
    1234,
    5555,   # ADB / Android debug bridge
    7777,
    65535,
    54321,
    12345,
    23,     # Telnet
}

# ── Suspicious outbound ports ─────────────────────────────────────────────────
SUSPICIOUS_REMOTE_PORTS = {
    4444, 4445, 1337, 31337, 8888, 9999,
    6666, 6667, 6668, 6669,
    1234, 5555, 7777, 65535, 54321, 12345,
}

# ── Known malicious IP ranges (CIDR) — extend with threat intel ──────────────
# Format: "x.x.x.x/y" or exact "x.x.x.x"
MALICIOUS_IPS: list = [
    # Add known C2 IPs from threat feeds (e.g. AbuseIPDB, Emerging Threats)
    # Example: "185.220.101.0/24",   # Tor exit nodes often abused
]

# ── SUID binaries whitelist (expected on clean Linux systems) ─────────────────
EXPECTED_SUID_BINARIES = {
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/bin/su",
    "/usr/bin/passwd",
    "/usr/bin/chfn",
    "/usr/bin/chsh",
    "/usr/bin/gpasswd",
    "/usr/bin/newgrp",
    "/usr/bin/pkexec",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/policykit-1/polkit-agent-helper-1",
    "/usr/sbin/pppd",
    "/bin/ping",
    "/bin/umount",
    "/bin/mount",
    "/bin/fusermount",
    "/sbin/unix_chkpwd",
    # macOS
    "/usr/bin/su",
    "/usr/bin/sudo",
    "/usr/lib/ssh/ssh-keysign",
}

# ── Critical files for integrity monitoring ────────────────────────────────────
CRITICAL_FILES = {
    "Linux": [
        {"path": "/etc/passwd",                     "risk": "CRITICAL", "desc": "User account database"},
        {"path": "/etc/shadow",                     "risk": "CRITICAL", "desc": "Password hash database"},
        {"path": "/etc/sudoers",                    "risk": "CRITICAL", "desc": "Sudo privilege configuration"},
        {"path": "/etc/sudoers.d",                  "risk": "HIGH",     "desc": "Sudo drop-in directory"},
        {"path": "/etc/ssh/sshd_config",            "risk": "HIGH",     "desc": "SSH daemon configuration"},
        {"path": "/etc/ssh/ssh_config",             "risk": "MEDIUM",   "desc": "SSH client configuration"},
        {"path": "/root/.ssh/authorized_keys",      "risk": "CRITICAL", "desc": "Root SSH authorized keys"},
        {"path": "/etc/crontab",                    "risk": "HIGH",     "desc": "System crontab"},
        {"path": "/etc/cron.d",                     "risk": "HIGH",     "desc": "Cron drop-in directory"},
        {"path": "/etc/hosts",                      "risk": "MEDIUM",   "desc": "Host name resolution"},
        {"path": "/etc/resolv.conf",                "risk": "MEDIUM",   "desc": "DNS resolver configuration"},
        {"path": "/etc/ld.so.preload",              "risk": "CRITICAL", "desc": "Shared library preload (rootkit indicator)"},
        {"path": "/etc/profile",                    "risk": "HIGH",     "desc": "System shell profile"},
        {"path": "/etc/bashrc",                     "risk": "HIGH",     "desc": "System bash configuration"},
        {"path": "/proc/sys/kernel/randomize_va_space", "risk": "HIGH", "desc": "ASLR configuration"},
        {"path": "/proc/sys/kernel/dmesg_restrict", "risk": "MEDIUM",   "desc": "Kernel log restriction"},
        {"path": "/etc/pam.d/sshd",                "risk": "HIGH",     "desc": "PAM SSH configuration"},
        {"path": "/etc/pam.d/sudo",                "risk": "CRITICAL", "desc": "PAM sudo configuration"},
    ],
    "Darwin": [
        {"path": "/etc/passwd",                     "risk": "CRITICAL", "desc": "User account database"},
        {"path": "/etc/hosts",                      "risk": "MEDIUM",   "desc": "Host name resolution"},
        {"path": "/private/etc/sudoers",            "risk": "CRITICAL", "desc": "Sudo configuration"},
        {"path": "/etc/ssh/sshd_config",            "risk": "HIGH",     "desc": "SSH daemon configuration"},
        {"path": "/Library/LaunchDaemons",          "risk": "HIGH",     "desc": "System launch daemons (persistence)"},
        {"path": "/Library/LaunchAgents",           "risk": "HIGH",     "desc": "System launch agents (persistence)"},
    ],
    "Windows": [
        {"path": r"C:\Windows\System32\drivers\etc\hosts", "risk": "HIGH",     "desc": "Windows hosts file"},
        {"path": r"C:\Windows\System32\config\SAM",        "risk": "CRITICAL", "desc": "Windows SAM database"},
        {"path": r"C:\Windows\System32\config\SYSTEM",     "risk": "CRITICAL", "desc": "Windows SYSTEM hive"},
        {"path": r"C:\Windows\System32\config\SECURITY",   "risk": "CRITICAL", "desc": "Windows SECURITY hive"},
        {"path": r"C:\Windows\System32\cmd.exe",           "risk": "HIGH",     "desc": "Windows command interpreter"},
        {"path": r"C:\Windows\win.ini",                    "risk": "MEDIUM",   "desc": "Windows ini file"},
        {"path": r"C:\Windows\System32\svchost.exe",       "risk": "CRITICAL", "desc": "Windows service host"},
    ],
}

# ── Sudo dangerous configurations ────────────────────────────────────────────
DANGEROUS_SUDO_PATTERNS = [
    "NOPASSWD: ALL",
    "(ALL) ALL",
    "(ALL:ALL) ALL",
    "NOPASSWD: /bin/bash",
    "NOPASSWD: /bin/sh",
    "NOPASSWD: /usr/bin/python",
    "NOPASSWD: /usr/bin/vim",
    "NOPASSWD: /usr/bin/nano",
    "NOPASSWD: /usr/bin/less",
    "NOPASSWD: /usr/bin/find",
    "NOPASSWD: /usr/bin/awk",
    "NOPASSWD: /usr/bin/perl",
    "NOPASSWD: /usr/bin/ruby",
]

# ── Writable paths used for persistence ──────────────────────────────────────
PERSISTENCE_PATHS_LINUX = [
    "/etc/cron.d/",
    "/etc/cron.daily/",
    "/etc/cron.hourly/",
    "/etc/cron.monthly/",
    "/etc/cron.weekly/",
    "/etc/init.d/",
    "/etc/rc.local",
    "/etc/profile.d/",
    "/etc/ld.so.conf.d/",
    "/etc/systemd/system/",
    "/usr/lib/systemd/system/",
    "/var/spool/cron/",
    "/home/*/.bashrc",
    "/home/*/.bash_profile",
    "/home/*/.profile",
    "/root/.bashrc",
    "/root/.bash_profile",
    "/root/.profile",
    "/home/*/.ssh/authorized_keys",
]

PERSISTENCE_PATHS_WINDOWS = [
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\System\CurrentControlSet\Services",
    r"C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
]
