#!/usr/bin/env bash
set -euo pipefail

# Cross-distro installer for:
# - auditd (Linux Audit)
# - audit rules to capture file activity by human users
# - systemd service + Python parser correlating session -> IP
#
# Code made using Copilot AI
#
# Output log: /var/log/ssh_file_activity.log

LOG_OUT="/var/log/ssh_file_activity.log"
PARSER_BIN="/usr/local/bin/ssh_file_activity_monitor.py"
RULES_FILE="/etc/audit/rules.d/ssh_fs.rules"
SERVICE_FILE="/etc/systemd/system/ssh-file-activity.service"

# --- helpers ---
need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Please run as root." >&2
    exit 1
  fi
}

detect_pkg_manager() {
  if command -v apt-get >/dev/null 2>&1; then echo "apt"; return
  elif command -v dnf >/dev/null 2>&1; then echo "dnf"; return
  elif command -v yum >/dev/null 2>&1; then echo "yum"; return
  elif command -v zypper >/dev/null 2>&1; then echo "zypper"; return
  else echo "unknown"; return
  fi
}

install_pkg() {
  local pm="$1" pkg="$2"
  case "$pm" in
    apt) DEBIAN_FRONTEND=noninteractive apt-get update -y && apt-get install -y "$pkg" ;;
    dnf) dnf install -y "$pkg" ;;
    yum) yum install -y "$pkg" ;;
    zypper) zypper install -y "$pkg" ;;
    *) echo "Install $pkg manually; unsupported package manager." >&2; exit 1;;
  esac
}

ensure_auditd() {
  if ! command -v auditctl >/dev/null 2>&1; then
    echo "Installing auditd..."
    local pm; pm=$(detect_pkg_manager)
    install_pkg "$pm" auditd || install_pkg "$pm" audit
  fi
  # Enable & start auditd
  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable auditd || true
    systemctl start auditd || true
  fi
}

write_rules() {
  # Notes:
  # - We capture writes/creates/deletes/renames/truncates/perm/owner changes using syscall rules.
  # - Filter to human users: auid>=1000, auid!=4294967295 (unset).
  # - Key: ssh_fs (used by parser to locate events).
  # - We include both b64 and b32 architectures for portability.
  # - Optional path watches for common dirs; comment/uncomment as desired.

  cat > "$RULES_FILE" <<'EOF'
# SSH file activity rules (human users only)
# Session correlation via audit USER_LOGIN events; parser links ses->addr.
# Syscall rules:
-a always,exit -F arch=b64 -S open,openat,creat,truncate,ftruncate,unlink,unlinkat,rename,renameat,chmod,fchmod,chown,fchown,utime,utimes -F success=1 -F auid>=1000 -F auid!=4294967295 -k ssh_fs
-a always,exit -F arch=b32 -S open,openat,creat,truncate,ftruncate,unlink,unlinkat,rename,renameat,chmod,fchmod,chown,fchown,utime,utimes -F success=1 -F auid>=1000 -F auid!=4294967295 -k ssh_fs

# Optional: add focused path watches to reduce noise (uncomment as needed)
# -p rwa means read/write/attribute changes; beware of volume if enabling `r`.
#-w /home -p wa -k ssh_fs_watch
#-w /etc -p wa -k ssh_fs_watch
#-w /var/www -p wa -k ssh_fs_watch
#-w /opt -p wa -k ssh_fs_watch
EOF

  # Load rules now
  if [ -f /sbin/augenrules ] || [ -f /usr/sbin/augenrules ]; then
    augenrules --load || true
  fi
  # Fallback: reload via auditctl
  if command -v auditctl >/dev/null 2>&1; then
    # Clear existing ssh_fs rules to avoid duplicates
    auditctl -D >/dev/null 2>&1 || true
    # Re-apply from rules files
    if [ -x /sbin/augenrules ]; then /sbin/augenrules --load || true; fi
    if [ -x /usr/sbin/augenrules ]; then /usr/sbin/augenrules --load || true; fi
  fi
}

write_parser() {
  # Minimal Python parser: polls ausearch for new ssh_fs events,
  # correlates ses -> USER_LOGIN addr (remote IP), and writes clean lines.

  cat > "$PARSER_BIN" <<'PYEOF'
#!/usr/bin/env python3
import subprocess, time, re, os, sys
from datetime import datetime

LOG_OUT = "/var/log/ssh_file_activity.log"
STATE = "/var/lib/ssh-file-activity.state"
os.makedirs(os.path.dirname(STATE), exist_ok=True)

# Regex helpers
RE_FIELD = re.compile(r'(\b[a-zA-Z_]+)=(?:"([^"]+)"|([^\s]+))')
RE_TIME = re.compile(r'time->([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\d{4})')
# Map syscall -> action label
ACTION_MAP = {
    'creat': 'created',
    'open': 'accessed',
    'openat': 'accessed',
    'unlink': 'deleted',
    'unlinkat': 'deleted',
    'rename': 'renamed',
    'renameat': 'renamed',
    'truncate': 'modified',
    'ftruncate': 'modified',
    'chmod': 'perm_changed',
    'fchmod': 'perm_changed',
    'chown': 'owner_changed',
    'fchown': 'owner_changed',
    'utime': 'time_changed',
    'utimes': 'time_changed',
}

def run(cmd):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True).stdout

def parse_fields(line):
    return {k: (v1 if v1 is not None else v2) for k, v1, v2 in RE_FIELD.findall(line)}

def load_last_ts():
    try:
        with open(STATE, 'r') as f:
            s = f.read().strip()
            return float(s)
    except:
        return 0.0

def save_last_ts(ts):
    with open(STATE, 'w') as f:
        f.write(str(ts))

def parse_time(audit_text):
    # Prefer header time->..., fallback to now
    m = RE_TIME.search(audit_text)
    if m:
        # Convert to a uniform format
        try:
            dt = datetime.strptime(m.group(1), "%a %b %d %H:%M:%S.%f %Y")
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            pass
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def get_ip_for_session(ses):
    # Find USER_LOGIN for this session with addr not '?'
    out = run(["ausearch", "-m", "USER_LOGIN", "-se", ses, "-i"])
    ip = None
    acct = None
    for line in out.splitlines():
        if "type=USER_LOGIN" in line:
            f = parse_fields(line)
            # Only accept sshd-driven logins with remote addr
            addr = f.get("addr", None)
            exe = f.get("exe", "")
            acct = f.get("acct", None)
            if addr and addr != "?" and ("sshd" in exe):
                ip = addr
                break
    return ip, acct

def get_events_since(ts_since):
    # Pull ssh_fs syscall events since last timestamp
    # -k ssh_fs key is set in rules
    # Use ausearch -k KEY -ts recent_time
    # If ts_since==0, pull last 10 minutes to bootstrap
    ts_arg = "recent"
    if ts_since > 0:
        ts_arg = str(int(ts_since))
    # We use -i for interpreted fields (usernames, paths) when possible
    return run(["ausearch", "-k", "ssh_fs", "-ts", ts_arg, "-i"])

def extract_records(audit_blob):
    # Group multi-line audit events; find syscall and path records
    events = []
    current = []
    for line in audit_blob.splitlines():
        if line.startswith("----"):
            if current:
                events.append("\n".join(current))
                current = []
        else:
            current.append(line)
    if current:
        events.append("\n".join(current))
    return events

def summarize_event(ev):
    # Identify syscall line
    syscall_line = None
    path_line = None
    for line in ev.splitlines():
        if "type=SYSCALL" in line and "syscall=" in line:
            syscall_line = line
        if "type=PATH" in line and ("name=" in line or "obj=" in line):
            path_line = line
    if not syscall_line or not path_line:
        return None

    sysf = parse_fields(syscall_line)
    pathf = parse_fields(path_line)
    ses = sysf.get("ses", None)
    acct = sysf.get("acct", None)
    syscall = sysf.get("syscall", None)
    exe = sysf.get("exe", None)
    auid = sysf.get("auid", None)
    success = sysf.get("success", None)
    # File path can be in name= or obj=
    fpath = pathf.get("name", pathf.get("obj", None))

    # Map syscall number/name: ausearch -i reports names already
    action = ACTION_MAP.get(syscall, "accessed")

    # Resolve time
    t = parse_time(ev)

    # Get IP via session correlation; ignore if local ('?')
    ip, acct_login = get_ip_for_session(ses or "")
    if not ip:
        return None  # ignore local/console, proxmox terminals

    # Prefer acct from USER_LOGIN if present
    acct_final = acct_login or acct or "unknown"

    return {
        "time": t,
        "acct": acct_final,
        "file": fpath or "unknown",
        "action": action,
        "ip": ip
    }

def write_log(entry):
    line = f"Time: {entry['time']} Account: {entry['acct']} File: {entry['file']} Action: {entry['action']} IP Address: {entry['ip']}\n"
    with open(LOG_OUT, 'a') as f:
        f.write(line)

def main():
    # Ensure log file exists
    try:
      open(LOG_OUT, 'a').close()
    except:
      pass

    last_ts = load_last_ts()
    # On first run, look back 10 minutes only
    if last_ts == 0:
        last_ts = time.time() - 600

    while True:
        audit_blob = get_events_since(last_ts)
        events = extract_records(audit_blob)
        for ev in events:
            summary = summarize_event(ev)
            if summary:
                write_log(summary)
        # Advance the cursor modestly
        now = time.time()
        save_last_ts(now)
        time.sleep(2)

if __name__ == "__main__":
    # Check dependencies
    for dep in ["ausearch"]:
        if not shutil.which(dep) if 'shutil' in globals() else subprocess.run(["which", dep], stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 1:
            pass  # We'll rely on system having auditd tools installed by setup
    main()
PYEOF

  chmod +x "$PARSER_BIN"
}

write_service() {
  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=SSH file activity monitor (session->IP correlation)
After=auditd.service
Requires=auditd.service

[Service]
Type=simple
ExecStart=$PARSER_BIN
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable ssh-file-activity.service
  systemctl restart ssh-file-activity.service
}

need_root
ensure_auditd
write_rules
write_parser
write_service

echo "Installed. Log output: $LOG_OUT"
echo "Service: ssh-file-activity.service"
