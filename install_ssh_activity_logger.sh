#!/usr/bin/env bash
set -euo pipefail

LOG_OUT="/var/log/ssh_file_activity.log"
PARSER_BIN="/usr/local/bin/ssh_file_activity_monitor.py"
RULES_FILE="/etc/audit/rules.d/ssh_fs.rules"
SERVICE_FILE="/etc/systemd/system/ssh-file-activity.service"

# --- Detect package manager ---
detect_pm() {
  if command -v apt-get >/dev/null 2>&1; then echo apt
  elif command -v dnf >/dev/null 2>&1; then echo dnf
  elif command -v yum >/dev/null 2>&1; then echo yum
  elif command -v zypper >/dev/null 2>&1; then echo zypper
  else echo unknown
  fi
}

install_pkg() {
  local pm="$1" pkg="$2"
  case "$pm" in
    apt) apt-get update -y && apt-get install -y "$pkg" ;;
    dnf) dnf install -y "$pkg" ;;
    yum) yum install -y "$pkg" ;;
    zypper) zypper install -y "$pkg" ;;
    *) echo "Install $pkg manually"; exit 1 ;;
  esac
}

# --- Ensure auditd ---
pm=$(detect_pm)
if ! command -v auditctl >/dev/null 2>&1; then
  install_pkg "$pm" auditd || install_pkg "$pm" audit
fi
systemctl start auditd
systemctl enable auditd.service || true

# --- Write rules (persist + immediate load) ---
cat > "$RULES_FILE" <<'EOF'
# SSH file activity rules (all users, exclude unset auid)
-a always,exit -F arch=b64 -S open,openat,creat,truncate,ftruncate,unlink,unlinkat,rename,renameat,chmod,fchmod,chown,fchown,utime,utimes -F success=1 -F auid!=4294967295 -k ssh_fs
-a always,exit -F arch=b32 -S open,openat,creat,truncate,ftruncate,unlink,unlinkat,rename,renameat,chmod,fchmod,chown,fchown,utime,utimes -F success=1 -F auid!=4294967295 -k ssh_fs
EOF

# Load immediately
auditctl -D >/dev/null 2>&1 || true
auditctl -R "$RULES_FILE"

# --- Parser script ---
cat > "$PARSER_BIN" <<'PYEOF'
#!/usr/bin/env python3
import subprocess, time, re, os
from datetime import datetime

LOG_OUT="/var/log/ssh_file_activity.log"
STATE="/var/lib/ssh-file-activity.state"
os.makedirs(os.path.dirname(STATE), exist_ok=True)

RE_FIELD = re.compile(r'(\b[a-zA-Z_]+)=(?:"([^"]+)"|([^\s]+))')
RE_TIME = re.compile(r'time->([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\d{4})')
ACTION_MAP = {
    'creat':'created','open':'accessed','openat':'accessed','unlink':'deleted',
    'unlinkat':'deleted','rename':'renamed','renameat':'renamed','truncate':'modified',
    'ftruncate':'modified','chmod':'perm_changed','fchmod':'perm_changed',
    'chown':'owner_changed','fchown':'owner_changed','utime':'time_changed','utimes':'time_changed'
}

def run(cmd): return subprocess.run(cmd,stdout=subprocess.PIPE,text=True).stdout
def parse_fields(line): return {k:(v1 if v1 else v2) for k,v1,v2 in RE_FIELD.findall(line)}
def parse_time(blob):
    m=RE_TIME.search(blob)
    if m:
        try: return datetime.strptime(m.group(1),"%a %b %d %H:%M:%S.%f %Y").strftime("%Y-%m-%d %H:%M:%S")
        except: pass
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def get_ip_for_session(ses):
    out=run(["ausearch","-m","USER_LOGIN","-se",ses,"-i"])
    for line in out.splitlines():
        if "type=USER_LOGIN" in line:
            f=parse_fields(line)
            addr=f.get("addr"); exe=f.get("exe","")
            acct=f.get("acct")
            if addr and addr!="?" and "sshd" in exe: return addr,acct
    return None,None

def extract_records(blob):
    evs=[]; cur=[]
    for line in blob.splitlines():
        if line.startswith("----"):
            if cur: evs.append("\n".join(cur)); cur=[]
        else: cur.append(line)
    if cur: evs.append("\n".join(cur))
    return evs

def summarize(ev):
    syscall_line=None; path_line=None
    for line in ev.splitlines():
        if "type=SYSCALL" in line: syscall_line=line
        if "type=PATH" in line: path_line=line
    if not syscall_line or not path_line: return None
    sysf=parse_fields(syscall_line); pathf=parse_fields(path_line)
    ses=sysf.get("ses"); syscall=sysf.get("syscall"); fpath=pathf.get("name") or pathf.get("obj")
    action=ACTION_MAP.get(syscall,"accessed"); t=parse_time(ev)
    ip,acct=get_ip_for_session(ses or "")
    if not ip: return None
    return {"time":t,"acct":acct or sysf.get("acct","unknown"),"file":fpath or "unknown","action":action,"ip":ip}

def main():
    open(LOG_OUT,'a').close()
    while True:
        blob=run(["ausearch","-k","ssh_fs","-ts","recent","-i"])
        for ev in extract_records(blob):
            s=summarize(ev)
            if s:
                line=f"Time: {s['time']} Account: {s['acct']} File: {s['file']} Action: {s['action']} IP Address: {s['ip']}\n"
                with open(LOG_OUT,'a') as f: f.write(line)
        time.sleep(2)

if __name__=="__main__": main()
PYEOF

chmod +x "$PARSER_BIN"

# --- Service ---
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=SSH file activity monitor
After=auditd.service
Requires=auditd.service

[Service]
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

echo "Installed. Logs will append to $LOG_OUT"
