#!/usr/bin/env bash
set -euo pipefail

LOG_OUT="/var/log/ssh_file_activity.log"
WATCH_DIRS="/home /etc /var/www /opt"   # adjust as needed
AUTH_LOG="/var/log/auth.log"
SECURE_LOG="/var/log/secure"

# Ensure inotify-tools is installed
pm=""
if command -v apt-get >/dev/null 2>&1; then pm=apt-get
elif command -v dnf >/dev/null 2>&1; then pm=dnf
elif command -v yum >/dev/null 2>&1; then pm=yum
elif command -v zypper >/dev/null 2>&1; then pm=zypper
fi

if ! command -v inotifywait >/dev/null 2>&1; then
  case "$pm" in
    apt-get) apt-get update -y && apt-get install -y inotify-tools ;;
    dnf) dnf install -y inotify-tools ;;
    yum) yum install -y inotify-tools ;;
    zypper) zypper install -y inotify-tools ;;
    *) echo "Please install inotify-tools manually"; exit 1 ;;
  esac
fi

touch "$LOG_OUT"

# Function: get active SSH sessions (account -> IP)
get_ssh_sessions() {
  local logfile=""
  if [ -f "$AUTH_LOG" ]; then logfile="$AUTH_LOG"
  elif [ -f "$SECURE_LOG" ]; then logfile="$SECURE_LOG"
  fi
  # Parse last 100 lines for active sessions
  last -Fi | grep "still logged in" | awk '{print $1,$3}'
}

# Function: log event
log_event() {
  local account="$1"
  local ip="$2"
  local file="$3"
  local action="$4"
  local time
  time=$(date +"%Y-%m-%d %H:%M:%S")
  echo "Time: $time Account: $account File: $file Action: $action IP Address: $ip" >> "$LOG_OUT"
}

# Monitor loop
while true; do
  inotifywait -r -e create,modify,open,delete,move $WATCH_DIRS --format '%e %w%f' |
  while read event file; do
    # Map event to action
    case "$event" in
      CREATE*) action="created" ;;
      MODIFY*) action="modified" ;;
      OPEN*)   action="accessed" ;;
      DELETE*) action="deleted" ;;
      MOVED*)  action="renamed" ;;
      *)       action="other" ;;
    esac

    # Get active SSH sessions
    while read account ip; do
      # Skip if IP is blank (local console)
      [ "$ip" = "-" ] && continue
      log_event "$account" "$ip" "$file" "$action"
    done < <(get_ssh_sessions)
  done
done
