#!/usr/bin/env bash
set -euo pipefail

LOG_OUT="/var/log/ssh_file_activity.log"
touch "$LOG_OUT"
chmod 600 "$LOG_OUT"

# Function: get active SSH sessions (account -> IP)
get_ssh_sessions() {
  last -Fi | grep "still logged in" | awk '{print $1,$3}'
}

# Function: log event
log_event() {
  local account="$1"
  local ip="$2"
  local cmd="$3"
  local time
  time=$(date +"%Y-%m-%d %H:%M:%S")
  echo "Time: $time Account: $account Command: $cmd IP Address: $ip" >> "$LOG_OUT"
}

# Install a shell hook for each SSH user
install_hooks() {
  while read account ip; do
    [ "$ip" = "-" ] && continue  # skip local console
    homedir=$(getent passwd "$account" | cut -d: -f6)
    bashrc="$homedir/.bashrc"
    if [ -w "$bashrc" ]; then
      # Add a PROMPT_COMMAND hook if not already present
      if ! grep -q "ssh_file_activity" "$bashrc"; then
        echo 'export PROMPT_COMMAND="history -a; cmd=$(history 1 | sed \"s/^ *[0-9]\+ *//\"); echo \"Time: $(date +\"%Y-%m-%d %H:%M:%S\") Account: $USER Command: $cmd IP Address: $(who -u am i | awk \'{print $NF}\')\" >> /var/log/ssh_file_activity.log"' >> "$bashrc"
      fi
    fi
  done < <(get_ssh_sessions)
}

# Run once to install hooks
install_hooks
echo "✅ Hooks installed. All SSH commands will be logged to $LOG_OUT"
