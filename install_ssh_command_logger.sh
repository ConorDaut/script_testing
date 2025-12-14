#!/usr/bin/env bash
set -euo pipefail

LOG_OUT="/var/log/ssh_file_activity.log"
PROFILE_SNIPPET="/etc/profile.d/ssh_command_logger.sh"

# 1) Prepare persistent, append-only log file
touch "$LOG_OUT"
chmod 600 "$LOG_OUT"
# Make append-only if chattr is available (best effort)
if command -v chattr >/dev/null 2>&1; then
  chattr +a "$LOG_OUT" || true
fi

# 2) Install a profile hook for all future SSH bash sessions
cat > "$PROFILE_SNIPPET" <<'EOF'
# ssh_command_logger: log every command for SSH bash sessions
# Loads only in interactive bash with an SSH connection.
# Appends clean lines to /var/log/ssh_file_activity.log without relying on bash history.

# Require interactive bash
[ -n "$PS1" ] || return 0
[ -n "$BASH" ] || return 0
# Require SSH session (skip local/Proxmox consoles)
[ -n "$SSH_CONNECTION" ] || return 0

# Extract remote IP from SSH_CONNECTION (format: "ip port localip port")
SSH_REMOTE_IP="${SSH_CONNECTION%% *}"

# Lightweight command filter (avoid logging empty/trivial internal updates)
__ssh_cmd_should_log() {
  case "$1" in
    ""|history*|fg|bg|jobs|pwd) return 1 ;;
    *) return 0 ;;
  esac
}

# DEBUG trap logs the command before execution
# Note: runs for each command line entered by the user
trap '{
  cmd="$BASH_COMMAND"
  __ssh_cmd_should_log "$cmd" || return 0
  ts=$(date +"%Y-%m-%d %H:%M:%S")

  # Try to extract absolute file paths referenced in the command (best effort)
  files=()
  for word in $cmd; do
    case "$word" in
      /*) files+=("$word") ;;
    esac
  done
  # Join array into space-separated string (or N/A)
  if [ ${#files[@]} -gt 0 ]; then
    file_list="${files[*]}"
    action="accessed"
  else
    file_list="N/A"
    action="command"
  fi

  # Write single-line entry
  printf "Time: %s Account: %s File: %s Action: %s Command: %s IP Address: %s\n" \
    "$ts" "$USER" "$file_list" "$action" "$cmd" "$SSH_REMOTE_IP" >> /var/log/ssh_file_activity.log
}' DEBUG
EOF

chmod 644 "$PROFILE_SNIPPET"

echo "Installed SSH command logger."
echo "• Log file: $LOG_OUT (append-only best effort)"
echo "• Profile hook: $PROFILE_SNIPPET"
echo "• New SSH bash sessions will be logged automatically."

