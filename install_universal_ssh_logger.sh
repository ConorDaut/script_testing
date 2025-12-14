#!/usr/bin/env bash
set -euo pipefail

LOG_OUT="/var/log/ssh_file_activity.log"
LOGGER_BIN="/usr/local/bin/ssh_cmd_logger.sh"
PROFILE_SNIPPET="/etc/profile.d/ssh_command_logger.sh"
ZSH_SNIPPET_DIR="/etc/zsh"
ZSH_SNIPPET_FILE="/etc/zsh/zshrc.d/ssh_command_logger.zsh"

# 1) Prepare persistent, append-only log file
touch "$LOG_OUT"
chmod 600 "$LOG_OUT"
if command -v chattr >/dev/null 2>&1; then
  chattr +a "$LOG_OUT" || true
fi

# 2) Command logger helper (used by hooks)
cat > "$LOGGER_BIN" <<'EOF'
#!/usr/bin/env bash
# Usage: ssh_cmd_logger <user> <ip> <cwd> <command>
set -euo pipefail
LOG_OUT="/var/log/ssh_file_activity.log"

user="${1:-unknown}"
ip="${2:-unknown}"
cwd="${3:-/}"
cmd="${4:-}"

# Extract absolute file paths mentioned in the command
files=()
# shellcheck disable=SC2206
for word in $cmd; do
  case "$word" in
    /*) files+=("$word") ;;
  esac
done

if [ "${#files[@]}" -gt 0 ]; then
  file_list="${files[*]}"
  action="accessed"
else
  file_list="N/A"
  action="command"
fi

ts="$(date +"%Y-%m-%d %H:%M:%S")"
printf "Time: %s Account: %s CWD: %s File: %s Action: %s Command: %s IP Address: %s\n" \
  "$ts" "$user" "$cwd" "$file_list" "$action" "$cmd" "$ip" >> "$LOG_OUT"
EOF
chmod +x "$LOGGER_BIN"

# 3) Install profile hook for bash and zsh (SSH-only)
cat > "$PROFILE_SNIPPET" <<'EOF'
# ssh_command_logger: activate for interactive SSH sessions only
# Works for bash; zsh uses a dedicated snippet installed separately.

# Require interactive shell
[ -n "$PS1" ] || return 0

# Require SSH session (skip local/Proxmox consoles)
[ -n "$SSH_CONNECTION" ] || return 0

# Extract remote IP from SSH_CONNECTION (format: "ip port localip port")
SSH_REMOTE_IP="${SSH_CONNECTION%% *}"

# Lightweight filter to avoid trivial noise
__ssh_cmd_should_log() {
  case "$1" in
    ""|history*|fg|bg|jobs|pwd) return 1 ;;
    *) return 0 ;;
  esac
}

# Bash hook: use DEBUG trap for real-time command capture
if [ -n "$BASH" ]; then
  trap '{
    cmd="$BASH_COMMAND"
    __ssh_cmd_should_log "$cmd" || return 0
    # Use $PWD for current directory
    /usr/local/bin/ssh_cmd_logger.sh "$USER" "$SSH_REMOTE_IP" "$PWD" "$cmd"
  }' DEBUG
fi
EOF
chmod 644 "$PROFILE_SNIPPET"

# 4) Install zsh preexec hook if zsh is present
if command -v zsh >/dev/null 2>&1; then
  mkdir -p "$ZSH_SNIPPET_DIR/zshrc.d"
  cat > "$ZSH_SNIPPET_FILE" <<'EOF'
# ssh_command_logger for zsh: activate for interactive SSH sessions only

# Require interactive zsh
[[ -o interactive ]] || return 0
# Require SSH session (skip local/Proxmox consoles)
[ -n "$SSH_CONNECTION" ] || return 0

# Extract remote IP
SSH_REMOTE_IP="${SSH_CONNECTION%% *}"

__ssh_cmd_should_log() {
  case "$1" in
    ""|history*|fg|bg|jobs|pwd) return 1 ;;
    *) return 0 ;;
  esac
}

# preexec runs just before a command executes
function preexec() {
  local cmd="$1"
  __ssh_cmd_should_log "$cmd" || return 0
  /usr/local/bin/ssh_cmd_logger.sh "$USER" "$SSH_REMOTE_IP" "$PWD" "$cmd"
}
EOF
  chmod 644 "$ZSH_SNIPPET_FILE"
fi

# 5) Ensure these are picked up by new SSH sessions
# (sshd already sets SSH_CONNECTION; profile scripts load automatically for interactive shells.)

# 6) Final messages
echo "Installed universal SSH command logger."
echo "• Log file: $LOG_OUT (append-only best effort)"
echo "• Bash hook: $PROFILE_SNIPPET"
if command -v zsh >/dev/null 2>&1; then
  echo "• Zsh hook: $ZSH_SNIPPET_FILE"
fi
echo "• New SSH interactive sessions will be logged automatically."
echo "• Local/Proxmox console sessions are ignored."
