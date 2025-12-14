#!/usr/bin/env bash
set -euo pipefail

LOG="/var/log/ssh_file_activity.log"
HOOK_BIN="/usr/local/bin/ssh_cmd_logger.sh"
BASH_HOOK="/etc/profile.d/ssh_command_logger.sh"
ZSH_HOOK="/etc/zsh/zshrc.d/ssh_command_logger.zsh"

# Create log file
touch "$LOG"
chmod 600 "$LOG"
chown root:root "$LOG"
command -v chattr >/dev/null && chattr +a "$LOG" || true

# Logger binary
cat > "$HOOK_BIN" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
LOG="/var/log/ssh_file_activity.log"
user="${1:-unknown}"
ip="${2:-unknown}"
cwd="${3:-/}"
cmd="${4:-}"
ts="$(date +"%Y-%m-%d %H:%M:%S")"
files=()
for word in $cmd; do [[ "$word" == /* ]] && files+=("$word"); done
file_list="${files[*]:-N/A}"
action=$([ "${#files[@]}" -gt 0 ] && echo "accessed" || echo "command")
printf "Time: %s Account: %s CWD: %s File: %s Action: %s Command: %s IP Address: %s\n" \
  "$ts" "$user" "$cwd" "$file_list" "$action" "$cmd" "$ip" >> "$LOG"
EOF
chmod +x "$HOOK_BIN"

# Bash hook
cat > "$BASH_HOOK" <<'EOF'
[ -n "$PS1" ] || return 0
[ -n "$SSH_CONNECTION" ] || return 0
IP="${SSH_CONNECTION%% *}"
trap 'cmd="$BASH_COMMAND"; /usr/local/bin/ssh_cmd_logger.sh "$USER" "$IP" "$PWD" "$cmd"' DEBUG
EOF
chmod 644 "$BASH_HOOK"

# Zsh hook
mkdir -p "$(dirname "$ZSH_HOOK")"
cat > "$ZSH_HOOK" <<'EOF'
[[ -o interactive ]] || return 0
[ -n "$SSH_CONNECTION" ] || return 0
IP="${SSH_CONNECTION%% *}"
function preexec() {
  cmd="$1"
  /usr/local/bin/ssh_cmd_logger.sh "$USER" "$IP" "$PWD" "$cmd"
}
EOF
chmod 644 "$ZSH_HOOK"

# Ensure zsh loads hook
grep -q 'zshrc.d' /etc/zsh/zshrc || echo 'for f in /etc/zsh/zshrc.d/*.zsh; do source "$f"; done' >> /etc/zsh/zshrc

echo "SSH command logger installed."
echo "• Log file: $LOG"
echo "• Hooks: bash + zsh"
echo "• No debugging needed. Just SSH in and test."
