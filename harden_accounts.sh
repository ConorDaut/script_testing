#!/usr/bin/env bash

# Made using Copilot AI
# Harden accounts: change passwords, add nologin, and scan for irregular users
# Works across most Linux distros using core utilities (awk, grep, sed, passwd, usermod, chsh).
# Usage: sudo ./harden_accounts.sh or sudo bash harden_accounts.sh

set -euo pipefail

# ---------- Helpers ----------

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
  fi
}

pause() {
  read -r -p "Press Enter to continue..."
}

confirm() {
  # Usage: confirm "message"
  local msg="${1:-Proceed?}"
  read -r -p "$msg [y/N]: " ans
  case "${ans:-}" in
    y|Y|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

# Prefer common nologin shells in portable order
detect_nologin_shell() {
  local candidates=("/usr/sbin/nologin" "/sbin/nologin" "/bin/false")
  for s in "${candidates[@]}"; do
    if [ -x "$s" ] || [ -f "$s" ]; then
      echo "$s"
      return 0
    fi
  done
  # Fallback even if not present (some systems still accept it)
  echo "/usr/sbin/nologin"
}

# Get passwd entries safely
get_passwd() {
  cat /etc/passwd
}

# Extract username, UID, shell from /etc/passwd
# Fields: name:passwd:uid:gid:gecos:home:shell
list_users() {
  get_passwd | awk -F: '{print $1":"$3":"$7}'
}

# Consider a shell "login-capable" if not nologin/false
is_login_shell() {
  local shell="$1"
  case "$shell" in
    */nologin|*/false|"") return 1 ;;
    *) return 0 ;;
  esac
}

# UID thresholds (portable heuristics)
# - Many distros: system UIDs < 1000; some like RHEL use < 1000, Alpine often < 1000 too.
SYSTEM_UID_MAX=999

# Baseline standard system accounts across common distros (Debian/Ubuntu, RHEL/CentOS, Arch, Alpine)
# This list is conservative; irregulars are informational only.
STANDARD_SYSTEM_ACCOUNTS="$(
  cat <<'EOF'
root
bin
daemon
sys
sync
games
man
lp
mail
news
uucp
proxy
www-data
backup
list
irc
gnats
nobody
systemd-coredump
systemd-network
systemd-resolve
systemd-timesync
systemd-oom
messagebus
dbus
sshd
chrony
ntp
avahi
postfix
mysql
mariadb
postgres
postgresql
redis
influxdb
cockpit
polkitd
dnsmasq
rpc
rpcuser
nfsnobody
statd
ftp
tss
usbmux
kvm
libvirt-qemu
qemu
lightdm
gdm
saned
cups
named
bind
radiusd
nginx
http
httpd
haproxy
etcd
consul
zabbix
graylog
logstash
jenkins
prometheus
node_exporter
alertmanager
EOF
)"

# Allow extension via environment: export EXTRA_STANDARD_ACCOUNTS="svc_app svc_ci"
EXTRA_STANDARD_ACCOUNTS="${EXTRA_STANDARD_ACCOUNTS:-}"

is_standard_account() {
  local user="$1"
  # Check baseline
  if grep -qx "$user" <<<"$STANDARD_SYSTEM_ACCOUNTS"; then
    return 0
  fi
  # Check extra provided by admin
  if [ -n "$EXTRA_STANDARD_ACCOUNTS" ]; then
    for u in $EXTRA_STANDARD_ACCOUNTS; do
      if [ "$u" = "$user" ]; then
        return 0
      fi
    done
  fi
  return 1
}

# ---------- Operations ----------

change_all_passwords() {
  echo "=== Change passwords for accounts with login-capable shells (including root) ==="
  echo "You will be prompted per user. Skipping any user leaves their password unchanged."
  echo

  local changed=0
  while IFS=: read -r user uid shell; do
    # Skip empty user lines
    [ -z "$user" ] && continue

    # Only propose changing for login-capable shells
    if is_login_shell "$shell"; then
      echo "User: $user (UID: $uid, Shell: $shell)"
      if confirm "Change password for '$user'?"; then
        if has_cmd passwd; then
          echo "Invoking passwd for '$user'..."
          passwd "$user"
          changed=$((changed+1))
        elif has_cmd chpasswd; then
          echo "passwd not available; using chpasswd (you will enter password once)"
          read -r -s -p "Enter new password for '$user': " pw1; echo
          read -r -s -p "Confirm new password: " pw2; echo
          if [ "$pw1" != "$pw2" ]; then
            echo "Passwords do not match; skipping '$user'."
          else
            printf '%s:%s\n' "$user" "$pw1" | chpasswd
            changed=$((changed+1))
          fi
        else
          echo "No supported password-changing utility found (passwd/chpasswd). Skipping '$user'."
        fi
      else
        echo "Skipped '$user'."
      fi
      echo "----"
    fi
  done < <(list_users)

  echo "Password change flow complete. Users changed: $changed"
}

add_nologin_for_selected() {
  echo "=== Add nologin shell for selected users ==="
  local nologin_shell
  nologin_shell="$(detect_nologin_shell)"
  echo "Using nologin shell: $nologin_shell"
  echo

  local updated=0
  while IFS=: read -r user uid shell; do
    # Skip root login shell by default unless explicitly confirmed
    if [ "$user" = "root" ]; then
      # Show root; warn before changing
      if is_login_shell "$shell"; then
        echo "User: root (UID: $uid) currently has login shell: $shell"
        echo "WARNING: Changing root shell to nologin may lock you out."
        if confirm "Set root shell to nologin?"; then
          if has_cmd usermod; then
            usermod -s "$nologin_shell" root
            updated=$((updated+1))
            echo "Root shell updated to $nologin_shell"
          elif has_cmd chsh; then
            chsh -s "$nologin_shell" root
            updated=$((updated+1))
            echo "Root shell updated to $nologin_shell"
          else
            echo "No usermod/chsh available; cannot change root shell safely."
          fi
        else
          echo "Skipping root."
        fi
        echo "----"
      fi
      continue
    fi

    # Propose nologin only for users with login-capable shells
    if is_login_shell "$shell"; then
      echo "User: $user (UID: $uid) has shell: $shell"
      if confirm "Set '$user' shell to nologin ($nologin_shell)?"; then
        if has_cmd usermod; then
          usermod -s "$nologin_shell" "$user"
          updated=$((updated+1))
          echo "Updated '$user' shell to $nologin_shell"
        elif has_cmd chsh; then
          chsh -s "$nologin_shell" "$user"
          updated=$((updated+1))
          echo "Updated '$user' shell to $nologin_shell"
        else
          # Fallback: edit /etc/passwd directly (careful)
          echo "usermod/chsh not available; attempting direct /etc/passwd edit."
          # Create backup
          cp -a /etc/passwd "/etc/passwd.bak.$(date +%s)"
          # Use awk to rewrite the shell field
          awk -F: -v OFS=: -v U="$user" -v NS="$nologin_shell" '
            $1==U {$7=NS} {print}
          ' /etc/passwd > /etc/passwd.tmp && mv /etc/passwd.tmp /etc/passwd
          updated=$((updated+1))
          echo "Updated '$user' shell to $nologin_shell via direct edit."
        fi
      else
        echo "Skipped '$user'."
      fi
      echo "----"
    fi
  done < <(list_users)

  echo "Nologin updates complete. Users updated: $updated"
}

scan_irregular_accounts() {
  echo "=== Scan for irregular user accounts ==="
  echo "- Heuristics:"
  echo "  * System UIDs typically <= $SYSTEM_UID_MAX."
  echo "  * Login-capable shell suggests interactive access."
  echo "  * Accounts not in baseline standard list may be custom (which can be normal)."
  echo
  echo "Baseline standard system accounts count: $(wc -l <<<"$STANDARD_SYSTEM_ACCOUNTS" | awk '{print $1}')"
  [ -n "$EXTRA_STANDARD_ACCOUNTS" ] && echo "Extra standard accounts provided: $EXTRA_STANDARD_ACCOUNTS"
  echo

  local irregular=0

  printf "%-20s %-8s %-30s %-20s\n" "USER" "UID" "SHELL" "REASON"
  printf "%-20s %-8s %-30s %-20s\n" "----" "----" "-----" "------"

  while IFS=: read -r user uid shell; do
    # Collect reasons
    reasons=()

    # Unknown system account with low UID
    if [ "$uid" -le "$SYSTEM_UID_MAX" ]; then
      if ! is_standard_account "$user"; then
        reasons+=("Low UID not in standard list")
      fi
    fi

    # Low UID but login-capable shell
    if [ "$uid" -le "$SYSTEM_UID_MAX" ] && is_login_shell "$shell"; then
      reasons+=("System UID has login shell")
    fi

    # High UID but nonstandard shell (rarely concerning)
    if [ "$uid" -gt "$SYSTEM_UID_MAX" ] && ! is_login_shell "$shell"; then
      reasons+=("Regular UID with nologin/false shell (check intent)")
    fi

    # Service-looking names with real shells
    if is_login_shell "$shell"; then
      case "$user" in
        *_svc|svc_*|service_*|daemon_*|*_daemon)
          reasons+=("Service-like name with login shell")
        ;;
      esac
    fi

    # Print if any reasons
    if [ "${#reasons[@]}" -gt 0 ]; then
      irregular=$((irregular+1))
      printf "%-20s %-8s %-30s %-20s\n" "$user" "$uid" "$shell" "$(IFS='; '; echo "${reasons[*]}")"
    fi
  done < <(list_users)

  echo
  echo "Scan complete. Potential irregular accounts flagged: $irregular"
  echo "Note: Irregular does not mean malicious; review in context of your system."
}

# ---------- Menu ----------

show_menu() {
  cat <<'EOF'
============================================================
Account Hardening Menu
============================================================
1) Change all user account passwords (interactive, includes root)
2) Add nologin shell for selected users (interactive choices)
3) Scan /etc/passwd for potential irregular accounts
4) Exit
EOF
}

main() {
  require_root

  # Sanity checks on critical files
  for f in /etc/passwd /etc/shadow; do
    if [ ! -r "$f" ]; then
      echo "WARNING: Cannot read $f; some operations may be limited."
    fi
  done

  while true; do
    show_menu
    read -r -p "Select an option [1-4]: " choice
    case "${choice:-}" in
      1) change_all_passwords; pause ;;
      2) add_nologin_for_selected; pause ;;
      3) scan_irregular_accounts; pause ;;
      4) echo "Exiting."; exit 0 ;;
      *) echo "Invalid choice. Please select 1-4." ;;
    esac
  done
}

main "$@"
