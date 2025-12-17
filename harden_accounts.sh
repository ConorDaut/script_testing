#!/usr/bin/env bash

# harden_accounts.sh
# Harden user accounts: change passwords, enforce nologin, and scan for suspicious accounts.
# Portable across major Linux distros.
# Made with Copilot AI

set -euo pipefail

# --- Helpers ---
error() { printf "Error: %s\n" "$1" >&2; }
info()  { printf "%s\n" "$1"; }

require_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    error "This script must be run as root."
    exit 1
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

# Detect nologin shell
detect_nologin_shell() {
  for s in /usr/sbin/nologin /sbin/nologin /bin/false; do
    if [ -x "$s" ] || [ -f "$s" ]; then
      echo "$s"
      return
    fi
  done
  echo "/bin/false"
}

# Expanded baseline accounts (system + service)
STANDARD_ACCOUNTS="
root
bin
daemon
adm
lp
sync
shutdown
halt
mail
news
uucp
operator
games
gopher
ftp
nobody
systemd-network
systemd-resolve
systemd-timesync
systemd-coredump
dbus
sshd
rpc
rpcuser
nfsnobody
chrony
ntp
avahi
postfix
mysql
mariadb
postgres
redis
influxdb
polkitd
dnsmasq
cups
named
bind
nginx
http
httpd
haproxy
lightdm
gdm
saned
tss
usbmux
kvm
libvirt-qemu
qemu
"

is_standard_account() {
  grep -qx "$1" <<<"$STANDARD_ACCOUNTS"
}

list_users() {
  getent passwd | awk -F: '{print $1":"$3":"$7}'
}

# --- Password change flow ---
change_passwords() {
  info "=== Change passwords for non-system accounts ==="
  while IFS=: read -r user uid shell; do
    if ! is_standard_account "$user"; then
      printf "Change password for '%s'? [y/N]: " "$user"
      read -r ans
      case "${ans:-}" in
        y|Y)
          local p1 p2
          while :; do
            printf "Enter new password for '%s': " "$user"
            stty -echo; read -r p1; stty echo; printf "\n"
            printf "Confirm password: "
            stty -echo; read -r p2; stty echo; printf "\n"
            [ "$p1" = "$p2" ] || { error "Passwords do not match."; continue; }
            printf "%s:%s\n" "$user" "$p1" | chpasswd
            info "Password updated for '$user'."
            break
          done
          ;;
        *) info "Skipped '$user'." ;;
      esac
    fi
  done < <(list_users)
}

# --- Nologin enforcement ---
set_nologin() {
  local nologin_shell
  nologin_shell="$(detect_nologin_shell)"
  info "=== Enforce nologin for selected accounts ==="
  cp -a /etc/passwd "/etc/passwd.bak.$(date +%s)"
  while IFS=: read -r user uid shell; do
    if ! is_standard_account "$user" && [ "$user" != "root" ]; then
      if [ "$shell" != "$nologin_shell" ]; then
        printf "Set nologin for '%s'? [y/N]: " "$user"
        read -r ans
        case "${ans:-}" in
          y|Y)
            usermod -s "$nologin_shell" "$user"
            info "Shell for '$user' set to $nologin_shell."
            ;;
          *) info "Skipped '$user'." ;;
        esac
      fi
    fi
  done < <(list_users)
}

# --- Suspicious account scan ---
scan_accounts() {
  info "=== Suspicious account scan ==="
  local suspicious=0
  while IFS=: read -r user uid shell; do
    if ! is_standard_account "$user"; then
      suspicious=$((suspicious+1))
      printf "Suspicious: %-15s UID=%-5s Shell=%s\n" "$user" "$uid" "$shell"
      # Extra heuristic: lookalike names
      case "$user" in
        r00t|root1|admin1|adm1n|toor)
          printf "  -> Name resembles critical account!\n"
          ;;
      esac
    fi
  done < <(list_users)
  info "Total suspicious accounts flagged: $suspicious"
}

# --- Menu ---
show_menu() {
  cat <<EOF
============================================================
Account Hardening Menu
============================================================
1) Change passwords for non-standard accounts
2) Set nologin shell for non-standard accounts
3) Scan for suspicious accounts
4) Exit
EOF
}

main() {
  require_root
  while true; do
    show_menu
    printf "Select option [1-4]: "
    read -r choice
    case "$choice" in
      1) change_passwords ;;
      2) set_nologin ;;
      3) scan_accounts ;;
      4) exit 0 ;;
      *) error "Invalid choice." ;;
    esac
  done
}

main "$@"
