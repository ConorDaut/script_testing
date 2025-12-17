#!/usr/bin/env bash

# harden_accounts.sh
# Harden user accounts: change passwords, enforce nologin, and scan for suspicious accounts.
# Portable across major Linux distros (Debian/Ubuntu, RHEL/CentOS/Fedora, SUSE, Arch, Alpine, etc.).
# Made using Copilot AI

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

detect_nologin_shell() {
  for s in /usr/sbin/nologin /sbin/nologin /bin/false; do
    if [ -x "$s" ] || [ -f "$s" ]; then
      printf "%s" "$s"
      return 0
    fi
  done
  printf "/bin/false"
}

# --- Expanded baseline of standard/system/service accounts ---
# Coverage includes: core system users, systemd, desktop services, network daemons,
# databases, web servers, monitoring, virtualization, mail, printing, crypto/security,
# containers, VPN, DNS, logging, and common distro-specific utilities.
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
nogroup
systemd-coredump
systemd-network
systemd-resolve
systemd-timesync
systemd-oom
messagebus
dbus
uuidd
sshd
pulse
rtkit
avahi
dnsmasq
named
bind
nsd
unbound
chrony
ntp
openvpn
strongswan
wg
wireguard
cups
saned
postfix
exim
smmsp
dovecot
mysql
mariadb
postgres
postgresql
mongodb
couchdb
redis
influxdb
elasticsearch
logstash
kibana
graylog
prometheus
node_exporter
alertmanager
grafana
zabbix
telegraf
fluentd
fluent-bit
journald
rsyslog
syslog
www-data
http
httpd
nginx
haproxy
apache
lighttpd
traefik
cockpit
polkitd
tss
tpm
clamav
amavis
spamassassin
fail2ban
shorewall
ufw
firewalld
docker
containerd
cri-o
podman
kube
kubelet
etcd
consul
nomad
vault
rabbitmq
memcached
ejabberd
prosody
vsftpd
proftpd
pure-ftpd
tftp
ntpd
nfsnobody
rpc
rpcuser
statd
lockd
sssd
ldap
openldap
samba
winbind
libvirt-qemu
libvirt-dnsmasq
libvirt
qemu
kvm
lxd
lightdm
gdm
sddm
cups-pk-helper
colord
flatpak
geoclue
snapd
man
www
backup
list
irc
gnats
system
sys
lpadmin
postmaster
"

# Allow admin to extend baseline dynamically (space-separated list)
EXTRA_STANDARD_ACCOUNTS="${EXTRA_STANDARD_ACCOUNTS:-}"

is_standard_account() {
  local user="$1"
  # Baseline check
  if grep -qx "$user" <<<"$STANDARD_ACCOUNTS"; then
    return 0
  fi
  # Admin extensions
  if [ -n "$EXTRA_STANDARD_ACCOUNTS" ]; then
    for u in $EXTRA_STANDARD_ACCOUNTS; do
      [ "$u" = "$user" ] && return 0
    done
  fi
  return 1
}

# Robust user listing via NSS
list_users() {
  # name:uid:shell
  getent passwd | awk -F: '{print $1":"$3":"$7}'
}

# --- Password change flow (interactive, modeled on your backup admin script) ---
change_passwords() {
  info "=== Change passwords for selected accounts ==="
  info "You will be prompted per account (including root)."
  while IFS=: read -r user uid shell; do
    printf "Change password for '%s'? [y/N]: " "$user"
    IFS= read -r ans
    case "${ans:-}" in
      y|Y)
        # Prefer chpasswd (non-interactive), fallback to passwd
        if have_cmd chpasswd; then
          local p1 p2
          while :; do
            printf "Enter new password for '%s': " "$user"
            stty -echo; IFS= read -r p1; stty echo; printf "\n"
            [ -n "$p1" ] || { error "Password cannot be empty."; continue; }
            printf "Confirm password: "
            stty -echo; IFS= read -r p2; stty echo; printf "\n"
            [ "$p1" = "$p2" ] || { error "Passwords do not match."; continue; }
            printf "%s:%s\n" "$user" "$p1" | chpasswd
            info "Password updated for '$user'."
            break
          done
        elif have_cmd passwd; then
          info "chpasswd not available; invoking passwd for '$user'..."
          passwd "$user"
        else
          error "No supported password-changing utility found (chpasswd/passwd). Skipping '$user'."
        fi
        ;;
      *) info "Skipped '$user'." ;;
    esac
  done < <(list_users)
}

# --- Nologin enforcement (reliable with usermod, safe fallback if needed) ---
set_nologin() {
  local nologin_shell
  nologin_shell="$(detect_nologin_shell)"
  info "=== Enforce nologin for selected accounts ==="
  info "Using nologin shell: $nologin_shell"
  cp -a /etc/passwd "/etc/passwd.bak.$(date +%s)"

  while IFS=: read -r user uid shell; do
    # Protect root by default (explicit warning if attempting to change)
    if [ "$user" = "root" ]; then
      printf "Set nologin for 'root'? This may lock you out. [y/N]: "
      IFS= read -r ans_root
      case "${ans_root:-}" in
        y|Y)
          if have_cmd usermod; then
            usermod -s "$nologin_shell" root
            info "Root shell updated to $nologin_shell."
          elif have_cmd chsh; then
            chsh -s "$nologin_shell" root
            info "Root shell updated to $nologin_shell."
          else
            # Fallback: direct edit (careful)
            awk -F: -v OFS=: -v U="root" -v NS="$nologin_shell" '
              $1==U {$7=NS} {print}
            ' /etc/passwd > /etc/passwd.tmp && mv /etc/passwd.tmp /etc/passwd
            info "Root shell updated to $nologin_shell via direct edit."
          fi
          ;;
        *) info "Skipping root." ;;
      esac
      continue
    fi

    # Show current shell and prompt
    printf "Set nologin for '%s' (current shell: %s)? [y/N]: " "$user" "$shell"
    IFS= read -r ans
    case "${ans:-}" in
      y|Y)
        if have_cmd usermod; then
          usermod -s "$nologin_shell" "$user"
          info "Shell for '$user' set to $nologin_shell."
        elif have_cmd chsh; then
          chsh -s "$nologin_shell" "$user"
          info "Shell for '$user' set to $nologin_shell."
        else
          # Fallback: direct edit with backup already made
          awk -F: -v OFS=: -v U="$user" -v NS="$nologin_shell" '
            $1==U {$7=NS} {print}
          ' /etc/passwd > /etc/passwd.tmp && mv /etc/passwd.tmp /etc/passwd
          info "Shell for '$user' set to $nologin_shell via direct edit."
        fi
        ;;
      *) info "Skipped '$user'." ;;
    esac
  done < <(list_users)
}

# --- Suspicious account scan (flags everything not in standard baseline) ---
scan_suspicious() {
  info "=== Suspicious account scan ==="
  [ -n "$EXTRA_STANDARD_ACCOUNTS" ] && info "Extra baseline accounts: $EXTRA_STANDARD_ACCOUNTS"
  local suspicious=0

  while IFS=: read -r user uid shell; do
    if ! is_standard_account "$user"; then
      suspicious=$((suspicious+1))
      printf "Suspicious: %-18s UID=%-6s Shell=%s\n" "$user" "$uid" "$shell"
      # Heuristics for lookalikes / high-risk names
      case "$user" in
        r00t|toor|root1|adm1n|admin1|support|helpdesk|service|daemon|system|sysadmin|sysadm|backup|operator1)
          printf "  -> Name resembles a critical or generic admin/service account.\n"
          ;;
        *root*|*admin*|*adm*|*sudo*|*wheel*)
          printf "  -> Contains privileged keyword (root/admin/sudo/wheel).\n"
          ;;
        *_svc|svc_*|service_*|*_service|*_daemon|daemon_*)
          printf "  -> Service-like naming; verify shell/UID and necessity.\n"
          ;;
      esac
      # UID heuristics
      if [ "$uid" -le 999 ]; then
        printf "  -> Low UID (system range) but not in baseline list.\n"
      fi
      # Shell heuristics
      case "$shell" in
        */nologin|*/false|"")
          printf "  -> Non-login shell; likely a service account.\n"
          ;;
        *)
          printf "  -> Login-capable shell; review if interactive access is intended.\n"
          ;;
      esac
    fi
  done < <(list_users)

  info "Total suspicious accounts flagged: $suspicious"
}

# --- Menu ---
show_menu() {
  cat <<'EOF'
============================================================
Account Hardening Menu
============================================================
1) Change passwords (prompt for every account, including root)
2) Set nologin shell (prompt for every account; root warns)
3) Scan for suspicious accounts (not in standard baseline)
4) Exit
EOF
}

main() {
  require_root

  # Sanity warnings if key utilities missing
  if ! have_cmd chpasswd && ! have_cmd passwd; then
    error "Neither 'chpasswd' nor 'passwd' is available. Password changes will fail."
  fi
  if ! have_cmd usermod && ! have_cmd chsh; then
    error "Neither 'usermod' nor 'chsh' is available. Nologin changes will use direct /etc/passwd edits."
  fi

  while true; do
    show_menu
    printf "Select option [1-4]: "
    IFS= read -r choice
    case "${choice:-}" in
      1) change_passwords ;;
      2) set_nologin ;;
      3) scan_suspicious ;;
      4) info "Exiting."; exit 0 ;;
      *) error "Invalid choice. Please select 1-4." ;;
    esac
    printf "Press Enter to continue..."
    IFS= read -r _ || true
  done
}

main "$@"

