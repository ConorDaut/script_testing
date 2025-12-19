#!/usr/bin/env bash
# Mail Server Hardener for Ubuntu
# - Harden Postfix, Dovecot, OpenDKIM, OpenDMARC, SpamAssassin, ClamAV, Fail2ban
# - Create backups and provide rollback
# - Interactive, modular, with logging and color-coded feedback

set -Eeuo pipefail

#############################
# Globals & Configuration   #
#############################

# Colors (fallback if unsupported)
if [[ -t 1 ]] && tput setaf 1 >/dev/null 2>&1; then
  RED=$(tput setaf 1); GREEN=$(tput setaf 2); YELLOW=$(tput setaf 3); BLUE=$(tput setaf 4); RESET=$(tput sgr0)
else
  RED=""; GREEN=""; YELLOW=""; BLUE=""; RESET=""
fi

# Log file for all actions
LOG_FILE="/var/log/mail_hardener.log"

# Default config directory (created if missing)
CONFIG_DIR="/etc/mail_hardener"
CONFIG_FILE="$CONFIG_DIR/config.sh"

# Backup directory (versioned archives)
BACKUP_DIR="/var/backups/mail_hardener"

# Common paths
DH_PARAM_FILE="/etc/ssl/dhparam.pem"

# Service lists for backup/rollback control (can be extended in config.sh)
SERVICES=(postfix dovecot opendkim opendmarc spamassassin clamav-daemon clamav-freshclam fail2ban)

# Files/directories to back up (expandable via config)
BACKUP_TARGETS=(
  "/etc/postfix"
  "/etc/dovecot"
  "/etc/opendkim"
  "/etc/opendmarc"
  "/etc/spamassassin"
  "/etc/clamav"
  "/etc/fail2ban"
  "/etc/ufw"
  "/etc/nftables.conf"
  "/etc/sysctl.conf"
  "$DH_PARAM_FILE"
)

# Interactive mode toggle (can be overridden in config)
INTERACTIVE=1
DRY_RUN=0

#############################
# Utility Functions         #
#############################

log() {
  # Log messages to file and stdout with levels
  local level="$1"; shift
  local msg="$*"
  local timestamp
  timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
  echo -e "[$timestamp] [$level] $msg" | tee -a "$LOG_FILE"
}

info()  { log "INFO"  "${BLUE}$*${RESET}"; }
ok()    { log "OK"    "${GREEN}$*${RESET}"; }
warn()  { log "WARN"  "${YELLOW}$*${RESET}"; }
error() { log "ERROR" "${RED}$*${RESET}"; }

confirm() {
  # Ask a yes/no question if INTERACTIVE=1, else default to yes
  local prompt="$1"
  if [[ "$INTERACTIVE" -eq 1 ]]; then
    read -r -p "$prompt [y/N]: " ans
    [[ "${ans:-N}" =~ ^[Yy]$ ]] && return 0 || return 1
  else
    return 0
  fi
}

require_root() {
  if [[ "$EUID" -ne 0 ]]; then
    error "Please run as root."
    exit 1
  fi
}

detect_ubuntu() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    if [[ "${ID:-}" != "ubuntu" ]]; then
      warn "This script targets Ubuntu. Detected: ${ID:-unknown}. Proceeding may require manual adjustments."
    else
      ok "Ubuntu detected: ${PRETTY_NAME:-Ubuntu}"
    fi
  else
    warn "Unable to detect OS via /etc/os-release. Proceeding cautiously."
  fi
}

ensure_dirs() {
  mkdir -p "$CONFIG_DIR" "$BACKUP_DIR"
  touch "$LOG_FILE"
}

load_or_create_config() {
  if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck disable=SC1090
    . "$CONFIG_FILE"
    ok "Loaded configuration from $CONFIG_FILE"
  else
    cat >"$CONFIG_FILE" <<'EOF'
# mail_hardener configuration
# Toggle interactive prompts (1=on, 0=off)
INTERACTIVE=1

# Enable dry-run to preview changes (1=on, 0=off)
DRY_RUN=0

# Domain for DKIM/DMARC (used to generate basic configs)
MAIL_DOMAIN="example.com"
DKIM_SELECTOR="default"

# Choose firewall: ufw or nftables (empty to skip firewall changes)
FIREWALL="ufw"

# Allowed mail ports (adjust per environment)
# SMTP: 25, 587; IMAP: 143, 993; POP3: 110, 995; LMTP for local: 24 (usually not public)
ALLOWED_MAIL_PORTS=(25 587 143 993 110 995)

# Services to manage (extend or reduce as needed)
SERVICES=(postfix dovecot opendkim opendmarc spamassassin clamav-daemon clamav-freshclam fail2ban)

# Backup targets (add any local customizations)
BACKUP_TARGETS=(
  "/etc/postfix"
  "/etc/dovecot"
  "/etc/opendkim"
  "/etc/opendmarc"
  "/etc/spamassassin"
  "/etc/clamav"
  "/etc/fail2ban"
  "/etc/ufw"
  "/etc/nftables.conf"
  "/etc/sysctl.conf"
  "/etc/ssl/dhparam.pem"
)
EOF
    ok "Created default config at $CONFIG_FILE. Edit it to fit your environment."
    # shellcheck disable=SC1090
    . "$CONFIG_FILE"
  fi
}

apt_install() {
  local pkgs=("$@")
  if [[ "$DRY_RUN" -eq 1 ]]; then
    info "DRY-RUN: Would install: ${pkgs[*]}"
    return 0
  fi
  DEBIAN_FRONTEND=noninteractive apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}"
}

svc_enable_restart() {
  local svc="$1"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    info "DRY-RUN: Would enable and restart $svc"
    return 0
  fi
  systemctl enable "$svc" || true
  systemctl restart "$svc"
  ok "Enabled and restarted $svc"
}

write_file_safe() {
  # Write content to file with a timestamped backup
  local file="$1"; shift
  local content="$*"
  if [[ -f "$file" ]]; then
    local ts
    ts="$(date '+%Y%m%d-%H%M%S')"
    cp -a "$file" "${file}.bak.${ts}"
    info "Backup created: ${file}.bak.${ts}"
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    info "DRY-RUN: Would write to $file"
    return 0
  fi
  printf "%s\n" "$content" > "$file"
  ok "Wrote: $file"
}

append_file_safe() {
  local file="$1"; shift
  local content="$*"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    info "DRY-RUN: Would append to $file"
    return 0
  fi
  printf "%s\n" "$content" >> "$file"
  ok "Appended: $file"
}

generate_dhparams() {
  if [[ -s "$DH_PARAM_FILE" ]]; then
    ok "DH params already exist: $DH_PARAM_FILE"
    return 0
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    info "DRY-RUN: Would generate 4096-bit DH params at $DH_PARAM_FILE"
    return 0
  fi
  info "Generating 4096-bit DH params (this may take a while)..."
  openssl dhparam -out "$DH_PARAM_FILE" 4096
  chmod 644 "$DH_PARAM_FILE"
  ok "Generated DH params: $DH_PARAM_FILE"
}

#############################
# Backup & Rollback         #
#############################

create_backup() {
  local ts archive
  ts="$(date '+%Y%m%d-%H%M%S')"
  archive="$BACKUP_DIR/mail_backup_${ts}.tar.gz"

  info "Creating backup at $archive"
  local include=()
  for path in "${BACKUP_TARGETS[@]}"; do
    [[ -e "$path" ]] && include+=("$path") || warn "Skipping missing: $path"
  done

  if [[ "$DRY_RUN" -eq 1 ]]; then
    info "DRY-RUN: Would tar up: ${include[*]}"
    return 0
  fi

  tar -czpf "$archive" "${include[@]}"
  ok "Backup created: $archive"
}

rollback_latest() {
  local latest
  latest="$(ls -1t "$BACKUP_DIR"/mail_backup_*.tar.gz 2>/dev/null | head -n1 || true)"
  if [[ -z "$latest" ]]; then
    error "No backups found in $BACKUP_DIR"
    exit 1
  fi

  if ! confirm "Rollback to latest backup: $(basename "$latest")?"; then
    info "Rollback canceled."
    return 0
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    info "DRY-RUN: Would restore from $latest"
    return 0
  fi

  info "Restoring from $latest ..."
  tar -xzpf "$latest" -C /
  ok "Files restored."

  info "Restarting services after rollback..."
  for svc in "${SERVICES[@]}"; do
    systemctl restart "$svc" || warn "Failed to restart $svc"
  done
  ok "Rollback complete."
}

#############################
# Hardening Modules         #
#############################

harden_sysctl() {
  info "Applying basic network hardening via sysctl..."
  local updates="
# Mail hardener additions
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
"
  append_file_safe "/etc/sysctl.conf" "$updates"
  [[ "$DRY_RUN" -eq 1 ]] || sysctl -p || warn "sysctl reload reported warnings"
}

configure_firewall() {
  if [[ -z "${FIREWALL:-}" ]]; then
    warn "Firewall configuration skipped per config."
    return 0
  fi

  if [[ "$FIREWALL" == "ufw" ]]; then
    apt_install ufw
    info "Configuring UFW for mail ports..."
    [[ "$DRY_RUN" -eq 1 ]] || ufw default deny incoming
    [[ "$DRY_RUN" -eq 1 ]] || ufw default allow outgoing
    for p in "${ALLOWED_MAIL_PORTS[@]}"; do
      [[ "$DRY_RUN" -eq 1 ]] || ufw allow "$p"/tcp
      info "Allowed TCP port: $p"
    done
    [[ "$DRY_RUN" -eq 1 ]] || ufw enable <<<"y"
    ok "UFW configured."
  elif [[ "$FIREWALL" == "nftables" ]]; then
    apt_install nftables
    info "Configuring nftables rules for mail ports..."
    local rules="flush ruleset
table inet mail {
  chain input {
    type filter hook input priority 0;
    policy drop;
    ct state established,related accept
    iif lo accept
    tcp dport { ${ALLOWED_MAIL_PORTS[*]} } accept
  }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output  { type filter hook output  priority 0; policy accept; }
}"
    write_file_safe "/etc/nftables.conf" "$rules"
    [[ "$DRY_RUN" -eq 1 ]] || systemctl enable nftables && systemctl restart nftables
    ok "nftables configured."
  else
    warn "Unknown firewall option: $FIREWALL"
  fi
}

harden_postfix() {
  info "Installing and hardening Postfix..."
  apt_install postfix

  generate_dhparams

  local maincf="/etc/postfix/main.cf"
  local mastercf="/etc/postfix/master.cf"

  # Minimal secure baseline; merges on append to avoid clobbering custom configs
  local main_updates="
# Mail hardener additions
smtpd_tls_security_level = may
smtpd_tls_cert_file = /etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file = /etc/ssl/private/ssl-cert-snakeoil.key
smtpd_tls_mandatory_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1
tls_preempt_cipherlist = yes
smtpd_tls_ciphers = high
smtpd_tls_exclude_ciphers = aNULL, MD5, RC4, 3DES
smtpd_tls_dh1024_param_file = $DH_PARAM_FILE
smtp_tls_security_level = may
smtp_tls_mandatory_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1
smtp_tls_ciphers = high
smtp_tls_exclude_ciphers = aNULL, MD5, RC4, 3DES

# Reduce enumeration and abuse
disable_vrfy_command = yes
smtpd_helo_required = yes

# Basic recipient and client restrictions (augment to fit policy)
smtpd_recipient_restrictions = \
  permit_mynetworks, \
  permit_sasl_authenticated, \
  reject_unauth_destination, \
  reject_non_fqdn_recipient, \
  reject_unknown_recipient_domain

smtpd_client_restrictions = \
  permit_mynetworks, \
  reject_unknown_client_hostname

# Logging and privacy
minimal_backoff_time = 300s
maximal_backoff_time = 1800s
"
  append_file_safe "$maincf" "$main_updates"

  # Submission service hardened (port 587), SMTPS optional if needed
  local master_updates="
# Mail hardener additions
submission inet n - y - - smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING

# Uncomment to enable smtps (465) if required
#smtps     inet  n       -       y       -       -       smtpd
#  -o syslog_name=postfix/smtps
#  -o smtpd_tls_security_level=encrypt
#  -o smtpd_sasl_auth_enable=yes
"
  append_file_safe "$mastercf" "$master_updates"

  svc_enable_restart postfix
}

harden_dovecot() {
  info "Installing and hardening Dovecot..."
  apt_install dovecot-core dovecot-imapd dovecot-pop3d

  local conf="/etc/dovecot/dovecot.conf"
  local confd="/etc/dovecot/conf.d/10-ssl.conf"
  local auth="/etc/dovecot/conf.d/10-auth.conf"

  local ssl_updates="
# Mail hardener additions
ssl = required
ssl_min_protocol = TLSv1.2
ssl_cipher_list = HIGH:!aNULL:!MD5:!RC4:!3DES
# Use system certs or provide your own
ssl_cert = </etc/ssl/certs/ssl-cert-snakeoil.pem
ssl_key  = </etc/ssl/private/ssl-cert-snakeoil.key
"
  append_file_safe "$confd" "$ssl_updates"

  local auth_updates="
# Mail hardener additions
disable_plaintext_auth = yes
auth_mechanisms = plain login
"
  append_file_safe "$auth" "$auth_updates"

  # Ensure protocols and logging are sane
  local base_updates="
# Mail hardener additions
protocols = imap pop3
log_timestamp = \"%Y-%m-%d %H:%M:%S \"
"
  append_file_safe "$conf" "$base_updates"

  svc_enable_restart dovecot
}

configure_opendkim() {
  info "Installing and configuring OpenDKIM..."
  apt_install opendkim opendkim-tools

  local dkim_dir="/etc/opendkim"
  local key_dir="$dkim_dir/keys/$MAIL_DOMAIN"
  mkdir -p "$key_dir"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    info "DRY-RUN: Would generate DKIM keys for $MAIL_DOMAIN with selector $DKIM_SELECTOR"
  else
    opendkim-genkey -D "$key_dir" -d "$MAIL_DOMAIN" -s "$DKIM_SELECTOR"
    chown -R opendkim:opendkim "$dkim_dir"
  fi

  local dkim_conf="
# Mail hardener additions
Syslog                  yes
UMask                   002
Canonicalization        relaxed/simple
Mode                    sv
SubDomains              no
AutoRestart             yes
AutoRestartRate         10/1h
Socket                  inet:8891@localhost
KeyTable                $dkim_dir/KeyTable
SigningTable            $dkim_dir/SigningTable
ExternalIgnoreList      $dkim_dir/TrustedHosts
InternalHosts           $dkim_dir/TrustedHosts
"
  write_file_safe "$dkim_dir/opendkim.conf" "$dkim_conf"

  local key_table="$DKIM_SELECTOR._domainkey.$MAIL_DOMAIN $MAIL_DOMAIN:$DKIM_SELECTOR:$key_dir/$DKIM_SELECTOR.private"
  write_file_safe "$dkim_dir/KeyTable" "$key_table"
  write_file_safe "$dkim_dir/SigningTable" "*@$MAIL_DOMAIN $DKIM_SELECTOR._domainkey.$MAIL_DOMAIN"
  write_file_safe "$dkim_dir/TrustedHosts" "127.0.0.1\nlocalhost"

  # Integrate with Postfix via milter
  local postfix_milter="
# OpenDKIM milter integration
milter_default_action = accept
milter_protocol = 6
smtpd_milters = inet:localhost:8891
non_smtpd_milters = inet:localhost:8891
"
  append_file_safe "/etc/postfix/main.cf" "$postfix_milter"

  svc_enable_restart opendkim
  svc_enable_restart postfix

  ok "OpenDKIM configured. Publish DNS TXT from: $key_dir/$DKIM_SELECTOR.txt"
}

configure_opendmarc() {
  info "Installing and configuring OpenDMARC..."
  apt_install opendmarc

  local conf="/etc/opendmarc.conf"
  local updates="
# Mail hardener additions
Syslog                  true
UMask                   002
Socket                  inet:8893@localhost
AuthservID              $MAIL_DOMAIN
TrustedAuthservIDs      $MAIL_DOMAIN
FailureReports          true
FailureReportsOnNone    true
SPFIgnoreResults        false
"
  write_file_safe "$conf" "$updates"

  # Integrate with Postfix via milter chain
  local postfix_milter="
# OpenDMARC milter integration (added to milters chain)
smtpd_milters = inet:localhost:8891, inet:localhost:8893
non_smtpd_milters = inet:localhost:8891, inet:localhost:8893
"
  append_file_safe "/etc/postfix/main.cf" "$postfix_milter"

  svc_enable_restart opendmarc
  svc_enable_restart postfix

  ok "OpenDMARC configured. Ensure DMARC DNS record is published for $MAIL_DOMAIN."
}

configure_spamassassin() {
  info "Installing and enabling SpamAssassin (spamd)..."
  apt_install spamassassin

  local localcf="/etc/spamassassin/local.cf"
  local updates="
# Mail hardener additions
required_score 5.0
rewrite_header Subject *****SPAM*****
report_safe 0
use_bayes 1
bayes_auto_learn 1
"
  append_file_safe "$localcf" "$updates"

  # Systemd enabling
  if [[ "$DRY_RUN" -eq 1 ]]; then
    info "DRY-RUN: Would enable spamassassin service"
  else
    sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/spamassassin || true
  fi

  svc_enable_restart spamassassin
}

configure_clamav() {
  info "Installing and configuring ClamAV..."
  apt_install clamav-daemon clamav-freshclam

  # Ensure freshclam runs and updates
  if [[ "$DRY_RUN" -eq 1 ]]; then
    info "DRY-RUN: Would enable clamav-daemon and freshclam"
  else
    systemctl enable clamav-daemon || true
    systemctl enable clamav-freshclam || true
    systemctl restart clamav-freshclam || true
  fi
  svc_enable_restart clamav-daemon
}

configure_fail2ban() {
  info "Installing and configuring Fail2ban jails for Postfix/Dovecot..."
  apt_install fail2ban

  local jaild="/etc/fail2ban/jail.d/mail-hardener.conf"
  local jail_conf="
# Mail hardener additions
[postfix]
enabled = true
port    = smtp,ssmtp,submission
filter  = postfix
logpath = /var/log/mail.log
maxretry = 5
bantime = 3600

[dovecot]
enabled = true
port    = pop3,pop3s,imap,imaps
filter  = dovecot
logpath = /var/log/dovecot.log
maxretry = 5
bantime = 3600
"
  write_file_safe "$jaild" "$jail_conf"
  svc_enable_restart fail2ban
}

#############################
# Orchestration             #
#############################

trap 'error "An error occurred. Check $LOG_FILE. Consider running rollback.";' ERR

preflight() {
  require_root
  detect_ubuntu
  ensure_dirs
  load_or_create_config
}

run_modules() {
  # Sequence: backup -> sysctl -> firewall -> services
  create_backup

  if confirm "Apply sysctl network hardening?"; then
    harken="harden_sysctl"; $harken
  else
    info "Sysctl hardening skipped."
  fi

  if confirm "Configure firewall ($FIREWALL)?"; then
    configure_firewall
  else
    info "Firewall configuration skipped."
  fi

  if confirm "Harden Postfix?"; then
    harken="harden_postfix"; $harken
  else
    info "Postfix hardening skipped."
  fi

  if confirm "Harden Dovecot?"; then
    harken="harden_dovecot"; $harken
  else
    info "Dovecot hardening skipped."
  fi

  if confirm "Configure OpenDKIM? (requires MAIL_DOMAIN)"; then
    configure_opendkim
  else
    info "OpenDKIM configuration skipped."
  fi

  if confirm "Configure OpenDMARC? (requires MAIL_DOMAIN)"; then
    configure_opendmarc
  else
    info "OpenDMARC configuration skipped."
  fi

  if confirm "Enable SpamAssassin (spamd)?"; then
    configure_spamassassin
  else
    info "SpamAssassin configuration skipped."
  fi

  if confirm "Enable ClamAV (daemon + freshclam)?"; then
    configure_clamav
  else
    info "ClamAV configuration skipped."
  fi

  if confirm "Configure Fail2ban jails for mail services?"; then
    configure_fail2ban
  else
    info "Fail2ban configuration skipped."
  fi

  ok "Module run complete."
}

usage() {
  cat <<EOF
Mail Server Hardener (Ubuntu)
Usage:
  $0 [--run] [--rollback] [--dry-run] [--non-interactive]

Options:
  --run             Execute hardening modules (default if no option provided)
  --rollback        Restore latest backup and restart services
  --dry-run         Preview changes without modifying system
  --non-interactive Run without prompts (assumes yes)

Edit config at: $CONFIG_FILE
Logs: $LOG_FILE
Backups: $BACKUP_DIR
EOF
}

main() {
  local action="run"
  while [[ "${1:-}" ]]; do
    case "$1" in
      --rollback) action="rollback" ;;
      --dry-run) DRY_RUN=1 ;;
      --non-interactive) INTERACTIVE=0 ;;
      --run) action="run" ;;
      -h|--help) usage; exit 0 ;;
      *) warn "Unknown argument: $1" ;;
    esac
    shift
  done

  preflight

  case "$action" in
    run) run_modules ;;
    rollback) rollback_latest ;;
  esac

  ok "Done."
}

main "$@"
