#!/usr/bin/env bash
# ============================================
#   Mail Hardener (Postfix + Dovecot + Roundcube)
#   Fedora version
#
#   Usage:
#     sudo bash mail_hardener_fedora.sh
#       → Hardens Postfix, Dovecot, and Roundcube
#
#     sudo bash mail_hardener_fedora.sh --rollback
#       → Restores the most recent backup
#
#     sudo bash mail_hardener_fedora.sh --disable-roundcube
#       → Disables Roundcube Apache alias
#
#     sudo bash mail_hardener_fedora.sh --enable-roundcube
#       → Re-enables Roundcube Apache alias
#
#   Features:
#     - Backup & rollback of /etc/postfix, /etc/dovecot, /etc/httpd/conf.d
#     - TLS hardening for Postfix & Dovecot (Fedora paths/syntax)
#     - Roundcube config hardening
#     - Roundcube enable/disable via Apache alias
# ============================================

set -euo pipefail

# --- Colors ---
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
BLUE=$(tput setaf 4)
RESET=$(tput sgr0)

# --- Paths ---
BACKUP_DIR="/var/backups/mail_hardener"
TIMESTAMP="$(date '+%Y%m%d-%H%M%S')"
BACKUP_FILE="$BACKUP_DIR/mail_backup_$TIMESTAMP.tar.gz"

SERVICES=(postfix dovecot httpd)

# Fedora TLS paths
POSTFIX_CERT="/etc/pki/tls/certs/localhost.crt"
POSTFIX_KEY="/etc/pki/tls/private/localhost.key"

DOVECOT_CERT="/etc/pki/dovecot/certs/dovecot.pem"
DOVECOT_KEY="/etc/pki/dovecot/private/dovecot.pem"

ROUNDCUBE_DIR="/usr/share/roundcubemail"
ROUNDCUBE_CONF="/etc/httpd/conf.d/roundcube.conf"
ROUNDCUBE_DISABLED="/etc/httpd/conf.d/roundcube.conf.disabled"

# --- Utility Functions ---
info()  { echo -e "${BLUE}[INFO]${RESET} $*"; }
ok()    { echo -e "${GREEN}[OK]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET} $*"; }
error() { echo -e "${RED}[ERROR]${RESET} $*"; }

require_root() {
  if [[ "$EUID" -ne 0 ]]; then
    error "This script must be run as root."
    exit 1
  fi
}

trap 'error "Unexpected error on line $LINENO. Check logs or rollback."' ERR

# --- Backup / Rollback ---
backup_configs() {
  mkdir -p "$BACKUP_DIR"
  info "Creating backup at $BACKUP_FILE..."
  tar -czpf "$BACKUP_FILE" /etc/postfix /etc/dovecot /etc/httpd/conf.d || {
    error "Backup failed."
    exit 1
  }
  ok "Backup complete."
}

rollback_latest() {
  local latest
  latest="$(ls -1t "$BACKUP_DIR"/mail_backup_*.tar.gz 2>/dev/null | head -n1 || true)"
  if [[ -z "$latest" ]]; then
    error "No backups found."
    exit 1
  fi

  info "Restoring from $latest..."
  tar -xzpf "$latest" -C / || {
    error "Rollback failed."
    exit 1
  }

  for svc in "${SERVICES[@]}"; do
    if systemctl restart "$svc"; then
      ok "Restarted $svc"
    else
      warn "Failed to restart $svc"
    fi
  done

  ok "Rollback complete."
}

# --- Postfix Hardening ---
harden_postfix() {
  info "Hardening Postfix..."

  if [[ ! -f "$POSTFIX_CERT" || ! -f "$POSTFIX_KEY" ]]; then
    warn "Postfix TLS cert/key not found at $POSTFIX_CERT / $POSTFIX_KEY"
    warn "Postfix will still be hardened, but TLS may not work until certs exist."
  fi

  cat <<EOF >> /etc/postfix/main.cf

# === Mail Hardener additions (Fedora) ===
smtpd_tls_security_level = may
smtpd_tls_cert_file = $POSTFIX_CERT
smtpd_tls_key_file = $POSTFIX_KEY
smtpd_tls_mandatory_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1
smtpd_tls_ciphers = high
smtpd_tls_exclude_ciphers = aNULL, MD5, RC4, 3DES
disable_vrfy_command = yes
smtpd_helo_required = yes
EOF

  cat <<'EOF' >> /etc/postfix/master.cf

# === Hardened submission service ===
submission inet n - y - - smtpd
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
EOF

  systemctl restart postfix
  ok "Postfix hardened."
}

# --- Dovecot Hardening ---
harden_dovecot() {
  info "Hardening Dovecot..."

  if [[ ! -f "$DOVECOT_CERT" || ! -f "$DOVECOT_KEY" ]]; then
    warn "Dovecot TLS cert/key not found at $DOVECOT_CERT / $DOVECOT_KEY"
    warn "Using Fedora defaults; ensure certs exist or adjust paths."
  fi

  # SSL block (Fedora syntax)
  cat <<EOF >> /etc/dovecot/conf.d/10-ssl.conf

# === Mail Hardener additions (Fedora) ===
ssl = required
ssl_min_protocol = TLSv1.2
ssl_cipher_list = HIGH:!aNULL:!MD5:!RC4:!3DES
ssl_cert = <$DOVECOT_CERT
ssl_key  = <$DOVECOT_KEY
EOF

  # Insert disable_plaintext_auth at top of 10-auth.conf
  sed -i '1i # === Mail Hardener additions (Fedora)\ndisable_plaintext_auth = yes\n' \
    /etc/dovecot/conf.d/10-auth.conf

  # Append auth mechanisms
  cat <<'EOF' >> /etc/dovecot/conf.d/10-auth.conf

# === Mail Hardener additions ===
auth_mechanisms = plain login
EOF

  # Validate config before restart
  if ! dovecot -n >/dev/null 2>&1; then
    error "Dovecot config validation failed after hardening. Not restarting."
    dovecot -n
    exit 1
  fi

  systemctl restart dovecot
  ok "Dovecot hardened."
}

# --- Roundcube Hardening ---
harden_roundcube() {
  info "Hardening Roundcube..."

  local config="$ROUNDCUBE_DIR/config/config.inc.php"

  if [[ ! -f "$config" ]]; then
    warn "Roundcube config not found at $config. Is Roundcube installed?"
    return
  fi

  cat <<'EOF' >> "$config"

// === Mail Hardener additions ===
$config['force_https'] = true;
$config['login_autocomplete'] = 0;
$config['password_charset'] = 'UTF-8';
$config['session_lifetime'] = 10;
$config['des_key'] = 'CHANGE_THIS_TO_A_RANDOM_KEY';
$config['enable_installer'] = false;
EOF

  ok "Roundcube hardened."
}

# --- Roundcube Enable/Disable ---
disable_roundcube() {
  info "Disabling Roundcube..."
  if [[ -f "$ROUNDCUBE_CONF" ]]; then
    mv "$ROUNDCUBE_CONF" "$ROUNDCUBE_DISABLED"
    systemctl restart httpd
    ok "Roundcube disabled."
  else
    warn "Roundcube Apache config not found at $ROUNDCUBE_CONF"
  fi
}

enable_roundcube() {
  info "Enabling Roundcube..."
  if [[ -f "$ROUNDCUBE_DISABLED" ]]; then
    mv "$ROUNDCUBE_DISABLED" "$ROUNDCUBE_CONF"
    systemctl restart httpd
    ok "Roundcube enabled."
  else
    warn "No disabled Roundcube config found at $ROUNDCUBE_DISABLED"
  fi
}

# --- Main ---
require_root

case "${1:-}" in
  --rollback)
    rollback_latest
    ;;
  --disable-roundcube)
    disable_roundcube
    ;;
  --enable-roundcube)
    enable_roundcube
    ;;
  *)
    info "Starting Mail Hardener (Fedora)..."
    backup_configs
    harden_postfix
    harden_dovecot
    harden_roundcube
    ok "Hardening complete. Backup stored at $BACKUP_FILE"
    ;;
esac

