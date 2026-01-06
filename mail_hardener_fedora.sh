#!/usr/bin/env bash
# ============================================
#   Mail Hardener (Postfix + Dovecot + Roundcube)
#   Target: Fedora (dnf + systemd + httpd)
#   Features: Backup, Rollback, TLS/Webmail Hardening, Test Setup
#   Visual: Color-coded output + error handling
#   Made using Copilot AI
#
#   Usage:
#     - Harden existing services:
#         sudo bash mail_hardener_fedora.sh
#
#     - Rollback to latest backup:
#         sudo bash mail_hardener_fedora.sh --rollback
#
#     - Test setup (install & basic-config Postfix, Dovecot, Roundcube):
#         sudo bash mail_hardener_fedora.sh --test-setup
#
#   Notes:
#     - This script must be run as root (sudo).
#     - Test setup ONLY installs and minimally configures services.
#       To apply hardening, run the script AGAIN without --test-setup.
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

# Fedora default self-signed cert paths (adjust if you use real certs)
SSL_CERT="/etc/pki/tls/certs/localhost.crt"
SSL_KEY="/etc/pki/tls/private/localhost.key"

# Config paths
POSTFIX_DIR="/etc/postfix"
DOVECOT_DIR="/etc/dovecot"
ROUNDCUBE_ETC_DIR="/etc/roundcubemail"
ROUNDCUBE_SHARE_DIR="/usr/share/roundcubemail"
ROUNDCUBE_CONFIG_FILE="$ROUNDCUBE_ETC_DIR/config.inc.php"

# Services (include httpd for Roundcube)
SERVICES=(postfix dovecot httpd)

# --- Utility Functions ---
info()  { echo -e "${BLUE}[INFO]${RESET} $*"; }
ok()    { echo -e "${GREEN}[OK]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET} $*"; }
error() { echo -e "${RED}[ERROR]${RESET} $*"; }

# --- Root Privilege Check ---
require_root() {
  if [[ "$EUID" -ne 0 ]]; then
    error "This script must be run as root (sudo)."
    exit 1
  fi
}

# --- Error Handling ---
trap 'error "An unexpected error occurred on line $LINENO. Check logs or use --rollback if needed."' ERR

# --- Backup & Rollback ---

backup_configs() {
  mkdir -p "$BACKUP_DIR"

  info "Creating backup at $BACKUP_FILE..."
  # Only include paths that exist to avoid tar errors
  mapfile -t paths < <(printf "%s\n" \
    "$POSTFIX_DIR" \
    "$DOVECOT_DIR" \
    "$ROUNDCUBE_ETC_DIR" \
    "$ROUNDCUBE_SHARE_DIR" | xargs -I{} bash -c '[[ -e "{}" ]] && echo "{}"' || true)

  if [[ "${#paths[@]}" -eq 0 ]]; then
    warn "No known mail-related paths found to back up. Skipping backup."
    return 0
  fi

  if tar -czpf "$BACKUP_FILE" "${paths[@]}"; then
    ok "Backup complete."
  else
    error "Backup failed."
    exit 1
  fi
}

rollback_latest() {
  mkdir -p "$BACKUP_DIR"
  local latest
  latest="$(ls -1t "$BACKUP_DIR"/mail_backup_*.tar.gz 2>/dev/null | head -n1 || true)"

  if [[ -z "$latest" ]]; then
    error "No backups found in $BACKUP_DIR."
    exit 1
  fi

  info "Restoring from $latest..."
  if tar -xzpf "$latest" -C /; then
    for svc in "${SERVICES[@]}"; do
      if systemctl restart "$svc"; then
        ok "Restarted $svc"
      else
        warn "Failed to restart $svc (it may not be installed or enabled)"
      fi
    done
    ok "Rollback complete."
  else
    error "Rollback failed."
    exit 1
  fi
}

# --- Test Setup (Install & Basic Config Only) ---

test_setup_install() {
  info "Starting test setup: installing Postfix, Dovecot, Roundcube, and httpd (Fedora)..."

  # Install core packages
  if dnf install -y postfix dovecot roundcubemail httpd mod_ssl; then
    ok "Packages installed: postfix, dovecot, roundcubemail, httpd, mod_ssl."
  else
    error "Package installation failed."
    exit 1
  fi

  # Enable and start services
  for svc in "${SERVICES[@]}"; do
    info "Enabling and starting $svc..."
    if systemctl enable --now "$svc"; then
      ok "$svc is enabled and running."
    else
      warn "Failed to enable/start $svc. Check systemctl status $svc."
    fi
  done

  # Minimal Roundcube setup using SQLite for testing
  info "Configuring Roundcube for test environment..."

  mkdir -p "$ROUNDCUBE_ETC_DIR"
  # Prefer Fedora sample config if present
  if [[ ! -f "$ROUNDCUBE_CONFIG_FILE" ]]; then
    if [[ -f "$ROUNDCUBE_ETC_DIR/config.inc.php.sample" ]]; then
      cp "$ROUNDCUBE_ETC_DIR/config.inc.php.sample" "$ROUNDCUBE_CONFIG_FILE"
      ok "Roundcube config created from sample."
    else
      info "No sample config found, creating minimal Roundcube config for test use."
      cat > "$ROUNDCUBE_CONFIG_FILE" <<'EOF'
<?php
$config = [];

/* Basic DB (SQLite for testing) */
$config['db_dsnw'] = 'sqlite:////var/lib/roundcubemail/sqlite.db?mode=0640';

/* IMAP & SMTP pointing to localhost (non-TLS for initial test) */
$config['default_host'] = 'localhost';
$config['default_port'] = 143;
$config['smtp_server'] = 'localhost';
$config['smtp_port'] = 25;

/* Misc */
$config['support_url'] = '';
$config['des_key'] = 'change_me_for_production_1234';
EOF
      ok "Minimal Roundcube config created at $ROUNDCUBE_CONFIG_FILE (for testing only)."
    fi
  else
    warn "Existing Roundcube config found. Leaving it as-is for test setup."
  fi

  # Ensure Roundcube data directory for SQLite exists
  mkdir -p /var/lib/roundcubemail
  chown apache:apache /var/lib/roundcubemail || true

  ok "Test setup complete. You should now be able to access Roundcube via http(s) on this host."
  warn "REMINDER: Test setup does NOT apply hardening. Run this script again WITHOUT --test-setup to harden."
}

# --- Postfix Hardening ---

harden_postfix() {
  info "Hardening Postfix (TLS, submission)..."

  if [[ ! -d "$POSTFIX_DIR" ]]; then
    error "Postfix config directory $POSTFIX_DIR not found. Is Postfix installed?"
    exit 1
  fi

  if [[ ! -f "$SSL_CERT" || ! -f "$SSL_KEY" ]]; then
    warn "TLS cert/key not found at $SSL_CERT / $SSL_KEY. Adjust paths in script for your certificates."
  fi

  {
    cat <<EOF >> "$POSTFIX_DIR/main.cf"

# === Mail Hardener additions (Fedora) ===
smtpd_tls_security_level = may
smtpd_tls_cert_file = $SSL_CERT
smtpd_tls_key_file = $SSL_KEY
smtpd_tls_mandatory_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1
smtpd_tls_ciphers = high
smtpd_tls_exclude_ciphers = aNULL, MD5, RC4, 3DES
disable_vrfy_command = yes
smtpd_helo_required = yes
EOF

    cat <<'EOF' >> "$POSTFIX_DIR/master.cf"

# === Hardened submission service (587) ===
submission inet n       -       y       -       -       smtpd
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
EOF
  } || { error "Failed to update Postfix configs."; exit 1; }

  if systemctl restart postfix; then
    ok "Postfix hardened and restarted."
  else
    error "Failed to restart Postfix."
    exit 1
  fi
}

# --- Dovecot Hardening ---

harden_dovecot() {
  info "Hardening Dovecot (TLS, auth)..."

  if [[ ! -d "$DOVECOT_DIR" ]]; then
    error "Dovecot config directory $DOVECOT_DIR not found. Is Dovecot installed?"
    exit 1
  fi

  local ssl_conf="$DOVECOT_DIR/conf.d/10-ssl.conf"
  local auth_conf="$DOVECOT_DIR/conf.d/10-auth.conf"

  if [[ ! -f "$ssl_conf" ]]; then
    warn "$ssl_conf not found. Creating it."
    touch "$ssl_conf"
  fi
  if [[ ! -f "$auth_conf" ]]; then
    warn "$auth_conf not found. Creating it."
    touch "$auth_conf"
  fi

  {
    cat <<EOF >> "$ssl_conf"

# === Mail Hardener additions (Fedora) ===
ssl = required
ssl_min_protocol = TLSv1.2
ssl_cipher_list = HIGH:!aNULL:!MD5:!RC4:!3DES
ssl_cert = <$SSL_CERT
ssl_key  = <$SSL_KEY
EOF

    cat <<'EOF' >> "$auth_conf"

# === Mail Hardener additions (Fedora) ===
disable_plaintext_auth = yes
auth_mechanisms = plain login
EOF
  } || { error "Failed to update Dovecot configs."; exit 1; }

  if systemctl restart dovecot; then
    ok "Dovecot hardened and restarted."
  else
    error "Failed to restart Dovecot."
    exit 1
  fi
}

# --- Roundcube Hardening ---

prepare_roundcube_config() {
  # Ensure config file exists before hardening
  if [[ ! -f "$ROUNDCUBE_CONFIG_FILE" ]]; then
    if [[ -f "$ROUNDCUBE_ETC_DIR/config.inc.php.sample" ]]; then
      info "Roundcube config not found. Creating from sample."
      cp "$ROUNDCUBE_ETC_DIR/config.inc.php.sample" "$ROUNDCUBE_CONFIG_FILE"
    else
      warn "No Roundcube config or sample found. Creating minimal config."
      mkdir -p "$ROUNDCUBE_ETC_DIR"
      cat > "$ROUNDCUBE_CONFIG_FILE" <<'EOF'
<?php
$config = [];

/* Basic DB (SQLite by default; adjust for production) */
$config['db_dsnw'] = 'sqlite:////var/lib/roundcubemail/sqlite.db?mode=0640';

/* IMAP & SMTP pointing to localhost (TLS settings will be hardened below) */
$config['default_host'] = 'localhost';
$config['default_port'] = 143;
$config['smtp_server'] = 'localhost';
$config['smtp_port'] = 25;

/* Misc */
$config['support_url'] = '';
$config['des_key'] = 'change_me_for_production_5678';
EOF
    fi
  fi
}

harden_roundcube() {
  info "Hardening Roundcube (webmail)..."

  if [[ ! -d "$ROUNDCUBE_ETC_DIR" ]]; then
    warn "Roundcube config directory $ROUNDCUBE_ETC_DIR not found. Is roundcubemail installed?"
    return 0
  fi

  prepare_roundcube_config

  if [[ ! -f "$ROUNDCUBE_CONFIG_FILE" ]]; then
    error "Failed to create or locate $ROUNDCUBE_CONFIG_FILE. Cannot harden Roundcube."
    exit 1
  fi

  # Append hardened settings
  cat <<'EOF' >> "$ROUNDCUBE_CONFIG_FILE"

// === Mail Hardener additions (Fedora) ===
$config['force_https'] = true;
$config['use_https'] = true;
$config['session_secure'] = true;
$config['login_autocomplete'] = 0;
$config['password_charset'] = 'UTF-8';
$config['enable_installer'] = false;

/* Assume hardened Dovecot/Postfix: IMAP over SSL, SMTP over TLS */
$config['default_host'] = 'ssl://localhost';
$config['default_port'] = 993;
$config['smtp_server'] = 'tls://localhost';
$config['smtp_port'] = 587;
EOF

  ok "Roundcube config hardened."

  # Restart web server to apply any changes
  if systemctl restart httpd; then
    ok "httpd restarted for Roundcube changes."
  else
    warn "Failed to restart httpd. Check systemctl status httpd."
  fi
}

# --- Main ---

require_root

case "${1:-}" in
  --rollback)
    info "Rollback requested."
    rollback_latest
    ;;
  --test-setup)
    info "Test setup requested (install & basic-config only)."
    test_setup_install
    ;;
  *)
    info "Starting Mail Hardener for Postfix, Dovecot, and Roundcube (Fedora)..."
    backup_configs
    harden_postfix
    harden_dovecot
    harden_roundcube
    ok "Hardening complete. Backup stored at $BACKUP_FILE"
    ;;
esac
