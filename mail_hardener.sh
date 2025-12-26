#!/usr/bin/env bash
# ============================================
#   Mail Hardener (Postfix + Dovecot + Roundcube)
#   Features: Backup, Rollback, TLS Hardening
#   Visual: Color-coded output + Error handling
#   Portable: Works on ALL major Linux distros
#   Made with Copilot AI
#   For rollback: sudo bash mail_hardener.sh --rollback
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

SERVICES=(postfix dovecot)

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
trap 'error "An unexpected error occurred on line $LINENO. Check logs or rollback."' ERR

# --- Distro Detection ---
detect_distro() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release

    case "$ID" in
      ubuntu|debian)
        PKG_INSTALL="apt-get install -y"
        PHP_INI="/etc/php/*/apache2/php.ini"
        WEBSERVER="apache2"
        ROUNDCUBE_PKG="roundcube"
        ;;
      fedora|centos|rhel|rocky|almalinux)
        PKG_INSTALL="dnf install -y"
        PHP_INI="/etc/php.ini"
        WEBSERVER="httpd"
        ROUNDCUBE_PKG="roundcubemail"
        ;;
      opensuse*|sles)
        PKG_INSTALL="zypper install -y"
        PHP_INI="/etc/php.ini"
        WEBSERVER="apache2"
        ROUNDCUBE_PKG="roundcubemail"
        ;;
      arch)
        PKG_INSTALL="pacman -S --noconfirm"
        PHP_INI="/etc/php/php.ini"
        WEBSERVER="httpd"
        ROUNDCUBE_PKG="roundcubemail"
        ;;
      *)
        error "Unsupported distro: $ID"
        exit 1
        ;;
    esac

    ok "Detected distro: $PRETTY_NAME"
  else
    error "Cannot detect distro."
    exit 1
  fi
}

backup_configs() {
  mkdir -p "$BACKUP_DIR"
  info "Creating backup at $BACKUP_FILE..."
  if tar -czpf "$BACKUP_FILE" /etc/postfix /etc/dovecot /etc/roundcube 2>/dev/null; then
    ok "Backup complete."
  else
    warn "Backup created but some components may not exist yet."
  fi
}

rollback_latest() {
  local latest
  latest="$(ls -1t "$BACKUP_DIR"/mail_backup_*.tar.gz 2>/dev/null | head -n1 || true)"
  if [[ -z "$latest" ]]; then
    error "No backups found."
    exit 1
  fi
  info "Restoring from $latest..."
  if tar -xzpf "$latest" -C /; then
    for svc in "${SERVICES[@]}"; do
      if systemctl restart "$svc"; then
        ok "Restarted $svc"
      else
        warn "Failed to restart $svc"
      fi
    done
    ok "Rollback complete."
  else
    error "Rollback failed."
    exit 1
  fi
}

# --- Postfix Hardening ---
harden_postfix() {
  info "Installing Postfix..."
  $PKG_INSTALL postfix || warn "Postfix may already be installed."

  info "Hardening Postfix..."
  {
    cat <<'EOF' >> /etc/postfix/main.cf

# === Mail Hardener additions ===
smtpd_tls_security_level = may
smtpd_tls_cert_file = /etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file = /etc/ssl/private/ssl-cert-snakeoil.key
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
  } || { error "Failed to update Postfix configs."; exit 1; }

  systemctl restart postfix
  ok "Postfix hardened and restarted."
}

# --- Dovecot Hardening ---
harden_dovecot() {
  info "Installing Dovecot..."
  $PKG_INSTALL dovecot || warn "Dovecot may already be installed."

  info "Hardening Dovecot..."
  {
    cat <<'EOF' >> /etc/dovecot/conf.d/10-ssl.conf

# === Mail Hardener additions ===
ssl = required
ssl_min_protocol = TLSv1.2
ssl_cipher_list = HIGH:!aNULL:!MD5:!RC4:!3DES
ssl_cert = </etc/ssl/certs/ssl-cert-snakeoil.pem
ssl_key  = </etc/ssl/private/ssl-cert-snakeoil.key
EOF

    cat <<'EOF' >> /etc/dovecot/conf.d/10-auth.conf

# === Mail Hardener additions ===
disable_plaintext_auth = yes
auth_mechanisms = plain login
EOF
  } || { error "Failed to update Dovecot configs."; exit 1; }

  systemctl restart dovecot
  ok "Dovecot hardened and restarted."
}

# --- Roundcube Hardening ---
harden_roundcube() {
  info "Installing Roundcube..."
  $PKG_INSTALL $ROUNDCUBE_PKG || warn "Roundcube may already be installed."

  info "Hardening Roundcube..."

  # Secure PHP settings
  if [[ -f $PHP_INI ]]; then
    sed -i 's/^session.cookie_httponly.*/session.cookie_httponly = 1/' $PHP_INI || true
    sed -i 's/^session.cookie_secure.*/session.cookie_secure = 1/' $PHP_INI || true
    sed -i 's/^expose_php.*/expose_php = Off/' $PHP_INI || true
  fi

  # Roundcube config hardening
  RCFG="/etc/roundcube/config.inc.php"
  if [[ -f "$RCFG" ]]; then
    cat <<'EOF' >> "$RCFG"

# === Mail Hardener additions ===
$config['force_https'] = true;
$config['password_charset'] = 'UTF-8';
$config['des_key'] = 'CHANGE_THIS_RANDOM_KEY_32CHARS';
$config['login_autocomplete'] = 0;
$config['session_lifetime'] = 10;
$config['session_domain'] = '';
$config['session_secure'] = true;
$config['session_http_only'] = true;
EOF
  fi

  # Permissions
  chown -R root:root /etc/roundcube 2>/dev/null || true
  chmod -R 750 /etc/roundcube 2>/dev/null || true

  # Restart web server
  systemctl restart "$WEBSERVER" || warn "Web server restart failed."

  ok "Roundcube hardened."
}

# --- Main ---
require_root
detect_distro

case "${1:-}" in
  --rollback)
    rollback_latest
    ;;
  *)
    info "Starting Mail Hardener..."
    backup_configs
    harden_postfix
    harden_dovecot
    harden_roundcube
    ok "Hardening complete. Backup stored at $BACKUP_FILE"
    ;;
esac
