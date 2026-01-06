#!/usr/bin/env bash
# ============================================================
#   Mail Hardener (Postfix + Dovecot + Roundcube)
#   Target: Fedora (dnf + systemd + httpd)
#   Features:
#     - Backup & Rollback
#     - Hardening for Postfix, Dovecot, Roundcube
#     - Test Setup (installs all 3 services)
#     - Roundcube Source Installer (latest version from GitHub)
#     - Roundcube Enable/Disable Options
#     - Strong Error Handling + Color Output
#
#   Usage:
#     sudo bash mail_hardener_fedora.sh
#     sudo bash mail_hardener_fedora.sh --rollback
#     sudo bash mail_hardener_fedora.sh --test-setup
#     sudo bash mail_hardener_fedora.sh --disable-roundcube
#     sudo bash mail_hardener_fedora.sh --enable-roundcube
#
#   Notes:
#     - Must be run as root.
#     - Test setup installs services but does NOT harden them.
# ============================================================

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

POSTFIX_DIR="/etc/postfix"
DOVECOT_DIR="/etc/dovecot"
ROUNDCUBE_DIR="/usr/share/roundcubemail"
ROUNDCUBE_CONFIG_DIR="$ROUNDCUBE_DIR/config"
ROUNDCUBE_CONFIG="$ROUNDCUBE_CONFIG_DIR/config.inc.php"
ROUNDCUBE_DB_DIR="/var/lib/roundcubemail"
ROUNDCUBE_ALIAS="/etc/httpd/conf.d/roundcube.conf"

SSL_CERT="/etc/pki/tls/certs/localhost.crt"
SSL_KEY="/etc/pki/tls/private/localhost.key"

SERVICES=(postfix dovecot httpd)

# --- Utility Output ---
info()  { echo -e "${BLUE}[INFO]${RESET} $*"; }
ok()    { echo -e "${GREEN}[OK]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET} $*"; }
error() { echo -e "${RED}[ERROR]${RESET} $*"; }

# --- Root Check ---
require_root() {
  if [[ "$EUID" -ne 0 ]]; then
    error "This script must be run as root."
    exit 1
  fi
}

# --- Error Trap ---
trap 'error "Unexpected error on line $LINENO. Use --rollback if needed."' ERR

# ============================================================
# BACKUP & ROLLBACK
# ============================================================

backup_configs() {
  mkdir -p "$BACKUP_DIR"

  info "Creating backup at $BACKUP_FILE..."

  mapfile -t paths < <(printf "%s\n" \
    "$POSTFIX_DIR" \
    "$DOVECOT_DIR" \
    "$ROUNDCUBE_DIR" \
    "$ROUNDCUBE_ALIAS" | xargs -I{} bash -c '[[ -e "{}" ]] && echo "{}"' || true)

  if [[ "${#paths[@]}" -eq 0 ]]; then
    warn "No config paths found to back up."
    return 0
  fi

  tar -czpf "$BACKUP_FILE" "${paths[@]}"
  ok "Backup complete."
}

rollback_latest() {
  mkdir -p "$BACKUP_DIR"
  local latest
  latest="$(ls -1t "$BACKUP_DIR"/mail_backup_*.tar.gz 2>/dev/null | head -n1 || true)"

  if [[ -z "$latest" ]]; then
    error "No backups found."
    exit 1
  fi

  info "Restoring from $latest..."
  tar -xzpf "$latest" -C /

  for svc in "${SERVICES[@]}"; do
    systemctl restart "$svc" || warn "Failed to restart $svc"
  done

  ok "Rollback complete."
}

# ============================================================
# ROUNDcube SOURCE INSTALLER (LATEST VERSION)
# ============================================================

install_roundcube_source() {
  info "Installing Roundcube from source (latest version)..."

  # Ensure dependencies
  dnf install -y php php-json php-mbstring php-intl php-xml php-pdo php-pdo_sqlite php-zip php-gd unzip curl

  # Fetch latest version tag
  local latest
  latest=$(curl -s https://api.github.com/repos/roundcube/roundcubemail/releases/latest | grep tag_name | cut -d '"' -f4)

  if [[ -z "$latest" ]]; then
    error "Failed to fetch latest Roundcube version."
    exit 1
  fi

  info "Latest Roundcube version: $latest"

  # Download tarball
  cd /usr/share
  curl -LO "https://github.com/roundcube/roundcubemail/releases/download/$latest/roundcubemail-$latest-complete.tar.gz"

  # Extract
  rm -rf "$ROUNDCUBE_DIR"
  tar -xzf "roundcubemail-$latest-complete.tar.gz"
  mv "roundcubemail-$latest" "$ROUNDCUBE_DIR"

  # Create config
  mkdir -p "$ROUNDCUBE_CONFIG_DIR"
  cp "$ROUNDCUBE_CONFIG_DIR/config.inc.php.sample" "$ROUNDCUBE_CONFIG"

  # SQLite DB
  mkdir -p "$ROUNDCUBE_DB_DIR"
  chown apache:apache "$ROUNDCUBE_DB_DIR"

  sed -i "s#'sqlite:.*'#'sqlite:////var/lib/roundcubemail/sqlite.db?mode=0640'#g" "$ROUNDCUBE_CONFIG"

  # Permissions
  chown -R apache:apache "$ROUNDCUBE_DIR"
  restorecon -RF "$ROUNDCUBE_DIR"

  # Apache alias
  cat > "$ROUNDCUBE_ALIAS" <<EOF
Alias /roundcubemail $ROUNDCUBE_DIR

<Directory $ROUNDCUBE_DIR>
    Options +FollowSymLinks
    AllowOverride All
    Require all granted
</Directory>
EOF

  systemctl restart httpd

  # Validate
  if sudo -u apache php "$ROUNDCUBE_DIR/index.php" >/dev/null 2>&1; then
    ok "Roundcube installed successfully."
  else
    error "Roundcube failed validation."
    exit 1
  fi
}

# ============================================================
# ROUNDcube ENABLE/DISABLE
# ============================================================

disable_roundcube() {
  info "Disabling Roundcube..."
  mv "$ROUNDCUBE_DIR" "${ROUNDCUBE_DIR}.disabled" 2>/dev/null || true
  rm -f "$ROUNDCUBE_ALIAS"
  systemctl restart httpd
  ok "Roundcube disabled."
}

enable_roundcube() {
  info "Enabling Roundcube..."
  if [[ -d "${ROUNDCUBE_DIR}.disabled" ]]; then
    mv "${ROUNDCUBE_DIR}.disabled" "$ROUNDCUBE_DIR"
  fi
  install_roundcube_source
  ok "Roundcube enabled."
}

# ============================================================
# TEST SETUP (INSTALL SERVICES)
# ============================================================

test_setup() {
  info "Starting test setup..."

  dnf install -y postfix dovecot httpd mod_ssl
  systemctl enable --now postfix dovecot httpd

  install_roundcube_source

  ok "Test setup complete. Run script again (without flags) to harden services."
}

# ============================================================
# HARDENING
# ============================================================

harden_postfix() {
  info "Hardening Postfix..."
  cat <<EOF >> "$POSTFIX_DIR/main.cf"

# === Mail Hardener additions ===
smtpd_tls_security_level = may
smtpd_tls_cert_file = $SSL_CERT
smtpd_tls_key_file = $SSL_KEY
smtpd_tls_mandatory_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1
smtpd_tls_ciphers = high
smtpd_tls_exclude_ciphers = aNULL, MD5, RC4, 3DES
disable_vrfy_command = yes
smtpd_helo_required = yes
EOF

  systemctl restart postfix
  ok "Postfix hardened."
}

harden_dovecot() {
  info "Hardening Dovecot..."

  cat <<EOF >> "$DOVECOT_DIR/conf.d/10-ssl.conf"

# === Mail Hardener additions ===
ssl = required
ssl_min_protocol = TLSv1.2
ssl_cipher_list = HIGH:!aNULL:!MD5:!RC4:!3DES
ssl_cert = <$SSL_CERT
ssl_key  = <$SSL_KEY
EOF

  cat <<EOF >> "$DOVECOT_DIR/conf.d/10-auth.conf"

# === Mail Hardener additions ===
disable_plaintext_auth = yes
auth_mechanisms = plain login
EOF

  systemctl restart dovecot
  ok "Dovecot hardened."
}

harden_roundcube() {
  info "Hardening Roundcube..."

  cat <<EOF >> "$ROUNDCUBE_CONFIG"

\$config['force_https'] = true;
\$config['use_https'] = true;
\$config['session_secure'] = true;
\$config['login_autocomplete'] = 0;
\$config['enable_installer'] = false;

\$config['default_host'] = 'ssl://localhost';
\$config['default_port'] = 993;
\$config['smtp_server'] = 'tls://localhost';
\$config['smtp_port'] = 587;
EOF

  systemctl restart httpd
  ok "Roundcube hardened."
}

# ============================================================
# MAIN
# ============================================================

require_root

case "${1:-}" in
  --rollback)
    rollback_latest
    ;;
  --test-setup)
    test_setup
    ;;
  --disable-roundcube)
    disable_roundcube
    ;;
  --enable-roundcube)
    enable_roundcube
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
