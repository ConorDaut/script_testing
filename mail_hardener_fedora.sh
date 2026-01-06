#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#   Mail Hardener for Fedora (Postfix + Dovecot + Roundcube)
#   Fully rewritten for reliability and correctness
# ============================================================

# --- Colors ---
RED=$(tput setaf 1); GREEN=$(tput setaf 2); YELLOW=$(tput setaf 3)
BLUE=$(tput setaf 4); RESET=$(tput sgr0)

info()  { echo -e "${BLUE}[INFO]${RESET} $*"; }
ok()    { echo -e "${GREEN}[OK]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET} $*"; }
error() { echo -e "${RED}[ERROR]${RESET} $*"; exit 1; }

# --- Paths ---
BACKUP_DIR="/var/backups/mail_hardener"
TIMESTAMP="$(date '+%Y%m%d-%H%M%S')"
BACKUP_FILE="$BACKUP_DIR/mail_backup_$TIMESTAMP.tar.gz"

POSTFIX_DIR="/etc/postfix"
DOVECOT_DIR="/etc/dovecot"
ROUNDCUBE_DIR="/usr/share/roundcubemail"
ROUNDCUBE_DB_DIR="/var/lib/roundcubemail"
ROUNDCUBE_ALIAS="/etc/httpd/conf.d/roundcube.conf"

SSL_CERT="/etc/pki/tls/certs/localhost.crt"
SSL_KEY="/etc/pki/tls/private/localhost.key"

SERVICES=(postfix dovecot httpd)

# ============================================================
# ROOT CHECK
# ============================================================
if [[ $EUID -ne 0 ]]; then
  error "This script must be run as root."
fi

# ============================================================
# DETECT APACHE USER
# ============================================================
detect_apache_user() {
  local user
  user=$(ps aux | grep httpd | grep -v root | grep -v grep | awk '{print $1}' | head -n1 || true)

  if [[ -z "$user" ]]; then
    warn "Could not detect Apache user. Defaulting to 'apache'."
    APACHE_USER="apache"
  else
    APACHE_USER="$user"
  fi

  info "Apache worker user detected: $APACHE_USER"
}

detect_apache_user

# ============================================================
# BACKUP
# ============================================================
backup_configs() {
  mkdir -p "$BACKUP_DIR"
  info "Creating backup at $BACKUP_FILE..."

  tar -czpf "$BACKUP_FILE" \
    "$POSTFIX_DIR" \
    "$DOVECOT_DIR" \
    "$ROUNDCUBE_DIR" \
    "$ROUNDCUBE_ALIAS" 2>/dev/null || true

  ok "Backup complete."
}

# ============================================================
# ROUNDCUBE INSTALLER (FULLY REWRITTEN)
# ============================================================
install_roundcube() {
  info "Installing Roundcube (latest version)..."

  # Remove duplicate alias files
  if [[ -f /etc/httpd/conf.d/roundcubemail.conf ]]; then
    warn "Removing duplicate alias file: roundcubemail.conf"
    rm -f /etc/httpd/conf.d/roundcubemail.conf
  fi

  # Prompt before deleting existing install
  if [[ -d "$ROUNDCUBE_DIR" ]]; then
    warn "Roundcube directory already exists at $ROUNDCUBE_DIR"
    read -rp "Delete and reinstall? (yes/Yes/Y/y to confirm): " confirm
    case "$confirm" in
      yes|Yes|Y|y)
        info "Removing existing Roundcube directory..."
        rm -rf "$ROUNDCUBE_DIR"
        ;;
      *)
        info "Skipping Roundcube installation."
        return 0
        ;;
    esac
  fi

  dnf install -y php php-json php-mbstring php-intl php-xml php-pdo php-pdo_sqlite php-zip php-gd curl unzip

  cd /usr/share

  # Fetch latest version
  latest=$(curl -s https://api.github.com/repos/roundcube/roundcubemail/releases/latest | grep tag_name | cut -d '"' -f4)
  [[ -z "$latest" ]] && error "Failed to fetch latest Roundcube version."

  info "Latest Roundcube version: $latest"

  curl -LO "https://github.com/roundcube/roundcubemail/releases/download/$latest/roundcubemail-$latest-complete.tar.gz"

  tar -xzf "roundcubemail-$latest-complete.tar.gz"

  # Detect extracted directory
  EXTRACTED_DIR=$(tar -tzf "roundcubemail-$latest-complete.tar.gz" | head -1 | cut -d/ -f1)

  [[ ! -d "$EXTRACTED_DIR" ]] && error "Extraction failed: $EXTRACTED_DIR not found."

  mv "$EXTRACTED_DIR" "$ROUNDCUBE_DIR"

  # Permissions
  chown -R "$APACHE_USER":"$APACHE_USER" "$ROUNDCUBE_DIR"
  chmod -R 755 "$ROUNDCUBE_DIR"
  restorecon -RF "$ROUNDCUBE_DIR"

  # SQLite DB
  mkdir -p "$ROUNDCUBE_DB_DIR"
  chown -R "$APACHE_USER":"$APACHE_USER" "$ROUNDCUBE_DB_DIR"

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

  # Validation
  if sudo -u "$APACHE_USER" php "$ROUNDCUBE_DIR/index.php" >/dev/null 2>&1; then
    ok "Roundcube installed successfully."
  else
    error "Roundcube failed validation."
  fi
}

# ============================================================
# HARDENING
# ============================================================
harden_postfix() {
  info "Hardening Postfix..."
  cat <<EOF >> "$POSTFIX_DIR/main.cf"

# Mail Hardener additions
disable_vrfy_command = yes
smtpd_helo_required = yes
smtpd_tls_security_level = may
smtpd_tls_cert_file = $SSL_CERT
smtpd_tls_key_file = $SSL_KEY
EOF
  systemctl restart postfix
  ok "Postfix hardened."
}

harden_dovecot() {
  info "Hardening Dovecot..."
  cat <<EOF >> "$DOVECOT_DIR/conf.d/10-ssl.conf"

ssl = required
ssl_min_protocol = TLSv1.2
ssl_cert = <$SSL_CERT
ssl_key = <$SSL_KEY
EOF
  systemctl restart dovecot
  ok "Dovecot hardened."
}

harden_roundcube() {
  info "Hardening Roundcube..."
  cat <<EOF >> "$ROUNDCUBE_DIR/config/config.inc.php"

\$config['force_https'] = true;
\$config['session_secure'] = true;
\$config['enable_installer'] = false;
EOF
  systemctl restart httpd
  ok "Roundcube hardened."
}

# ============================================================
# MAIN
# ============================================================
case "${1:-}" in
  --test-setup)
    dnf install -y postfix dovecot httpd mod_ssl
    systemctl enable --now postfix dovecot httpd
    install_roundcube
    ;;
  --enable-roundcube)
    install_roundcube
    ;;
  --disable-roundcube)
    rm -rf "$ROUNDCUBE_DIR"
    rm -f "$ROUNDCUBE_ALIAS"
    systemctl restart httpd
    ok "Roundcube disabled."
    ;;
  *)
    backup_configs
    harden_postfix
    harden_dovecot
    harden_roundcube
    ok "Hardening complete. Backup stored at $BACKUP_FILE"
    ;;
esac

