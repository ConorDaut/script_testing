#!/usr/bin/env bash
# ============================================
#   Mail Hardener (Postfix + Dovecot only)
#   Features: Backup, Rollback, TLS Hardening
#   Visual: Color-coded output
#   Made with Copilot AI
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

backup_configs() {
  mkdir -p "$BACKUP_DIR"
  info "Creating backup at $BACKUP_FILE..."
  tar -czpf "$BACKUP_FILE" /etc/postfix /etc/dovecot
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
  tar -xzpf "$latest" -C /
  for svc in "${SERVICES[@]}"; do
    systemctl restart "$svc"
    ok "Restarted $svc"
  done
  ok "Rollback complete."
}

# --- Postfix Hardening ---
harden_postfix() {
  info "Hardening Postfix..."
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

  systemctl restart postfix
  ok "Postfix hardened and restarted."
}

# --- Dovecot Hardening ---
harden_dovecot() {
  info "Hardening Dovecot..."
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

  systemctl restart dovecot
  ok "Dovecot hardened and restarted."
}

# --- Main ---
case "${1:-}" in
  --rollback)
    rollback_latest
    ;;
  *)
    info "Starting Mail Hardener..."
    backup_configs
    harden_postfix
    harden_dovecot
    ok "Hardening complete. Backup stored at $BACKUP_FILE"
    ;;
esac
