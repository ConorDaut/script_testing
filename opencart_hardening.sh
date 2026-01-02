#!/usr/bin/env bash
# Made using Copilot AI
# opencart_hardening.sh
#
# Purpose:
#   Opinionated hardening helper for an existing OpenCart installation on Ubuntu.
#
#   This script can:
#     - Create timestamped backups of the OpenCart webroot and database
#     - Roll back to a previous backup (files + database)
#     - Apply a set of basic hardening steps for an Apache-hosted OpenCart site
#       * Tighten file and directory permissions
#       * Lock down config files
#       * Disable directory listing via .htaccess
#       * Add some additional Apache/OpenCart-oriented protections
#
# Notes:
#   - This script assumes:
#       * Ubuntu + Apache + PHP + MySQL/MariaDB
#       * OpenCart already installed and working
#       * PHP CLI is available (php command) so we can read DB credentials
#   - You must run this as root (sudo).
#   - Backups are stored under /var/backups/opencart-hardening/.
#   - Rollback will restore both files and database. Use with care on production.
#
#   ALWAYS test on a staging system or make your own external backups first.

set -euo pipefail

############################
# Color and formatting
############################

RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
MAGENTA="\e[35m"
CYAN="\e[36m"
BOLD="\e[1m"
RESET="\e[0m"

info()    { echo -e "${BLUE}[INFO]${RESET} $*"; }
ok()      { echo -e "${GREEN}[OK]${RESET}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET} $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
section() { echo -e "\n${MAGENTA}${BOLD}==> $*${RESET}\n"; }

############################
# Basic checks and defaults
############################

if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (use sudo)."
    exit 1
fi

# Default locations (edit these if needed)
OC_ROOT_DEFAULT="/var/www/html/opencart"
BACKUP_BASE_DIR="/var/backups/opencart-hardening"
APACHE_USER="www-data"
APACHE_GROUP="www-data"

############################
# Helper: ask for opencart root
############################

ask_oc_root() {
    local oc_root

    echo
    read -r -p "Enter OpenCart webroot path [${OC_ROOT_DEFAULT}]: " oc_root
    if [[ -z "$oc_root" ]]; then
        oc_root="$OC_ROOT_DEFAULT"
    fi

    if [[ ! -d "$oc_root" ]]; then
        error "Directory '$oc_root' does not exist. Please adjust and try again."
        exit 1
    fi

    if [[ ! -f "$oc_root/config.php" ]]; then
        warn "config.php not found in '$oc_root'."
        warn "Make sure this is the correct OpenCart root (it should contain config.php)."
        read -r -p "Continue anyway? [y/N]: " cont
        cont=${cont:-N}
        if [[ ! "$cont" =~ ^[Yy]$ ]]; then
            error "Aborting by user choice."
            exit 1
        fi
    fi

    echo "$oc_root"
}

############################
# Helper: extract DB credentials via PHP
############################

get_db_credentials() {
    local oc_root="$1"

    if ! command -v php >/dev/null 2>&1; then
        error "php CLI is not installed. Install it (e.g. 'apt install php-cli') to use DB backup/rollback."
        return 1
    fi

    if [[ ! -f "$oc_root/config.php" ]]; then
        error "config.php not found at '$oc_root/config.php'; cannot read DB credentials."
        return 1
    fi

    local result
    result=$(php -r "
        error_reporting(E_ALL ^ E_WARNING ^ E_NOTICE);
        require '$oc_root/config.php';
        echo DB_USERNAME,':',DB_PASSWORD,':',DB_DATABASE,':',DB_HOSTNAME;
    " 2>/dev/null || true)

    if [[ -z "$result" ]]; then
        error "Unable to read DB credentials from config.php via PHP."
        return 1
    fi

    IFS=':' read -r DB_USER DB_PASS DB_NAME DB_HOST <<< "$result"

    if [[ -z "${DB_USER:-}" || -z "${DB_NAME:-}" || -z "${DB_HOST:-}" ]]; then
        error "DB credentials read from config.php appear incomplete."
        return 1
    fi

    export DB_USER DB_PASS DB_NAME DB_HOST
    return 0
}

############################
# Backup logic
############################

create_backup() {
    section "Creating backup"

    local oc_root="$1"
    local ts backup_dir web_tar db_dump

    ts=$(date +"%Y%m%d-%H%M%S")
    backup_dir="${BACKUP_BASE_DIR}/${ts}"
    web_tar="${backup_dir}/webroot.tar.gz"
    db_dump="${backup_dir}/db.sql"

    mkdir -p "$backup_dir"

    info "Backing up webroot: ${oc_root} -> ${web_tar}"
    tar -czf "$web_tar" -C "$(dirname "$oc_root")" "$(basename "$oc_root")"
    ok "Webroot backup created."

    if get_db_credentials "$oc_root"; then
        info "Backing up database '${DB_NAME}' -> ${db_dump}"
        if ! mysqldump -h "$DB_HOST" -u "$DB_USER" "-p${DB_PASS}" "$DB_NAME" > "$db_dump" 2>/dev/null; then
            warn "Database backup failed. Check DB credentials and permissions."
            warn "Continuing, but this backup will NOT have a DB dump."
            rm -f "$db_dump"
        else
            ok "Database backup created."
        fi
    else
        warn "Skipping DB backup due to credential issues."
    fi

    echo "$backup_dir"
}

list_backups() {
    if [[ ! -d "$BACKUP_BASE_DIR" ]]; then
        warn "No backup directory found at '$BACKUP_BASE_DIR'."
        return 1
    fi

    ls -1 "$BACKUP_BASE_DIR" | sort
}

############################
# Rollback logic
############################

rollback_backup() {
    section "Rollback from backup"

    local oc_root="$1"
    local backup_dir

    if [[ ! -d "$BACKUP_BASE_DIR" ]]; then
        error "No backups found at '$BACKUP_BASE_DIR'."
        return 1
    fi

    info "Available backups:"
    echo "------------------"
    list_backups || true
    echo "------------------"

    read -r -p "Enter timestamp of backup to restore (e.g. 20250102-123456): " ts
    backup_dir="${BACKUP_BASE_DIR}/${ts}"

    if [[ ! -d "$backup_dir" ]]; then
        error "Backup directory '$backup_dir' does not exist."
        return 1
    fi

    local web_tar="${backup_dir}/webroot.tar.gz"
    local db_dump="${backup_dir}/db.sql"

    if [[ ! -f "$web_tar" ]]; then
        error "Webroot archive '$web_tar' not found in backup. Cannot rollback."
        return 1
    fi

    warn "This will overwrite your current OpenCart files under '$oc_root'."
    warn "If db.sql exists, it will also overwrite the database."
    read -r -p "Type 'ROLLBACK' to confirm: " confirm
    if [[ "$confirm" != "ROLLBACK" ]]; then
        error "Rollback aborted."
        return 1
    fi

    # Restore webroot
    section "Restoring webroot"
    info "Removing current webroot: $oc_root"
    rm -rf "$oc_root"
    info "Extracting backup: $web_tar"
    tar -xzf "$web_tar" -C "$(dirname "$oc_root")"
    ok "Webroot restored."

    # Restore database if present
    if [[ -f "$db_dump" ]]; then
        section "Restoring database"
        if get_db_credentials "$oc_root"; then
            warn "Restoring database '${DB_NAME}' from '$db_dump'. This will overwrite existing data."
            read -r -p "Proceed with DB restore? [y/N]: " db_confirm
            db_confirm=${db_confirm:-N}
            if [[ "$db_confirm" =~ ^[Yy]$ ]]; then
                if ! mysql -h "$DB_HOST" -u "$DB_USER" "-p${DB_PASS}" "$DB_NAME" < "$db_dump"; then
                    error "Database restore failed. Check credentials and try manually if needed."
                    return 1
                else
                    ok "Database restored."
                fi
            else
                warn "Skipped database restore by user choice."
            fi
        else
            error "Cannot restore DB because credentials could not be retrieved."
        fi
    else
        warn "No db.sql found in backup; skipping DB restore."
    fi

    ok "Rollback process complete."
}

############################
# Hardening logic
############################

harden_opencart() {
    section "Applying OpenCart hardening"

    local oc_root="$1"

    if [[ ! -d "$oc_root" ]]; then
        error "OpenCart root '$oc_root' does not exist."
        return 1
    fi

    ############################
    # 1. Ownership and basic permissions
    ############################
    section "Fixing ownership and permissions"

    info "Setting ownership to ${APACHE_USER}:${APACHE_GROUP} for '$oc_root'."
    chown -R "${APACHE_USER}:${APACHE_GROUP}" "$oc_root"
    ok "Ownership updated."

    info "Setting directory permissions (755) and file permissions (644)."
    find "$oc_root" -type d -exec chmod 755 {} \;
    find "$oc_root" -type f -exec chmod 644 {} \;
    ok "Basic permissions applied."

    ############################
    # 2. Harden config files
    ############################
    section "Hardening config files"

    local main_config="$oc_root/config.php"
    local admin_config

    # Detect admin directory
    if [[ -d "$oc_root/admin" ]]; then
        admin_config="$oc_root/admin/config.php"
    else
        # Try to find any admin config.php
        admin_config=$(find "$oc_root" -maxdepth 2 -type f -name "config.php" | grep "/admin/" || true)
    fi

    if [[ -f "$main_config" ]]; then
        info "Locking down $main_config"
        chmod 640 "$main_config"
        chown "${APACHE_USER}:${APACHE_GROUP}" "$main_config"
        ok "Main config hardened."
    else
        warn "Main config.php not found at $main_config"
    fi

    if [[ -n "$admin_config" && -f "$admin_config" ]]; then
        info "Locking down $admin_config"
        chmod 640 "$admin_config"
        chown "${APACHE_USER}:${APACHE_GROUP}" "$admin_config"
        ok "Admin config hardened."
    else
        warn "Admin config.php not found under admin/."
    fi

    ############################
    # 3. Apache / .htaccess protections
    ############################
    section "Applying .htaccess protections"

    local htaccess_root="$oc_root/.htaccess"

    # Ensure directory listing is disabled and some generic protections are present
    if [[ ! -f "$htaccess_root" ]]; then
        info "Creating .htaccess in webroot."
        cat > "$htaccess_root" <<'EOF'
# Basic OpenCart hardening

# Disable directory listing
Options -Indexes

# Disable access to sensitive files
<FilesMatch "(^\.|config\.php|index\.php~|\.bak|\.swp)">
    Require all denied
</FilesMatch>

# Block access to Git, SVN, and other VCS metadata
RedirectMatch 404 /(\.git|\.svn|\.hg|\.bzr)/

# Prevent access to composer files and environment files
<FilesMatch "(composer\.(json|lock)|package\.json|yarn\.lock|\.env)">
    Require all denied
</FilesMatch>

# Mitigate some XSS/Clickjacking via headers (Apache 2.4+)
<IfModule mod_headers.c>
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
</IfModule>
EOF
        ok "Created basic .htaccess for OpenCart."
    else
        info ".htaccess already exists in webroot; appending some hardening directives (idempotent where possible)."

        # Add Options -Indexes if missing
        if ! grep -q "Options -Indexes" "$htaccess_root"; then
            echo -e "\nOptions -Indexes" >> "$htaccess_root"
            ok "Added 'Options -Indexes' to .htaccess."
        else
            info "'Options -Indexes' already present."
        fi

        # Add simple header block if not present
        if ! grep -q "X-Frame-Options" "$htaccess_root"; then
            cat >> "$htaccess_root" <<'EOF'

# Additional security headers
<IfModule mod_headers.c>
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
</IfModule>
EOF
            ok "Added security headers block to .htaccess."
        else
            info "Security headers already present (or similar); not duplicating."
        fi
    fi

    ############################
    # 4. Protect common writable directories
    ############################
    section "Protecting writable directories (upload/storage/etc.)"

    # Common directories for OpenCart (adjust per your setup)
    local writable_dirs=(
        "system/storage"
        "system/storage/cache"
        "system/storage/logs"
        "system/storage/download"
        "system/storage/upload"
        "image/cache"
    )

    for rel in "${writable_dirs[@]}"; do
        local dir="$oc_root/$rel"
        local htf="$dir/.htaccess"

        if [[ -d "$dir" ]]; then
            info "Hardening $dir"
            mkdir -p "$dir"
            cat > "$htf" <<'EOF'
# Deny direct access to files in this directory
<Files "*">
    Require all denied
</Files>

# But allow access to index.php (if applicable)
<Files "index.php">
    Require all granted
</Files>
EOF
            chmod 644 "$htf"
            chown "${APACHE_USER}:${APACHE_GROUP}" "$htf"
            ok "Added restrictive .htaccess to $dir."
        else
            info "Directory '$dir' not found; skipping."
        fi
    done

    ############################
    # 5. Optional: ensure PHP errors are not exposed (app-level setting hint)
    ############################
    section "Review OpenCart error display and logging"

    warn "Make sure in OpenCart admin -> System -> Settings -> Server:"
    echo -e "  - ${BOLD}Display Errors${RESET}: set to 'No' on production."
    echo -e "  - ${BOLD}Log Errors${RESET}: set to 'Yes'."
    echo -e "  - Ensure 'system/storage/logs' is not publicly accessible (we added .htaccess)."

    ############################
    # 6. Final notes
    ############################
    ok "Hardening steps completed for '$oc_root'."
    echo
    info "You may want to also:"
    echo -e "  - Change the admin URL path to something non-default."
    echo -e "  - Use strong admin passwords and enable 2FA where possible."
    echo -e "  - Keep OpenCart core, extensions, and theme up to date."
}

############################
# Menu
############################

show_menu() {
    cat <<EOF

${BOLD}OpenCart Hardening Script${RESET}
---------------------------------
Choose an action:

  1) Create backup (files + DB)
  2) Apply hardening to OpenCart
  3) Rollback from an existing backup
  4) List backups
  5) Exit

EOF
}

main() {
    local choice oc_root backup_dir

    oc_root=$(ask_oc_root)

    while true; do
        show_menu
        read -r -p "Enter choice [1-5]: " choice

        case "$choice" in
            1)
                backup_dir=$(create_backup "$oc_root")
                ok "Backup completed. Stored at: $backup_dir"
                ;;
            2)
                # Always create a backup before hardening
                section "Pre-hardening backup"
                backup_dir=$(create_backup "$oc_root")
                ok "Pre-hardening backup stored at: $backup_dir"
                harden_opencart "$oc_root"
                ;;
            3)
                rollback_backup "$oc_root"
                ;;
            4)
                section "Existing backups"
                if ! list_backups; then
                    warn "No backups found."
                fi
                ;;
            5)
                info "Exiting."
                exit 0
                ;;
            *)
                warn "Invalid choice. Please select 1-5."
                ;;
        esac
    done
}

main "$@"
