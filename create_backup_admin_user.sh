#!/usr/bin/env bash
# create_backup_admin_user.sh
# Creates a local admin "break-glass" user with a home directory and interactive password.
# Designed to be portable across major Linux distros (Debian/Ubuntu, RHEL/CentOS/Fedora, SUSE, Arch, etc.)
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

read_username() {
  local u
  while :; do
    printf "Enter local backup admin username: "
    IFS= read -r u
    # Basic POSIX username validation: start with a letter, then letters/numbers/._-
    if [ -z "$u" ]; then
      error "Username cannot be empty."
      continue
    fi
    if ! printf "%s" "$u" | grep -Eq '^[a-zA-Z][a-zA-Z0-9._-]*$'; then
      error "Invalid username. Use letters, numbers, dot, underscore, dash; must start with a letter."
      continue
    fi
    USERNAME="$u"
    break
  done
}

read_password() {
  local p1 p2
  while :; do
    printf "Enter password for '%s': " "$USERNAME"
    stty -echo
    IFS= read -r p1
    stty echo
    printf "\n"
    if [ -z "$p1" ]; then
      error "Password cannot be empty."
      continue
    fi
    printf "Confirm password: "
    stty -echo
    IFS= read -r p2
    stty echo
    printf "\n"
    if [ "$p1" != "$p2" ]; then
      error "Passwords do not match."
      continue
    fi
    PASSWORD="$p1"
    break
  done
}

ensure_home_and_shell() {
  # Default home and shell
  HOME_DIR="/home/$USERNAME"
  # Prefer bash if available, else sh
  if [ -x /bin/bash ]; then
    USER_SHELL="/bin/bash"
  elif [ -x /usr/bin/bash ]; then
    USER_SHELL="/usr/bin/bash"
  elif [ -x /bin/sh ]; then
    USER_SHELL="/bin/sh"
  else
    # Fallback to whatever getent says or leave empty; most systems have /bin/sh
    USER_SHELL="/bin/sh"
  fi
}

user_exists() {
  getent passwd "$USERNAME" >/dev/null 2>&1
}

create_user_with_useradd() {
  local args=( -m -d "$HOME_DIR" -s "$USER_SHELL" "$USERNAME" )
  # Many distros default to creating a primary group with the same name
  info "Creating user with useradd..."
  useradd "${args[@]}" || {
    error "useradd failed."
    exit 1
  }
}

create_user_with_adduser() {
  # adduser behavior varies; use non-interactive flags where possible
  info "Creating user with adduser..."
  if have_cmd adduser; then
    # Debian/Ubuntu style
    adduser --home "$HOME_DIR" --shell "$USER_SHELL" --disabled-password "$USERNAME" || {
      error "adduser failed."
      exit 1
    }
  else
    error "adduser not found."
    exit 1
  fi
}

set_password() {
  # Use chpasswd to set password non-interactively, works across most distros
  printf "%s:%s\n" "$USERNAME" "$PASSWORD" | chpasswd || {
    error "Failed to set password via chpasswd."
    exit 1
  }
}

ensure_sudoers_d() {
  # Ensure /etc/sudoers.d exists and correct perms
  if [ ! -d /etc/sudoers.d ]; then
    mkdir -p /etc/sudoers.d
    chmod 750 /etc/sudoers.d
  fi
}

write_sudoers_file() {
  # Grant per-user admin privileges using sudoers.d to avoid group differences (sudo vs wheel)
  local file="/etc/sudoers.d/99-${USERNAME}-admin"
  # Require password when using sudo, change to NOPASSWD:ALL if you prefer no prompt
  cat > "$file" <<EOF
# Local break-glass admin user
$USERNAME ALL=(ALL) ALL
EOF
  chmod 440 "$file"

  # Validate with visudo if available
  if have_cmd visudo; then
    if ! visudo -cf "$file" >/dev/null 2>&1; then
      error "visudo validation failed for $file. Reverting."
      rm -f "$file"
      exit 1
    fi
  fi
}

add_to_common_admin_groups() {
  # Optional: add to common admin groups if they exist
  # This helps environments where policies rely on groups like sudo or wheel
  local added_any=false
  for g in sudo wheel adm; do
    if getent group "$g" >/dev/null 2>&1; then
      usermod -aG "$g" "$USERNAME" && added_any=true || true
    fi
  done
  if [ "$added_any" = true ]; then
    info "Added '$USERNAME' to existing admin-related groups (sudo/wheel/adm) where present."
  fi
}

ensure_home_ownership() {
  # Ensure home exists and ownership is correct
  if [ ! -d "$HOME_DIR" ]; then
    mkdir -p "$HOME_DIR"
  fi
  chown -R "$USERNAME":"$USERNAME" "$HOME_DIR"
  chmod 700 "$HOME_DIR" || true
}

main() {
  require_root
  read_username
  ensure_home_and_shell

  if user_exists; then
    info "User '$USERNAME' already exists."
    printf "Do you want to reset the password and admin privileges for this user? [y/N]: "
    IFS= read -r ans
    case "${ans:-N}" in
      y|Y)
        read_password
        set_password
        ;;
      *)
        info "Skipping password change."
        ;;
    esac
  else
    read_password
    # Prefer useradd if present; otherwise attempt adduser
    if have_cmd useradd; then
      create_user_with_useradd
    elif have_cmd adduser; then
      create_user_with_adduser
    else
      error "Neither 'useradd' nor 'adduser' is available. Cannot create user."
      exit 1
    fi
    set_password
  fi

  ensure_home_ownership
  ensure_sudoers_d
  write_sudoers_file
  add_to_common_admin_groups

  info "-----------------------------------------"
  info "Local backup admin user setup complete."
  info "Username: $USERNAME"
  info "Home dir: $HOME_DIR"
  info "Shell:     $USER_SHELL"
  info "Admin:     Granted via /etc/sudoers.d/99-${USERNAME}-admin"
  info "-----------------------------------------"
  info "Test with: sudo -l -U $USERNAME  (or log in and run: sudo whoami)"
}

main "$@"
