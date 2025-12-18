#!/usr/bin/env bash
#
# Master Hardening Script
# Executes a list of hardening scripts sequentially with error handling
# Works across Linux distros (Debian, RHEL, Arch, etc.)
# Made with Copilot AI
#

# === CONFIGURATION SECTION ===
# Add or remove script paths here
HARDENING_SCRIPTS=(
    "/path/to/hardening-script-1.sh"
    "/path/to/hardening-script-2.sh"
    "/path/to/hardening-script-3.sh"
)

# === FUNCTIONS ===

# Color-coded output for clarity
info()    { echo -e "\033[1;34m[INFO]\033[0m $*"; }
success() { echo -e "\033[1;32m[SUCCESS]\033[0m $*"; }
warn()    { echo -e "\033[1;33m[WARNING]\033[0m $*"; }
error()   { echo -e "\033[1;31m[ERROR]\033[0m $*"; }

# Run a single script with error handling
run_script() {
    local script="$1"

    if [[ ! -f "$script" ]]; then
        error "Script not found: $script"
        return 1
    fi
    if [[ ! -x "$script" ]]; then
        warn "Script is not executable: $script. Attempting to set +x..."
        chmod +x "$script" || {
            error "Failed to make $script executable."
            return 1
        }
    fi

    info "Running: $script"
    bash "$script"
    local status=$?

    if [[ $status -eq 0 ]]; then
        success "Completed successfully: $script"
    else
        error "Script failed with exit code $status: $script"
        return $status
    fi
}

# Prompt user to continue
prompt_continue() {
    while true; do
        read -rp "Do you want to continue to the next script? (y/n): " choice
        case "$choice" in
            [Yy]*) return 0 ;;
            [Nn]*) return 1 ;;
            *) echo "Please answer y or n." ;;
        esac
    done
}

# === MAIN EXECUTION LOOP ===
info "Starting master hardening sequence..."
for script in "${HARDENING_SCRIPTS[@]}"; do
    run_script "$script"
    status=$?

    if [[ $status -ne 0 ]]; then
        warn "Encountered an error in $script."
        read -rp "Do you want to continue despite the error? (y/n): " choice
        [[ "$choice" =~ ^[Nn]$ ]] && error "Aborting due to error." && exit 1
    fi

    if ! prompt_continue; then
        info "User chose to stop. Exiting."
        exit 0
    fi
done

success "All scripts processed."
exit 0
