#!/usr/bin/env bash
#
# Master Hardening Script
# Executes a list of hardening scripts sequentially with error handling
# Works across Linux distros (Debian, RHEL, Arch, etc.)
# Made with Copilot AI
# Still needs more testing and room for improvement
# Idea is it goes 1 by 1 down the list of hardening scripts
# Ideally, it is modified depending on the user or the systems needed
#

# === CONFIGURATION SECTION ===
# Add or remove script paths here
HARDENING_SCRIPTS=(
    "create_backup_admin_user.sh"
    "fail2ban_script.sh"
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
    local index="$2"

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

    info "Running script #$index: $script"
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

# === MENU ===
echo "======================================"
echo "   Master Hardening Script Menu"
echo "======================================"
echo "Scripts to be executed:"
for i in "${!HARDENING_SCRIPTS[@]}"; do
    echo "  $((i+1)). ${HARDENING_SCRIPTS[$i]}"
done
echo "======================================"

# Ask user how to run scripts
while true; do
    echo "Choose execution mode:"
    echo "  1) Breaks between scripts (prompt after each)"
    echo "  2) Run all scripts one after another (no breaks)"
    read -rp "Enter choice [1-2]: " mode
    case "$mode" in
        1) BREAKS=true; break ;;
        2) BREAKS=false; break ;;
        *) echo "Invalid choice. Please enter 1 or 2." ;;
    esac
done

# === MAIN EXECUTION LOOP ===
info "Starting master hardening sequence..."
for i in "${!HARDENING_SCRIPTS[@]}"; do
    script="${HARDENING_SCRIPTS[$i]}"
    run_script "$script" "$((i+1))"
    status=$?

    if [[ $status -ne 0 ]]; then
        warn "Encountered an error in $script."
        read -rp "Do you want to continue despite the error? (y/n): " choice
        [[ "$choice" =~ ^[Nn]$ ]] && error "Aborting due to error." && exit 1
    fi

    if [[ "$BREAKS" == true ]]; then
        if ! prompt_continue; then
            info "User chose to stop. Exiting."
            exit 0
        fi
    fi
done

success "All scripts processed."
exit 0
