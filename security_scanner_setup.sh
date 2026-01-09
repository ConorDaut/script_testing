#!/bin/bash

################################################################################
# ClamAV and RKhunter Installation & Management Script
################################################################################
# Made with Claude AI
# Description:
#   This script installs and configures ClamAV and RKhunter on major Linux
#   distributions. It provides easy-to-use commands for scanning systems.
#
# Usage:
#   1. Run with sudo/root: sudo bash security_scanner_setup.sh
#   2. Follow interactive prompts to install both tools
#   3. Use provided commands for scanning:
#      - clamscan_file <path>     : Scan specific file/directory
#      - clamscan_system          : Scan entire system
#      - rkhunter_scan            : Run RKhunter security scan
#      - rkhunter_baseline        : Establish RKhunter baseline (when clean)
#
# Important Notes:
#   - Run as root/sudo (script will check)
#   - For RKhunter: DO NOT run baseline until you're confident system is clean
#   - Signature databases are updated during installation
#   - Scan results saved to /var/log/security-scans/
#
# Supported Distributions:
#   Ubuntu/Debian, Fedora, RHEL/CentOS/Rocky/Alma, Arch, openSUSE, Kali
#
################################################################################

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Log directory
LOG_DIR="/var/log/security-scans"
SCRIPT_FUNCTIONS="/usr/local/bin"

################################################################################
# Helper Functions
################################################################################

print_header() {
    echo -e "${CYAN}${BOLD}"
    echo "═══════════════════════════════════════════════════════════════"
    echo "$1"
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

################################################################################
# Root Check
################################################################################

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root or with sudo"
        echo -e "${YELLOW}Usage: sudo $0${NC}"
        exit 1
    fi
}

################################################################################
# Distribution Detection
################################################################################

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
    else
        print_error "Unable to detect Linux distribution"
        exit 1
    fi
    
    print_info "Detected distribution: $DISTRO"
}

################################################################################
# Package Manager Functions
################################################################################

update_system() {
    print_info "Updating package lists..."
    case $DISTRO in
        ubuntu|debian|kali)
            apt-get update -qq
            ;;
        fedora)
            dnf check-update -q || true
            ;;
        rhel|centos|rocky|almalinux)
            yum check-update -q || true
            ;;
        arch|manjaro)
            pacman -Sy --noconfirm
            ;;
        opensuse*|sles)
            zypper refresh -q
            ;;
        *)
            print_warning "Unknown distribution, skipping update"
            ;;
    esac
}

install_package() {
    local package=$1
    print_info "Installing $package..."
    
    case $DISTRO in
        ubuntu|debian|kali)
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $package
            ;;
        fedora)
            dnf install -y -q $package
            ;;
        rhel|centos|rocky|almalinux)
            yum install -y -q $package
            ;;
        arch|manjaro)
            pacman -S --noconfirm --quiet $package
            ;;
        opensuse*|sles)
            zypper install -y $package
            ;;
        *)
            print_error "Unsupported distribution for automatic installation"
            return 1
            ;;
    esac
    
    if [ $? -eq 0 ]; then
        print_success "$package installed successfully"
        return 0
    else
        print_error "Failed to install $package"
        return 1
    fi
}

################################################################################
# ClamAV Installation and Configuration
################################################################################

install_clamav() {
    print_header "ClamAV Installation"
    
    # Check if already installed
    if command -v clamscan &> /dev/null; then
        print_warning "ClamAV is already installed"
        read -p "Do you want to reinstall/update? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            return 0
        fi
    fi
    
    # Install ClamAV based on distribution
    case $DISTRO in
        ubuntu|debian|kali)
            install_package "clamav clamav-freshclam"
            ;;
        fedora|rhel|centos|rocky|almalinux)
            install_package "clamav clamav-update"
            # Enable EPEL if needed on RHEL-based
            if [[ $DISTRO == "rhel" ]] || [[ $DISTRO == "centos" ]]; then
                install_package "epel-release" 2>/dev/null || true
            fi
            ;;
        arch|manjaro)
            install_package "clamav"
            ;;
        opensuse*|sles)
            install_package "clamav"
            ;;
        *)
            print_error "Unsupported distribution for ClamAV installation"
            return 1
            ;;
    esac
    
    # Stop freshclam service if running to update manually
    systemctl stop clamav-freshclam 2>/dev/null || service clamav-freshclam stop 2>/dev/null || true
    
    print_info "Updating ClamAV virus definitions (this may take a few minutes)..."
    freshclam --quiet 2>/dev/null || freshclam
    
    if [ $? -eq 0 ]; then
        print_success "ClamAV virus definitions updated successfully"
    else
        print_warning "ClamAV update completed with warnings (this is often normal)"
    fi
    
    print_success "ClamAV installation complete"
}

################################################################################
# RKhunter Installation and Configuration
################################################################################

install_rkhunter() {
    print_header "RKhunter Installation"
    
    # Check if already installed
    if command -v rkhunter &> /dev/null; then
        print_warning "RKhunter is already installed"
        read -p "Do you want to reinstall/update? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            return 0
        fi
    fi
    
    # Install RKhunter based on distribution
    case $DISTRO in
        ubuntu|debian|kali)
            install_package "rkhunter"
            ;;
        fedora|rhel|centos|rocky|almalinux)
            install_package "rkhunter"
            ;;
        arch|manjaro)
            install_package "rkhunter"
            ;;
        opensuse*|sles)
            install_package "rkhunter"
            ;;
        *)
            print_error "Unsupported distribution for RKhunter installation"
            return 1
            ;;
    esac
    
    print_info "Updating RKhunter data files..."
    rkhunter --update --quiet 2>/dev/null || rkhunter --update
    
    if [ $? -eq 0 ]; then
        print_success "RKhunter data files updated successfully"
    else
        print_warning "RKhunter update completed with warnings"
    fi
    
    # Display important warning about baseline
    echo ""
    print_warning "IMPORTANT: RKhunter Baseline Notice"
    echo -e "${YELLOW}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  RKhunter requires a baseline of your system's binaries.      ║${NC}"
    echo -e "${YELLOW}║  DO NOT establish this baseline until you are CONFIDENT       ║${NC}"
    echo -e "${YELLOW}║  your system is clean and free from rootkits/malware.         ║${NC}"
    echo -e "${YELLOW}║                                                                ║${NC}"
    echo -e "${YELLOW}║  To establish baseline later, use:                            ║${NC}"
    echo -e "${YELLOW}║    ${CYAN}rkhunter_baseline${YELLOW}                                         ║${NC}"
    echo -e "${YELLOW}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    print_success "RKhunter installation complete"
}

################################################################################
# Helper Script Creation
################################################################################

create_helper_scripts() {
    print_header "Creating Helper Scripts"
    
    # Create log directory
    mkdir -p "$LOG_DIR"
    chmod 755 "$LOG_DIR"
    
    # Create ClamAV file/directory scan script
    cat > "$SCRIPT_FUNCTIONS/clamscan_file" << 'EOF'
#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'
LOG_DIR="/var/log/security-scans"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

if [ $# -eq 0 ]; then
    echo -e "${RED}Error: Please specify a file or directory to scan${NC}"
    echo -e "${CYAN}Usage: clamscan_file <path>${NC}"
    exit 1
fi

TARGET="$1"
if [ ! -e "$TARGET" ]; then
    echo -e "${RED}Error: Path does not exist: $TARGET${NC}"
    exit 1
fi

echo -e "${CYAN}Starting ClamAV scan of: $TARGET${NC}"
echo -e "${CYAN}Log file: $LOG_DIR/clamscan_${TIMESTAMP}.log${NC}"
echo ""

clamscan -r -i --log="$LOG_DIR/clamscan_${TIMESTAMP}.log" "$TARGET" 2>&1 | tee -a "$LOG_DIR/clamscan_${TIMESTAMP}.log"

echo ""
echo -e "${GREEN}Scan complete. Full log saved to: $LOG_DIR/clamscan_${TIMESTAMP}.log${NC}"
EOF
    chmod +x "$SCRIPT_FUNCTIONS/clamscan_file"
    print_success "Created clamscan_file command"
    
    # Create ClamAV system scan script
    cat > "$SCRIPT_FUNCTIONS/clamscan_system" << 'EOF'
#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
LOG_DIR="/var/log/security-scans"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo -e "${YELLOW}WARNING: Full system scan may take a long time!${NC}"
echo -e "${CYAN}Starting full system ClamAV scan...${NC}"
echo -e "${CYAN}Log file: $LOG_DIR/clamscan_system_${TIMESTAMP}.log${NC}"
echo ""

clamscan -r -i --exclude-dir="^/sys" --exclude-dir="^/proc" --exclude-dir="^/dev" \
    --log="$LOG_DIR/clamscan_system_${TIMESTAMP}.log" / 2>&1 | tee -a "$LOG_DIR/clamscan_system_${TIMESTAMP}.log"

echo ""
echo -e "${GREEN}System scan complete. Full log saved to: $LOG_DIR/clamscan_system_${TIMESTAMP}.log${NC}"
EOF
    chmod +x "$SCRIPT_FUNCTIONS/clamscan_system"
    print_success "Created clamscan_system command"
    
    # Create RKhunter scan script
    cat > "$SCRIPT_FUNCTIONS/rkhunter_scan" << 'EOF'
#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'
LOG_DIR="/var/log/security-scans"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo -e "${CYAN}Starting RKhunter security scan...${NC}"
echo -e "${CYAN}Log file: $LOG_DIR/rkhunter_${TIMESTAMP}.log${NC}"
echo ""

# Check if baseline exists
if [ ! -f /var/lib/rkhunter/db/rkhunter.dat ]; then
    echo -e "${YELLOW}WARNING: No RKhunter baseline found!${NC}"
    echo -e "${YELLOW}This is expected if you haven't run 'rkhunter_baseline' yet.${NC}"
    echo -e "${YELLOW}Results may show many warnings without a baseline.${NC}"
    echo ""
    read -p "Continue anyway? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 0
    fi
fi

rkhunter --check --skip-keypress --report-warnings-only --log "$LOG_DIR/rkhunter_${TIMESTAMP}.log" 2>&1 | tee -a "$LOG_DIR/rkhunter_${TIMESTAMP}.log"

echo ""
echo -e "${GREEN}RKhunter scan complete. Full log saved to: $LOG_DIR/rkhunter_${TIMESTAMP}.log${NC}"
echo -e "${CYAN}Review the log for any warnings or suspicious findings.${NC}"
EOF
    chmod +x "$SCRIPT_FUNCTIONS/rkhunter_scan"
    print_success "Created rkhunter_scan command"
    
    # Create RKhunter baseline script
    cat > "$SCRIPT_FUNCTIONS/rkhunter_baseline" << 'EOF'
#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${YELLOW}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║              RKhunter Baseline Establishment                   ║${NC}"
echo -e "${YELLOW}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${RED}WARNING: Only run this if you are CONFIDENT your system is clean!${NC}"
echo ""
echo -e "${CYAN}This will create a baseline of your system's binaries and files.${NC}"
echo -e "${CYAN}Future scans will compare against this baseline.${NC}"
echo ""
echo -e "${YELLOW}Have you verified your system is free from malware/rootkits?${NC}"
read -p "Are you sure you want to proceed? (yes/no): " -r
echo

if [[ ! $REPLY == "yes" ]]; then
    echo -e "${CYAN}Baseline creation cancelled.${NC}"
    exit 0
fi

echo ""
echo -e "${CYAN}Updating RKhunter data files...${NC}"
rkhunter --update

echo -e "${CYAN}Creating system baseline...${NC}"
rkhunter --propupd

if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✓ RKhunter baseline established successfully!${NC}"
    echo -e "${CYAN}You can now run 'rkhunter_scan' to check your system.${NC}"
else
    echo ""
    echo -e "${RED}✗ Error establishing baseline${NC}"
    exit 1
fi
EOF
    chmod +x "$SCRIPT_FUNCTIONS/rkhunter_baseline"
    print_success "Created rkhunter_baseline command"
    
    print_success "All helper scripts created successfully"
}

################################################################################
# Main Installation Function
################################################################################

main() {
    clear
    print_header "ClamAV & RKhunter Security Scanner Setup"
    
    # Check root privileges
    check_root
    
    # Detect distribution
    detect_distro
    
    # Update system
    update_system
    
    echo ""
    print_info "This script will install ClamAV and RKhunter"
    read -p "Continue with installation? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_warning "Installation cancelled"
        exit 0
    fi
    
    echo ""
    
    # Install ClamAV
    read -p "Install ClamAV? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_clamav
    fi
    
    echo ""
    
    # Install RKhunter
    read -p "Install RKhunter? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_rkhunter
    fi
    
    echo ""
    
    # Create helper scripts
    create_helper_scripts
    
    # Final summary
    echo ""
    print_header "Installation Complete!"
    echo ""
    print_success "Available commands:"
    echo -e "  ${CYAN}clamscan_file <path>${NC}     - Scan specific file or directory"
    echo -e "  ${CYAN}clamscan_system${NC}          - Scan entire system (takes time)"
    echo -e "  ${CYAN}rkhunter_scan${NC}            - Run RKhunter security scan"
    echo -e "  ${CYAN}rkhunter_baseline${NC}        - Establish RKhunter baseline (when clean)"
    echo ""
    print_info "Scan logs are saved to: $LOG_DIR"
    echo ""
    print_warning "Remember: Establish RKhunter baseline only when system is verified clean!"
    echo ""
}

# Run main function
main
