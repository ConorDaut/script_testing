#!/usr/bin/env bash

set -euo pipefail

# All Credit goes to the creators of the Vulnx tool
# Found here: https://github.com/projectdiscovery/cvemap
# Made using Copilot AI
# This script is to help automatically install the tool, and make searching easier

# -----------------------------
#  Color helpers
# -----------------------------
green() { printf "\033[1;32m%s\033[0m\n" "$1"; }
yellow() { printf "\033[1;33m%s\033[0m\n" "$1"; }
red() { printf "\033[1;31m%s\033[0m\n" "$1"; }

# -----------------------------
#  Detect distro
# -----------------------------
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    else
        echo "unknown"
    fi
}

# -----------------------------
#  Install Go if missing
# -----------------------------
install_go() {
    if command -v go >/dev/null 2>&1; then
        green "Go is already installed."
        return
    fi

    distro=$(detect_distro)
    yellow "Go not found. Installing Go for distro: $distro"

    case "$distro" in
        fedora|rhel|centos)
            sudo dnf install -y golang
            ;;
        ubuntu|debian|kali)
            sudo apt update
            sudo apt install -y golang
            ;;
        arch)
            sudo pacman -Sy --noconfirm go
            ;;
        *)
            red "Unsupported distro for automatic Go installation."
            exit 1
            ;;
    esac
}

# -----------------------------
#  Ensure GOPATH and PATH
# -----------------------------
fix_go_path() {
    GOPATH=$(go env GOPATH)
    GOBIN=$(go env GOBIN)

    # If GOBIN is empty, binaries go to GOPATH/bin
    if [ -z "$GOBIN" ]; then
        BINPATH="$GOPATH/bin"
    else
        BINPATH="$GOBIN"
    fi

    green "Using Go binary path: $BINPATH"

    # Add to PATH for Bash, Zsh, Fish
    for shellrc in ~/.bashrc ~/.zshrc ~/.config/fish/config.fish; do
        if [ -f "$shellrc" ]; then
            if ! grep -q "$BINPATH" "$shellrc"; then
                echo "export PATH=\$PATH:$BINPATH" >> "$shellrc"
                yellow "Added $BINPATH to PATH in $shellrc"
            fi
        fi
    done

    export PATH="$PATH:$BINPATH"
}

# -----------------------------
#  Install vulnx
# -----------------------------
install_vulnx() {
    green "Installing vulnx..."
    go install github.com/projectdiscovery/cvemap/cmd/vulnx@latest
    green "vulnx installed successfully."
}

# -----------------------------
#  Normalize version
#  (strip distro suffix: 2.4.1-4 → 2.4.1)
# -----------------------------
normalize_version() {
    echo "$1" | sed 's/-.*$//'
}

# -----------------------------
#  Search CVEs for service + version
# -----------------------------
search_cves() {
    read -rp "Enter service name (e.g., dovecot): " service
    read -rp "Enter version (e.g., 2.4.1-4): " version_raw

    version=$(normalize_version "$version_raw")
    green "Normalized version: $version"

    cpe="cpe:2.3:a:${service}:${service}:${version}"

    yellow "Searching for CVEs affecting: $cpe"
    echo

    vulnx search -cpe "$cpe" 2>/dev/null | \
        grep -Eo 'CVE-[0-9]{4}-[0-9]+' | sort -u || {
            red "No CVEs found for this version."
            return
        }

    echo
    green "Search complete."
}

# -----------------------------
#  Menu
# -----------------------------
menu() {
    while true; do
        echo
        green "=== vulnx Installer & CVE Search Tool ==="
        echo "1) Install vulnx"
        echo "2) Search CVEs by service + version"
        echo "3) Exit"
        read -rp "Choose an option: " choice

        case "$choice" in
            1) install_go; fix_go_path; install_vulnx ;;
            2) search_cves ;;
            3) exit 0 ;;
            *) red "Invalid choice." ;;
        esac
    done
}

menu
