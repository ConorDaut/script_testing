#!/usr/bin/env bash

set -euo pipefail

# All Credit goes to the creators of the Vulnx tool
# Found here: https://github.com/projectdiscovery/cvemap
# Made using Copilot AI
# This script is made for easily using the Vulnx tool
# It helps with automatically installing the tool, and makes searching for services and CVEs easier

# -----------------------------
#  Color helpers
# -----------------------------
green()  { printf "\033[1;32m%s\033[0m\n" "$1"; }
yellow() { printf "\033[1;33m%s\033[0m\n" "$1"; }
red()    { printf "\033[1;31m%s\033[0m\n" "$1"; }

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
            sudo dnf install -y golang ;;
        ubuntu|debian|kali)
            sudo apt update
            sudo apt install -y golang ;;
        arch)
            sudo pacman -Sy --noconfirm go ;;
        *)
            red "Unsupported distro for automatic Go installation."
            exit 1 ;;
    esac
}

# -----------------------------
#  Ensure GOPATH / GOBIN on PATH
# -----------------------------
fix_go_path() {
    GOPATH=$(go env GOPATH)
    GOBIN=$(go env GOBIN)

    if [ -z "$GOBIN" ]; then
        BINPATH="$GOPATH/bin"
    else
        BINPATH="$GOBIN"
    fi

    # Add to PATH for current session
    export PATH="$PATH:$BINPATH"

    # Add to shell RC files
    for shellrc in ~/.bashrc ~/.zshrc ~/.config/fish/config.fish; do
        if [ -f "$shellrc" ]; then
            if ! grep -q "$BINPATH" "$shellrc"; then
                echo "export PATH=\$PATH:$BINPATH" >> "$shellrc"
                yellow "Added $BINPATH to PATH in $shellrc"
            fi
        fi
    done

    green "Go binary path ensured: $BINPATH"
}

# -----------------------------
#  Install vulnx
# -----------------------------
install_vulnx() {
    green "Installing vulnx..."
    go install github.com/projectdiscovery/cvemap/cmd/vulnx@latest

    # Ensure PATH is updated immediately
    fix_go_path

    if ! command -v vulnx >/dev/null 2>&1; then
        red "vulnx installation completed, but command not found."
        red "Try opening a new terminal or source your shell config."
        exit 1
    fi

    green "vulnx installed successfully and is ready to use."
}

# -----------------------------
#  Search by service
# -----------------------------
search_by_service() {
    if ! command -v vulnx >/dev/null 2>&1; then
        red "vulnx is not installed. Install it first."
        return
    fi

    read -rp "Enter service name: " service
    vulnx search "$service"
}

# -----------------------------
#  Search by CVE ID
# -----------------------------
search_by_id() {
    if ! command -v vulnx >/dev/null 2>&1; then
        red "vulnx is not installed. Install it first."
        return
    fi

    read -rp "Enter CVE ID: " cve
    vulnx id "$cve"
}

# -----------------------------
#  Menu
# -----------------------------
menu() {
    while true; do
        echo
        green "=== vulnx Toolkit ==="
        echo "1) Install vulnx"
        echo "2) Search by service"
        echo "3) Search by CVE ID"
        echo "4) Exit"
        read -rp "Choose an option: " choice

        case "$choice" in
            1) install_go; fix_go_path; install_vulnx ;;
            2) search_by_service ;;
            3) search_by_id ;;
            4) exit 0 ;;
            *) red "Invalid choice." ;;
        esac
    done
}

menu
