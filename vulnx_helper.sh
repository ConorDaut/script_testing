#!/usr/bin/env bash

set -euo pipefail

# All Credit goes to the creators of the Vulnx tool
# Found here: https://github.com/projectdiscovery/cvemap
# Made using Copilot AI
# This script is to help automatically install the tool, and make searching easier

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

    green "Using Go binary path: $BINPATH"

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
#  Extract semantic versions only
# -----------------------------
extract_versions() {
    echo "$1" | grep -Eo '[0-9]+\.[0-9]+(\.[0-9]+)?' | sort -u
}

# -----------------------------
#  Version comparison helpers
# -----------------------------
ver_lt() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" != "$2" ]; }
ver_le() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$1" ]; }
ver_gt() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n1)" != "$2" ]; }
ver_ge() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n1)" = "$1" ]; }

ver_between_inclusive() {
    local v="$1" low="$2" high="$3"
    ver_ge "$v" "$low" && ver_le "$v" "$high"
}

# -----------------------------
#  Determine if user's version
#  is vulnerable based on summary line
# -----------------------------
is_version_vulnerable_from_line() {
    local user_version="$1"
    local line="$2"

    local uv
    uv=$(normalize_version "$user_version")

    mapfile -t versions < <(extract_versions "$line")
    [ "${#versions[@]}" -eq 0 ] && return 1

    # Explicit version list (Option C)
    if echo "$line" | grep -Eiq 'versions|affected versions|include'; then
        for v in "${versions[@]}"; do
            if [ "$uv" = "$v" ]; then
                return 0
            fi
        done
    fi

    # before / prior to / up to
    if echo "$line" | grep -Eiq 'before|prior to|up to'; then
        local bound="${versions[0]}"
        ver_lt "$uv" "$bound" && return 0 || return 1
    fi

    # <=
    if echo "$line" | grep -Eq '<='; then
        local bound="${versions[0]}"
        ver_le "$uv" "$bound" && return 0 || return 1
    fi

    # <
    if echo "$line" | grep -Eq '<'; then
        local bound="${versions[0]}"
        ver_lt "$uv" "$bound" && return 0 || return 1
    fi

    # >=
    if echo "$line" | grep -Eq '>='; then
        local bound="${versions[0]}"
        ver_ge "$uv" "$bound" && return 0 || return 1
    fi

    # through / between
    if echo "$line" | grep -Eiq 'through|between'; then
        if [ "${#versions[@]}" -ge 2 ]; then
            local low="${versions[0]}"
            local high="${versions[1]}"
            ver_between_inclusive "$uv" "$low" "$high" && return 0 || return 1
        fi
    fi

    return 1
}

# -----------------------------
#  Version-aware CVE search
# -----------------------------
search_cves_version_aware() {
    read -rp "Enter service name: " service
    read -rp "Enter version: " version_raw

    local version
    version=$(normalize_version "$version_raw")
    green "Normalized version: $version"

    yellow "Collecting CVEs for service: $service"
    echo

    mapfile -t cves < <(vulnx search "$service" 2>/dev/null | grep -Eo 'CVE-[0-9]{4}-[0-9]+' | sort -u)

    if [ "${#cves[@]}" -eq 0 ]; then
        red "No CVEs found for service: $service"
        return
    fi

    green "Found ${#cves[@]} CVEs. Analyzing summaries..."
    echo

    local vulnerable_found=0

    for cve in "${cves[@]}"; do
        summary=$(vulnx id "$cve" 2>/dev/null || true)
        [ -z "$summary" ] && continue

        while IFS= read -r line; do
            echo "$line" | grep -Eiq 'version|versions|before|prior to|through|up to|<|<=|>=|between|include' || continue

            if is_version_vulnerable_from_line "$version" "$line"; then
                if [ "$vulnerable_found" -eq 0 ]; then
                    green "Potentially vulnerable CVEs for $service $version:"
                    echo
                fi
                vulnerable_found=1
                printf "%s: %s\n" "$cve" "$line"
                break
            fi
        done <<< "$summary"
    done

    echo
    if [ "$vulnerable_found" -eq 0 ]; then
        yellow "No CVEs matched as affecting $service $version."
    else
        green "Analysis complete."
    fi
}

# -----------------------------
#  Simple search by service
# -----------------------------
search_by_service() {
    read -rp "Enter service name: " service
    vulnx search "$service"
}

# -----------------------------
#  Simple search by CVE ID
# -----------------------------
search_by_id() {
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
        echo "4) Version-aware vulnerability analysis"
        echo "5) Exit"
        read -rp "Choose an option: " choice

        case "$choice" in
            1) install_go; fix_go_path; install_vulnx ;;
            2) search_by_service ;;
            3) search_by_id ;;
            4) search_cves_version_aware ;;
            5) exit 0 ;;
            *) red "Invalid choice." ;;
        esac
    done
}

menu
