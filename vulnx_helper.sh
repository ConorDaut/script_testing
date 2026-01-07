#!/usr/bin/env bash

set -euo pipefail

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
#  Version comparison helpers
#  Uses sort -V (coreutils) for semantic-ish compare
# -----------------------------
ver_lt() {
    # $1 < $2 ?
    [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" != "$2" ]
}

ver_le() {
    # $1 <= $2 ?
    first=$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)
    [ "$first" = "$1" ]
}

ver_gt() {
    # $1 > $2 ?
    [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n1)" != "$2" ]
}

ver_ge() {
    # $1 >= $2 ?
    last=$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n1)
    [ "$last" = "$1" ]
}

ver_between_inclusive() {
    # $1 between $2 and $3 inclusive?
    local v="$1" low="$2" high="$3"
    ver_ge "$v" "$low" && ver_le "$v" "$high"
}

# -----------------------------
#  Determine if user's version
#  is vulnerable based on a
#  summary line with version text
# -----------------------------
is_version_vulnerable_from_line() {
    local user_version="$1"
    local line="$2"

    # Extract all version-like tokens
    mapfile -t versions < <(echo "$line" | grep -Eo '[0-9]+\.[0-9]+(\.[0-9]+)?' | sort -u)

    # No version info → can't decide
    [ "${#versions[@]}" -eq 0 ] && return 1

    # Normalize user version once
    local uv
    uv=$(normalize_version "$user_version")

    # Handle common patterns

    # 1) "before X", "prior to X", "up to X", "< X", "<= X"
    if echo "$line" | grep -Eiq 'before|prior to|up to|<='; then
        local bound="${versions[0]}"
        if echo "$line" | grep -Eiq '<='; then
            ver_le "$uv" "$bound" && return 0 || return 1
        else
            # before / prior to / up to → treat as <
            ver_lt "$uv" "$bound" && return 0 || return 1
        fi
    fi

    if echo "$line" | grep -Eq '<'; then
        local bound="${versions[0]}"
        ver_lt "$uv" "$bound" && return 0 || return 1
    fi

    # 2) ">= X", "from X", "since X"
    if echo "$line" | grep -Eiq '>=|from|since'; then
        local bound="${versions[0]}"
        ver_ge "$uv" "$bound" && return 0 || return 1
    fi

    # 3) "X through Y", "between X and Y"
    if echo "$line" | grep -Eiq 'through|between'; then
        if [ "${#versions[@]}" -ge 2 ]; then
            local low="${versions[0]}"
            local high="${versions[1]}"
            ver_between_inclusive "$uv" "$low" "$high" && return 0 || return 1
        fi
    fi

    # 4) Fallback: if a single version is mentioned and line says "affected versions"
    if echo "$line" | grep -Eiq 'affected version|affected versions'; then
        local bound="${versions[0]}"
        # Treat as "up to bound"
        ver_le "$uv" "$bound" && return 0 || return 1
    fi

    # If we get here, we couldn't confidently decide
    return 1
}

# -----------------------------
#  Search CVEs for service + version
#  using summaries and version logic
# -----------------------------
search_cves() {
    read -rp "Enter service name (e.g., dovecot, apache): " service
    read -rp "Enter version (e.g., 2.4.1-4): " version_raw

    local version
    version=$(normalize_version "$version_raw")
    green "Normalized version: $version"

    yellow "Collecting CVEs for service: $service"
    echo

    # Get unique CVE IDs for the service
    mapfile -t cves < <(vulnx search "$service" 2>/dev/null | grep -Eo 'CVE-[0-9]{4}-[0-9]+' | sort -u)

    if [ "${#cves[@]}" -eq 0 ]; then
        red "No CVEs found for service: $service"
        return
    fi

    green "Found ${#cves[@]} CVEs. Analyzing summaries for version impact..."
    echo

    local vulnerable_found=0

    for cve in "${cves[@]}"; do
        # Get summary for each CVE
        summary=$(vulnx id "$cve" 2>/dev/null || true)
        [ -z "$summary" ] && continue

        # Look for lines that mention versions / ranges
        while IFS= read -r line; do
            echo "$line" | grep -Eiq 'version|versions|before|prior to|through|up to|<|<=|>=|between' || continue

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
        yellow "No CVEs clearly matched as affecting $service $version based on summary version text."
    else
        green "Analysis complete."
    fi
}

# -----------------------------
#  Menu
# -----------------------------
menu() {
    while true; do
        echo
        green "=== vulnx Installer & Version-Aware CVE Search Tool ==="
        echo "1) Install vulnx"
        echo "2) Search CVEs by service + version (summary-based)"
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
