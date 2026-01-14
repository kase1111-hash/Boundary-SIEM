#!/bin/bash
# Boundary SIEM Security Policy Installer
# This script installs SELinux or AppArmor policies based on the detected MAC system.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SELINUX_DIR="${SCRIPT_DIR}/selinux"
APPARMOR_DIR="${SCRIPT_DIR}/apparmor"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Detect MAC system
detect_mac_system() {
    if [[ -d /sys/fs/selinux ]]; then
        echo "selinux"
    elif [[ -d /sys/kernel/security/apparmor ]]; then
        echo "apparmor"
    elif [[ -f /sys/kernel/security/lsm ]]; then
        local lsm
        lsm=$(cat /sys/kernel/security/lsm)
        if [[ $lsm == *"selinux"* ]]; then
            echo "selinux"
        elif [[ $lsm == *"apparmor"* ]]; then
            echo "apparmor"
        else
            echo "none"
        fi
    else
        echo "none"
    fi
}

# Install SELinux policy
install_selinux() {
    log_info "Installing SELinux policy..."

    # Check for required tools
    for cmd in checkmodule semodule_package semodule semanage restorecon; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "Required command '$cmd' not found. Install policycoreutils-python-utils."
            exit 1
        fi
    done

    cd "${SELINUX_DIR}"

    # Compile type enforcement policy
    log_info "Compiling type enforcement policy..."
    checkmodule -M -m -o boundary_siem.mod boundary_siem.te
    if [[ $? -ne 0 ]]; then
        log_error "Failed to compile SELinux policy module"
        exit 1
    fi

    # Package policy module
    log_info "Packaging policy module..."
    semodule_package -o boundary_siem.pp -m boundary_siem.mod
    if [[ $? -ne 0 ]]; then
        log_error "Failed to package SELinux policy"
        exit 1
    fi

    # Install policy module
    log_info "Installing policy module..."
    semodule -i boundary_siem.pp
    if [[ $? -ne 0 ]]; then
        log_error "Failed to install SELinux policy"
        exit 1
    fi

    # Define ports
    log_info "Defining custom ports..."
    semanage port -a -t boundary_siem_port_t -p tcp 8080 2>/dev/null || true
    semanage port -a -t boundary_siem_port_t -p tcp 9090 2>/dev/null || true
    semanage port -a -t kafka_port_t -p tcp 9092 2>/dev/null || true
    semanage port -a -t kafka_port_t -p tcp 9093 2>/dev/null || true
    semanage port -a -t clickhouse_port_t -p tcp 8123 2>/dev/null || true
    semanage port -a -t clickhouse_port_t -p tcp 9000 2>/dev/null || true

    # Apply file contexts
    log_info "Applying file contexts..."

    # Create directories if they don't exist
    mkdir -p /etc/boundary-siem
    mkdir -p /var/log/boundary-siem
    mkdir -p /var/lib/boundary-siem

    # Apply file contexts from .fc file
    semanage fcontext -a -t boundary_siem_exec_t '/usr/local/bin/boundary-siem' 2>/dev/null || true
    semanage fcontext -a -t boundary_siem_conf_t '/etc/boundary-siem(/.*)?' 2>/dev/null || true
    semanage fcontext -a -t boundary_siem_log_t '/var/log/boundary-siem(/.*)?' 2>/dev/null || true
    semanage fcontext -a -t boundary_siem_var_t '/var/lib/boundary-siem(/.*)?' 2>/dev/null || true

    # Restore file contexts
    restorecon -Rv /usr/local/bin/boundary-siem 2>/dev/null || true
    restorecon -Rv /etc/boundary-siem
    restorecon -Rv /var/log/boundary-siem
    restorecon -Rv /var/lib/boundary-siem

    log_info "SELinux policy installed successfully"
}

# Install AppArmor profile
install_apparmor() {
    log_info "Installing AppArmor profile..."

    # Check for required tools
    if ! command -v apparmor_parser &> /dev/null; then
        log_error "apparmor_parser not found. Install apparmor-utils."
        exit 1
    fi

    # Copy profile to AppArmor directory
    log_info "Copying profile to /etc/apparmor.d/..."
    cp "${APPARMOR_DIR}/boundary-siem" /etc/apparmor.d/boundary-siem
    chmod 644 /etc/apparmor.d/boundary-siem

    # Create directories if they don't exist
    mkdir -p /etc/boundary-siem
    mkdir -p /var/log/boundary-siem
    mkdir -p /var/lib/boundary-siem
    mkdir -p /tmp/boundary-siem

    # Load the profile
    log_info "Loading AppArmor profile..."
    apparmor_parser -r /etc/apparmor.d/boundary-siem
    if [[ $? -ne 0 ]]; then
        log_error "Failed to load AppArmor profile"
        exit 1
    fi

    # Verify profile is loaded
    if aa-status 2>/dev/null | grep -q "boundary-siem"; then
        log_info "AppArmor profile loaded and active"
    else
        log_warn "Profile installed but may not be active. Check aa-status."
    fi

    log_info "AppArmor profile installed successfully"
}

# Verify installation
verify_installation() {
    log_info "Verifying installation..."

    local mac_system
    mac_system=$(detect_mac_system)

    case $mac_system in
        selinux)
            if semodule -l | grep -q "boundary_siem"; then
                log_info "SELinux policy module is loaded"
            else
                log_error "SELinux policy module not found"
                exit 1
            fi

            local mode
            mode=$(getenforce 2>/dev/null || echo "Unknown")
            log_info "SELinux mode: $mode"

            if [[ $mode == "Enforcing" ]]; then
                log_info "SELinux is in enforcing mode"
            else
                log_warn "SELinux is not in enforcing mode. Consider: setenforce 1"
            fi
            ;;
        apparmor)
            if aa-status 2>/dev/null | grep -q "boundary-siem"; then
                log_info "AppArmor profile is active"
            else
                log_warn "AppArmor profile may not be active"
            fi

            local mode
            mode=$(aa-status 2>/dev/null | head -n1 || echo "Unknown")
            log_info "AppArmor status: $mode"
            ;;
        *)
            log_warn "No MAC system detected"
            ;;
    esac
}

# Uninstall policies
uninstall() {
    log_info "Uninstalling security policies..."

    local mac_system
    mac_system=$(detect_mac_system)

    case $mac_system in
        selinux)
            log_info "Removing SELinux policy..."
            semodule -r boundary_siem 2>/dev/null || true
            semanage fcontext -d '/usr/local/bin/boundary-siem' 2>/dev/null || true
            semanage fcontext -d '/etc/boundary-siem(/.*)?' 2>/dev/null || true
            semanage fcontext -d '/var/log/boundary-siem(/.*)?' 2>/dev/null || true
            semanage fcontext -d '/var/lib/boundary-siem(/.*)?' 2>/dev/null || true
            log_info "SELinux policy removed"
            ;;
        apparmor)
            log_info "Removing AppArmor profile..."
            apparmor_parser -R /etc/apparmor.d/boundary-siem 2>/dev/null || true
            rm -f /etc/apparmor.d/boundary-siem
            log_info "AppArmor profile removed"
            ;;
        *)
            log_warn "No MAC system detected, nothing to uninstall"
            ;;
    esac
}

# Set profile to complain/permissive mode (for debugging)
set_permissive() {
    log_info "Setting permissive/complain mode..."

    local mac_system
    mac_system=$(detect_mac_system)

    case $mac_system in
        selinux)
            semanage permissive -a boundary_siem_t
            log_info "SELinux domain boundary_siem_t is now permissive"
            ;;
        apparmor)
            aa-complain /etc/apparmor.d/boundary-siem
            log_info "AppArmor profile is now in complain mode"
            ;;
        *)
            log_error "No MAC system detected"
            exit 1
            ;;
    esac
}

# Set profile to enforcing mode
set_enforcing() {
    log_info "Setting enforcing mode..."

    local mac_system
    mac_system=$(detect_mac_system)

    case $mac_system in
        selinux)
            semanage permissive -d boundary_siem_t 2>/dev/null || true
            log_info "SELinux domain boundary_siem_t is now enforcing"
            ;;
        apparmor)
            aa-enforce /etc/apparmor.d/boundary-siem
            log_info "AppArmor profile is now in enforce mode"
            ;;
        *)
            log_error "No MAC system detected"
            exit 1
            ;;
    esac
}

# Print usage
usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  install      Install security policies (auto-detects MAC system)"
    echo "  uninstall    Remove security policies"
    echo "  verify       Verify installation"
    echo "  permissive   Set profile to permissive/complain mode"
    echo "  enforcing    Set profile to enforcing mode"
    echo "  status       Show current status"
    echo ""
    echo "Example:"
    echo "  sudo $0 install"
}

# Show status
show_status() {
    local mac_system
    mac_system=$(detect_mac_system)

    echo "================================"
    echo "Boundary SIEM Security Status"
    echo "================================"
    echo ""
    echo "MAC System: $mac_system"
    echo ""

    case $mac_system in
        selinux)
            echo "SELinux Mode: $(getenforce 2>/dev/null || echo 'Unknown')"
            echo ""
            echo "Policy Version: $(cat /sys/fs/selinux/policyvers 2>/dev/null || echo 'Unknown')"
            echo ""
            echo "Boundary SIEM Module:"
            semodule -l 2>/dev/null | grep boundary_siem || echo "  Not installed"
            echo ""
            echo "Current Process Context:"
            cat /proc/self/attr/current 2>/dev/null || echo "  Unknown"
            ;;
        apparmor)
            echo "AppArmor Status:"
            aa-status 2>/dev/null | head -5 || echo "  Unknown"
            echo ""
            echo "Boundary SIEM Profile:"
            aa-status 2>/dev/null | grep boundary-siem || echo "  Not loaded"
            echo ""
            echo "Current Process Profile:"
            cat /proc/self/attr/current 2>/dev/null || echo "  Unknown"
            ;;
        *)
            echo "No MAC system detected."
            echo ""
            echo "To enable kernel-level enforcement, install and configure either:"
            echo "  - SELinux (recommended for RHEL/CentOS/Fedora)"
            echo "  - AppArmor (recommended for Ubuntu/Debian/SUSE)"
            ;;
    esac
    echo ""
}

# Main
main() {
    local cmd="${1:-}"

    case $cmd in
        install)
            check_root
            local mac_system
            mac_system=$(detect_mac_system)
            case $mac_system in
                selinux)
                    install_selinux
                    ;;
                apparmor)
                    install_apparmor
                    ;;
                *)
                    log_error "No supported MAC system detected (SELinux or AppArmor required)"
                    exit 1
                    ;;
            esac
            verify_installation
            ;;
        uninstall)
            check_root
            uninstall
            ;;
        verify)
            verify_installation
            ;;
        permissive)
            check_root
            set_permissive
            ;;
        enforcing)
            check_root
            set_enforcing
            ;;
        status)
            show_status
            ;;
        -h|--help|help)
            usage
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"
