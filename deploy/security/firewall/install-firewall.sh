#!/bin/bash
# Boundary SIEM Firewall Installer
# Installs independent firewall rules that persist without daemon management
#
# Usage: sudo ./install-firewall.sh [install|uninstall|status|reload]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Detect firewall backend
detect_backend() {
    if command -v nft &> /dev/null; then
        # Verify nftables is working
        if nft list ruleset &> /dev/null; then
            echo "nftables"
            return
        fi
    fi

    if command -v iptables &> /dev/null; then
        if iptables -L -n &> /dev/null; then
            echo "iptables"
            return
        fi
    fi

    echo "none"
}

# Install nftables rules
install_nftables() {
    log_info "Installing nftables rules..."

    # Create configuration directory
    mkdir -p /etc/nftables.d

    # Copy rules
    cp "${SCRIPT_DIR}/boundary-siem.nft" /etc/nftables.d/
    chmod 644 /etc/nftables.d/boundary-siem.nft

    # Load rules
    nft -f /etc/nftables.d/boundary-siem.nft
    if [[ $? -ne 0 ]]; then
        log_error "Failed to load nftables rules"
        exit 1
    fi

    # Verify
    if nft list table inet boundary_siem &> /dev/null; then
        log_info "nftables rules loaded successfully"
    else
        log_error "Failed to verify nftables rules"
        exit 1
    fi

    # Install systemd service for persistence
    install_systemd_service

    # Configure nftables to include our rules
    configure_nftables_include
}

# Install iptables rules
install_iptables() {
    log_info "Installing iptables rules..."

    # Create configuration directory
    mkdir -p /etc/iptables

    # Copy rules
    cp "${SCRIPT_DIR}/boundary-siem.iptables" /etc/iptables/boundary-siem.rules
    chmod 644 /etc/iptables/boundary-siem.rules

    # Load rules
    iptables-restore < /etc/iptables/boundary-siem.rules
    if [[ $? -ne 0 ]]; then
        log_error "Failed to load iptables rules"
        exit 1
    fi

    # Verify
    if iptables -L SIEM_SERVICES -n &> /dev/null; then
        log_info "iptables rules loaded successfully"
    else
        log_error "Failed to verify iptables rules"
        exit 1
    fi

    # Install systemd service for persistence
    install_systemd_service

    # Save rules for persistence (distro-specific)
    save_iptables_rules
}

# Install systemd service
install_systemd_service() {
    log_info "Installing systemd service..."

    cp "${SCRIPT_DIR}/boundary-siem-firewall.service" /etc/systemd/system/
    chmod 644 /etc/systemd/system/boundary-siem-firewall.service

    systemctl daemon-reload
    systemctl enable boundary-siem-firewall.service

    log_info "Systemd service installed and enabled"
}

# Configure nftables to include our rules
configure_nftables_include() {
    local nft_conf="/etc/nftables.conf"

    if [[ -f "${nft_conf}" ]]; then
        # Check if include already exists
        if ! grep -q "boundary-siem.nft" "${nft_conf}"; then
            echo 'include "/etc/nftables.d/boundary-siem.nft"' >> "${nft_conf}"
            log_info "Added include to ${nft_conf}"
        fi
    fi
}

# Save iptables rules for persistence
save_iptables_rules() {
    # Debian/Ubuntu
    if command -v netfilter-persistent &> /dev/null; then
        netfilter-persistent save
        log_info "Rules saved with netfilter-persistent"
        return
    fi

    # RHEL/CentOS/Fedora
    if command -v iptables-save &> /dev/null; then
        iptables-save > /etc/sysconfig/iptables 2>/dev/null || \
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        log_info "Rules saved"
    fi
}

# Uninstall firewall rules
uninstall() {
    log_info "Uninstalling Boundary SIEM firewall rules..."

    # Stop and disable service
    if systemctl is-active boundary-siem-firewall.service &> /dev/null; then
        systemctl stop boundary-siem-firewall.service
    fi
    if systemctl is-enabled boundary-siem-firewall.service &> /dev/null; then
        systemctl disable boundary-siem-firewall.service
    fi

    local backend
    backend=$(detect_backend)

    case $backend in
        nftables)
            nft delete table inet boundary_siem 2>/dev/null || true
            nft delete table inet boundary_ratelimit 2>/dev/null || true
            rm -f /etc/nftables.d/boundary-siem.nft
            # Remove include from nftables.conf
            if [[ -f /etc/nftables.conf ]]; then
                sed -i '/boundary-siem.nft/d' /etc/nftables.conf
            fi
            ;;
        iptables)
            # Flush and delete custom chains
            iptables -F SIEM_SERVICES 2>/dev/null || true
            iptables -F MGMT_SERVICES 2>/dev/null || true
            iptables -F LOGGING 2>/dev/null || true
            iptables -X SIEM_SERVICES 2>/dev/null || true
            iptables -X MGMT_SERVICES 2>/dev/null || true
            iptables -X LOGGING 2>/dev/null || true
            rm -f /etc/iptables/boundary-siem.rules
            ;;
    esac

    rm -f /etc/systemd/system/boundary-siem-firewall.service
    systemctl daemon-reload

    log_info "Firewall rules uninstalled"
}

# Show status
status() {
    echo "================================"
    echo "Boundary SIEM Firewall Status"
    echo "================================"
    echo ""

    local backend
    backend=$(detect_backend)
    echo "Backend: $backend"
    echo ""

    # Service status
    if systemctl is-active boundary-siem-firewall.service &> /dev/null; then
        echo "Service: active"
    else
        echo "Service: inactive"
    fi

    if systemctl is-enabled boundary-siem-firewall.service &> /dev/null; then
        echo "Enabled: yes"
    else
        echo "Enabled: no"
    fi
    echo ""

    case $backend in
        nftables)
            echo "nftables Tables:"
            nft list tables 2>/dev/null | grep boundary || echo "  (none loaded)"
            echo ""

            if nft list table inet boundary_siem &> /dev/null; then
                echo "Rules loaded: yes"

                # Show blocked IPs
                echo ""
                echo "Blocked IPs (IPv4):"
                nft list set inet boundary_siem blocked_ips 2>/dev/null || echo "  (none)"

                echo ""
                echo "Blocked IPs (IPv6):"
                nft list set inet boundary_siem blocked_ips_v6 2>/dev/null || echo "  (none)"
            else
                echo "Rules loaded: no"
            fi
            ;;
        iptables)
            echo "iptables Chains:"
            if iptables -L SIEM_SERVICES -n &> /dev/null; then
                echo "  SIEM_SERVICES: active"
                iptables -L SIEM_SERVICES -n -v 2>/dev/null | head -5
            else
                echo "  SIEM_SERVICES: not loaded"
            fi

            if iptables -L MGMT_SERVICES -n &> /dev/null; then
                echo "  MGMT_SERVICES: active"
            else
                echo "  MGMT_SERVICES: not loaded"
            fi
            ;;
        *)
            echo "No firewall backend detected"
            ;;
    esac
    echo ""
}

# Reload rules
reload() {
    log_info "Reloading firewall rules..."

    local backend
    backend=$(detect_backend)

    case $backend in
        nftables)
            if [[ -f /etc/nftables.d/boundary-siem.nft ]]; then
                nft -f /etc/nftables.d/boundary-siem.nft
                log_info "nftables rules reloaded"
            else
                log_error "Rules file not found"
                exit 1
            fi
            ;;
        iptables)
            if [[ -f /etc/iptables/boundary-siem.rules ]]; then
                iptables-restore < /etc/iptables/boundary-siem.rules
                log_info "iptables rules reloaded"
            else
                log_error "Rules file not found"
                exit 1
            fi
            ;;
        *)
            log_error "No firewall backend available"
            exit 1
            ;;
    esac
}

# Add IP to blocklist
block_ip() {
    local ip="$1"
    local timeout="${2:-3600}"

    if [[ -z "$ip" ]]; then
        log_error "Usage: $0 block <ip> [timeout_seconds]"
        exit 1
    fi

    local backend
    backend=$(detect_backend)

    case $backend in
        nftables)
            local set_name="blocked_ips"
            if [[ "$ip" == *":"* ]]; then
                set_name="blocked_ips_v6"
            fi
            nft add element inet boundary_siem "$set_name" "{ $ip timeout ${timeout}s }"
            log_info "Blocked $ip for ${timeout} seconds"
            ;;
        iptables)
            local ipt_cmd="iptables"
            if [[ "$ip" == *":"* ]]; then
                ipt_cmd="ip6tables"
            fi
            $ipt_cmd -I INPUT 1 -s "$ip" -j DROP -m comment --comment "boundary-siem-blocked"
            log_info "Blocked $ip"
            ;;
    esac
}

# Remove IP from blocklist
unblock_ip() {
    local ip="$1"

    if [[ -z "$ip" ]]; then
        log_error "Usage: $0 unblock <ip>"
        exit 1
    fi

    local backend
    backend=$(detect_backend)

    case $backend in
        nftables)
            local set_name="blocked_ips"
            if [[ "$ip" == *":"* ]]; then
                set_name="blocked_ips_v6"
            fi
            nft delete element inet boundary_siem "$set_name" "{ $ip }" 2>/dev/null || true
            log_info "Unblocked $ip"
            ;;
        iptables)
            local ipt_cmd="iptables"
            if [[ "$ip" == *":"* ]]; then
                ipt_cmd="ip6tables"
            fi
            while $ipt_cmd -D INPUT -s "$ip" -j DROP 2>/dev/null; do :; done
            log_info "Unblocked $ip"
            ;;
    esac
}

# Main
main() {
    local cmd="${1:-}"
    local arg1="${2:-}"
    local arg2="${3:-}"

    case $cmd in
        install)
            check_root
            local backend
            backend=$(detect_backend)
            case $backend in
                nftables)
                    install_nftables
                    ;;
                iptables)
                    install_iptables
                    ;;
                *)
                    log_error "No firewall backend available"
                    exit 1
                    ;;
            esac
            status
            ;;
        uninstall)
            check_root
            uninstall
            ;;
        status)
            status
            ;;
        reload)
            check_root
            reload
            ;;
        block)
            check_root
            block_ip "$arg1" "$arg2"
            ;;
        unblock)
            check_root
            unblock_ip "$arg1"
            ;;
        -h|--help|help)
            echo "Usage: $0 [command]"
            echo ""
            echo "Commands:"
            echo "  install           Install firewall rules (auto-detects backend)"
            echo "  uninstall         Remove firewall rules"
            echo "  status            Show current status"
            echo "  reload            Reload rules from config files"
            echo "  block <ip> [sec]  Block an IP address (default 1 hour)"
            echo "  unblock <ip>      Unblock an IP address"
            echo ""
            echo "Examples:"
            echo "  sudo $0 install"
            echo "  sudo $0 block 192.168.1.100 7200"
            echo "  sudo $0 unblock 192.168.1.100"
            ;;
        *)
            echo "Usage: $0 [install|uninstall|status|reload|block|unblock]"
            exit 1
            ;;
    esac
}

main "$@"
