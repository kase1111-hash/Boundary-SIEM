#!/bin/bash
# Boundary-SIEM Container Isolation Setup Script
#
# This script sets up container isolation with network restrictions.
# Run as root on the host system.
#
# Usage:
#   ./setup-container-isolation.sh [docker|kubernetes|both]
#
# Requirements:
#   - Docker 20.10+ or Kubernetes 1.25+
#   - AppArmor or SELinux enabled
#   - Root privileges

set -euo pipefail

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

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# =============================================================================
# Docker Setup
# =============================================================================

setup_docker() {
    log_info "Setting up Docker container isolation..."

    # Check Docker is installed
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi

    # 1. Load AppArmor profile
    if command -v apparmor_parser &> /dev/null; then
        log_info "Loading AppArmor profile for boundary-siem..."
        if [[ -f "${SCRIPT_DIR}/apparmor-profile" ]]; then
            apparmor_parser -r -W "${SCRIPT_DIR}/apparmor-profile" || {
                log_warn "Failed to load AppArmor profile, container will use default"
            }
        fi
    else
        log_warn "AppArmor not available, skipping profile installation"
    fi

    # 2. Create Docker networks
    log_info "Creating isolated Docker networks..."

    # Internal network (no external access)
    docker network create \
        --driver bridge \
        --internal \
        --subnet 172.28.0.0/24 \
        --gateway 172.28.0.1 \
        siem-internal 2>/dev/null || log_info "Network siem-internal already exists"

    # Ingestion network
    docker network create \
        --driver bridge \
        --subnet 172.28.1.0/24 \
        --gateway 172.28.1.1 \
        --opt "com.docker.network.bridge.enable_ip_masquerade=false" \
        siem-ingestion 2>/dev/null || log_info "Network siem-ingestion already exists"

    # Management network
    docker network create \
        --driver bridge \
        --subnet 172.28.2.0/24 \
        --gateway 172.28.2.1 \
        siem-management 2>/dev/null || log_info "Network siem-management already exists"

    # 3. Create volumes
    log_info "Creating Docker volumes..."
    docker volume create siem-data 2>/dev/null || true
    docker volume create siem-logs 2>/dev/null || true
    docker volume create siem-config 2>/dev/null || true

    # 4. Set up iptables rules for network isolation
    log_info "Configuring iptables for network isolation..."
    setup_iptables_rules

    # 5. Configure Docker daemon (if needed)
    configure_docker_daemon

    log_info "Docker container isolation setup complete"
}

setup_iptables_rules() {
    # Create custom chain for SIEM traffic
    iptables -N SIEM-ISOLATION 2>/dev/null || iptables -F SIEM-ISOLATION

    # Block direct internet access from internal network
    iptables -A SIEM-ISOLATION -s 172.28.0.0/24 -d 0.0.0.0/0 -j DROP
    iptables -A SIEM-ISOLATION -s 172.28.0.0/24 -d 172.28.0.0/24 -j ACCEPT

    # Allow ingestion network to receive from anywhere, but not initiate
    iptables -A SIEM-ISOLATION -d 172.28.1.0/24 -p tcp --dport 5514 -j ACCEPT
    iptables -A SIEM-ISOLATION -d 172.28.1.0/24 -p udp --dport 5514 -j ACCEPT
    iptables -A SIEM-ISOLATION -d 172.28.1.0/24 -p udp --dport 5515 -j ACCEPT

    # Allow management network access only from specific IPs
    # (Configure MANAGEMENT_CIDR for your environment)
    MANAGEMENT_CIDR="${MANAGEMENT_CIDR:-10.0.0.0/8}"
    iptables -A SIEM-ISOLATION -s "${MANAGEMENT_CIDR}" -d 172.28.2.0/24 -p tcp --dport 8443 -j ACCEPT
    iptables -A SIEM-ISOLATION -d 172.28.2.0/24 -j DROP

    # Insert chain into FORWARD
    iptables -C FORWARD -j SIEM-ISOLATION 2>/dev/null || \
        iptables -I FORWARD 1 -j SIEM-ISOLATION

    # Save rules
    if command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi
}

configure_docker_daemon() {
    DAEMON_JSON="/etc/docker/daemon.json"

    # Create daemon.json if it doesn't exist
    if [[ ! -f "${DAEMON_JSON}" ]]; then
        cat > "${DAEMON_JSON}" << 'EOF'
{
    "icc": false,
    "live-restore": true,
    "userland-proxy": false,
    "no-new-privileges": true,
    "seccomp-profile": "/etc/docker/seccomp/default.json",
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "100m",
        "max-file": "5"
    },
    "storage-driver": "overlay2"
}
EOF
        log_info "Created Docker daemon configuration"
        log_warn "Docker daemon restart required: systemctl restart docker"
    else
        log_info "Docker daemon.json exists, please verify security settings manually"
    fi

    # Copy seccomp profile
    mkdir -p /etc/docker/seccomp
    if [[ -f "${SCRIPT_DIR}/seccomp-profile.json" ]]; then
        cp "${SCRIPT_DIR}/seccomp-profile.json" /etc/docker/seccomp/boundary-siem.json
        log_info "Installed seccomp profile to /etc/docker/seccomp/"
    fi
}

# =============================================================================
# Kubernetes Setup
# =============================================================================

setup_kubernetes() {
    log_info "Setting up Kubernetes container isolation..."

    # Check kubectl is installed
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed"
        exit 1
    fi

    # Check cluster connection
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi

    # 1. Create namespace with security labels
    log_info "Creating namespace with Pod Security Standards..."
    kubectl apply -f "${SCRIPT_DIR}/pod-security-policy.yaml"

    # 2. Apply network policies
    log_info "Applying network policies..."
    kubectl apply -f "${SCRIPT_DIR}/network-policy.yaml"

    # 3. Install Gatekeeper constraints (if Gatekeeper is installed)
    if kubectl get crd constrainttemplates.templates.gatekeeper.sh &> /dev/null; then
        log_info "Gatekeeper detected, applying constraints..."
        kubectl apply -f "${SCRIPT_DIR}/pod-security-policy.yaml"
    else
        log_warn "Gatekeeper not installed, skipping OPA constraints"
    fi

    # 4. Create secrets for TLS (placeholder)
    log_info "Creating TLS secrets..."
    create_tls_secrets

    # 5. Apply RBAC
    log_info "Applying RBAC policies..."
    apply_rbac

    log_info "Kubernetes container isolation setup complete"
}

create_tls_secrets() {
    # Check if secrets already exist
    if kubectl get secret siem-tls -n boundary-siem &> /dev/null; then
        log_info "TLS secret already exists"
        return
    fi

    # Generate self-signed certificate (for development)
    CERT_DIR=$(mktemp -d)
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "${CERT_DIR}/tls.key" \
        -out "${CERT_DIR}/tls.crt" \
        -subj "/CN=boundary-siem/O=Boundary Security" \
        2>/dev/null

    kubectl create secret tls siem-tls \
        --cert="${CERT_DIR}/tls.crt" \
        --key="${CERT_DIR}/tls.key" \
        -n boundary-siem

    rm -rf "${CERT_DIR}"
    log_warn "Created self-signed TLS certificate - replace with proper cert in production"
}

apply_rbac() {
    kubectl apply -f - << 'EOF'
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: boundary-siem
  namespace: boundary-siem
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: boundary-siem-role
  namespace: boundary-siem
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["siem-tls", "siem-config"]
    verbs: ["get"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: boundary-siem-binding
  namespace: boundary-siem
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: boundary-siem-role
subjects:
  - kind: ServiceAccount
    name: boundary-siem
    namespace: boundary-siem
EOF
}

# =============================================================================
# Verification
# =============================================================================

verify_setup() {
    log_info "Verifying container isolation setup..."

    local errors=0

    # Check Docker networks
    if command -v docker &> /dev/null; then
        for net in siem-internal siem-ingestion siem-management; do
            if docker network inspect "$net" &> /dev/null; then
                log_info "✓ Docker network '$net' exists"
            else
                log_error "✗ Docker network '$net' missing"
                ((errors++))
            fi
        done
    fi

    # Check AppArmor profile
    if command -v aa-status &> /dev/null; then
        if aa-status 2>/dev/null | grep -q "boundary-siem"; then
            log_info "✓ AppArmor profile 'boundary-siem' loaded"
        else
            log_warn "○ AppArmor profile 'boundary-siem' not loaded"
        fi
    fi

    # Check Kubernetes namespace
    if command -v kubectl &> /dev/null; then
        if kubectl get namespace boundary-siem &> /dev/null; then
            log_info "✓ Kubernetes namespace 'boundary-siem' exists"

            # Check PSA labels
            labels=$(kubectl get namespace boundary-siem -o jsonpath='{.metadata.labels}')
            if echo "$labels" | grep -q "pod-security.kubernetes.io/enforce"; then
                log_info "✓ Pod Security Admission labels configured"
            else
                log_warn "○ Pod Security Admission labels not configured"
            fi
        else
            log_info "○ Kubernetes namespace not created (run with 'kubernetes' option)"
        fi
    fi

    # Check iptables rules
    if iptables -L SIEM-ISOLATION &> /dev/null; then
        log_info "✓ iptables SIEM-ISOLATION chain exists"
    else
        log_warn "○ iptables SIEM-ISOLATION chain not configured"
    fi

    if [[ $errors -gt 0 ]]; then
        log_error "Verification completed with $errors errors"
        return 1
    else
        log_info "Verification completed successfully"
        return 0
    fi
}

# =============================================================================
# Main
# =============================================================================

usage() {
    echo "Usage: $0 [docker|kubernetes|both|verify]"
    echo ""
    echo "Options:"
    echo "  docker      - Set up Docker container isolation"
    echo "  kubernetes  - Set up Kubernetes container isolation"
    echo "  both        - Set up both Docker and Kubernetes"
    echo "  verify      - Verify the current setup"
    echo ""
    exit 1
}

main() {
    check_root

    local mode="${1:-both}"

    case "$mode" in
        docker)
            setup_docker
            ;;
        kubernetes)
            setup_kubernetes
            ;;
        both)
            setup_docker
            setup_kubernetes
            ;;
        verify)
            verify_setup
            ;;
        *)
            usage
            ;;
    esac

    if [[ "$mode" != "verify" ]]; then
        echo ""
        verify_setup
    fi
}

main "$@"
