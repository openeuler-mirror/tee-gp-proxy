#!/bin/bash
# =============================================================================
# CCOS Environment Main Deployment Script
# =============================================================================
# This is the main entry point for CCOS environment deployment.
# It provides common functions and calls the appropriate deployment script
# based on the DEPLOY_MODE setting.
#
# Usage:
#   ./deploy.sh [options]
#
# If config_file is not specified, it will look for deploy.conf in the same
# directory as this script.
# =============================================================================

set -e
# ======================== 可配置参数 ========================
# Base directory for git clone and building
WORK_DIR=${WORK_DIR:-"/opt/ccos-deploy"}

# Enable this option if VM deployment is needed in the future
VM_SCALABILITY=${VM_SCALABILITY:-"true"}

# Machine model: 920v100, 920v200 (different models may have different build steps)
MACHINE_MODEL=${MACHINE_MODEL:-"920v200"}

# Whether to install huawei's sdf utils rpm package
NEED_SDF_UTILS_RPM=${NEED_SDF_UTILS_RPM:-"true"}



# ======================== 内部变量 ==========================
TEE_GP_PROXY_REPO="https://gitcode.com/openeuler/tee-gp-proxy.git"
LIBBOUNDSCHECK_REPO="https://gitcode.com/openeuler/libboundscheck.git"
ITRUSTEE_TZDRIVER_REPO="https://gitcode.com/openeuler/itrustee_tzdriver.git"
ITRUSTEE_CLIENT_REPO="https://gitcode.com/openeuler/itrustee_client.git"

TEE_GP_PROXY_DIR="${WORK_DIR}/tee-gp-proxy"
LIBBOUNDSCHECK_DIR="${WORK_DIR}/libboundscheck"
ITRUSTEE_TZDRIVER_DIR="${WORK_DIR}/itrustee_tzdriver"
ITRUSTEE_CLIENT_DIR="${WORK_DIR}/itrustee_client"
TRUSTZONE_INSTALL_DIR="/lib/modules/$(uname -r)/kernel/drivers/trustzone"
VTZ_PROXY_DIR="${WORK_DIR}/tee-gp-proxy/trustzone-awared-vm/Host/vtzb_proxy"
VTZDRIVER_DIR="${TEE_GP_PROXY_DIR}/trustzone-awared-vm/VM/vtzdriver"
VIRTIO_CONSOLE_DIR="${TEE_GP_PROXY_DIR}/trustzone-awared-vm/VM/virtio/char"
KUNPENG_SEC_DRV_DIR="/var/itrustee/tee_dynamic_drv/crypto"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KUNPENG_SEC_DRV_FILE_NAME="kunpeng_sec_drv.sec"
KUNPENG_SEC_DRV_FILE=${SCRIPT_DIR}/${KUNPENG_SEC_DRV_FILE_NAME}
SDF_UTILS_RPM=${SDF_UTILS_RPM:-"sdf-utils*.rpm"}
DEPLOYMENT_SUCCESS="false"
RPM_PKG_INSTALLED="false"
CONFIG_FILE="${SCRIPT_DIR}/deploy.conf"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# -----------------------------------------------------------------------------
# Logging Functions
# -----------------------------------------------------------------------------
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# -----------------------------------------------------------------------------
# Configuration Functions
# -----------------------------------------------------------------------------
update_env_variable() {
    TEE_GP_PROXY_DIR="${WORK_DIR}/tee-gp-proxy"
    LIBBOUNDSCHECK_DIR="${WORK_DIR}/libboundscheck"
    ITRUSTEE_TZDRIVER_DIR="${WORK_DIR}/itrustee_tzdriver"
    ITRUSTEE_CLIENT_DIR="${WORK_DIR}/itrustee_client"
    VTZ_PROXY_DIR="${WORK_DIR}/tee-gp-proxy/trustzone-awared-vm/Host/vtzb_proxy"
    VTZDRIVER_DIR="${TEE_GP_PROXY_DIR}/trustzone-awared-vm/VM/vtzdriver"
    VIRTIO_CONSOLE_DIR="${TEE_GP_PROXY_DIR}/trustzone-awared-vm/VM/virtio/char"
}

print_config() {
    echo ""
    echo "============================================================================="
    echo "             CCOS Environment Deployment Configuration                       "
    echo "============================================================================="
    echo ""
    echo "Deployment Mode:"
    echo "  DEPLOY_MODE           : ${DEPLOY_MODE}"
    echo ""
    echo "System Configuration:"
    echo "  MACHINE_MODEL         : ${MACHINE_MODEL}"
    echo "  OS_TYPE               : ${OS_TYPE}"
    echo "  KERNEL_VERSION        : $(uname -r)"
    echo ""
    echo "Paths Configuration:"
    echo "  WORK_DIR              : ${WORK_DIR}"
    echo ""
    echo "Required Files:"
    if [ $DEPLOY_MODE = "host" ]; then
        echo "  KUNPENG_SEC_DRV_FILE  : ${KUNPENG_SEC_DRV_FILE}"
    fi
    echo "  NEED_SDF_UTILS_RPM    : ${NEED_SDF_UTILS_RPM}"
    if [ $NEED_SDF_UTILS_RPM = "true" ]; then
        echo "  SDF_UTILS_RPM         : ${SDF_UTILS_RPM}"
    fi
    echo ""
    echo "============================================================================="
    echo ""
}

confirm_config() {
    print_config

    echo -n "Please confirm the above configuration is correct. Continue? [y/N]: "
    read -r response

    case "$response" in
        [yY][eE][sS]|[yY])
            log_info "Configuration confirmed. Proceeding with deployment..."
            return 0
            ;;
        *)
            log_warn "Deployment cancelled by user."
            log_info "Please modify the configuration file and run the script again."
            exit 0
            ;;
    esac
}

# Detect if running in a virtual machine
# Returns 0 if in VM, 1 if on host
is_virtual_machine() {
    # Method 1: Use systemd-detect-virt (most reliable)
    if command -v systemd-detect-virt &> /dev/null; then
        local virt_type
        virt_type=$(systemd-detect-virt 2>/dev/null)
        if [ "$virt_type" != "none" ] && [ -n "$virt_type" ]; then
            return 0  # In VM
        fi
        return 1  # On host
    fi

    # Method 2: Check /proc/cpuinfo for hypervisor flag
    if grep -q "^flags.*hypervisor" /proc/cpuinfo 2>/dev/null; then
        return 0  # In VM
    fi

    # Method 3: Check DMI product name for common VM indicators
    if [ -f /sys/class/dmi/id/product_name ]; then
        local product_name
        product_name=$(cat /sys/class/dmi/id/product_name 2>/dev/null)
        case "$product_name" in
            *"Virtual"*|*"VMware"*|*"KVM"*|*"QEMU"*|*"Xen"*|*"HVM"*|*"Bochs"*)
                return 0  # In VM
                ;;
        esac
    fi

    return 1  # Assume host if no VM indicators found
}

check_params() {
    log_info "Checking params..."
    if [[ ! -d "${WORK_DIR}" ]]; then
        log_warn "Work directory does not exist, make directory first"
        mkdir -p "${WORK_DIR}" && cd "${WORK_DIR}"
        log_info "Enter into ${WORK_DIR}"
    fi

    if [[ "${VM_SCALABILITY}" != "true" ]] && [[ "${VM_SCALABILITY}" != "false" ]]; then
        log_error "Invalid param: VM_SCALABILITY"
        return 1
    fi

    if [[ "${MACHINE_MODEL}" != "920v100" ]] && [[ "${MACHINE_MODEL}" != "920v200" ]]; then
        log_error "Invalid param: MACHINE_MODEL"
        return 1
    fi

    if [[ "${NEED_SDF_UTILS_RPM}" != "true" ]] && [[ "${NEED_SDF_UTILS_RPM}" != "false" ]]; then
        log_error "Invalid param: NEED_SDF_UTILS_RPM"
        return 1
    fi

    log_info "Checking params finished"
    return 0
}

load_config() {
    local config_file="$1"

    if [[ ! -f "$config_file" ]]; then
        log_error "Configuration file not found: $config_file"
        exit 1
    fi

    # shellcheck source=/dev/null
    source "$config_file"
    log_info "Configuration loaded from: $config_file"
}
# =============================================================================
# Main Entry Point
# =============================================================================

main() {
    load_config "${CONFIG_FILE}"

    if check_params; then
        log_info "Valid params"
    else
        log_error "Invalid params"
        exit 1
    fi

    OS_TYPE=$(grep '^NAME=' /etc/os-release | cut -d'=' -f2 | tr -d '"')
    if [ ${NEED_SDF_UTILS_RPM} == "true" ]; then
        SDF_UTILS_RPM=$(ls ${SCRIPT_DIR}/${SDF_UTILS_RPM})
    fi

    if is_virtual_machine; then
        DEPLOY_MODE="vm"
    else
        DEPLOY_MODE="host"
    fi


    # Print configuration and confirm with user
    confirm_config
    WORK_DIR="${WORK_DIR}/tmp"
    if [[ ! -d "${WORK_DIR}" ]]; then
        mkdir -p "${WORK_DIR}"
    fi
    update_env_variable
    
    if is_virtual_machine; then
        log_info "Deployment mode: VM"
        log_info "Calling deploy_vm.sh..."
        echo ""
        source "${SCRIPT_DIR}/deploy_vm.sh"
    else
        log_info "Deployment mode: Host"
        log_info "Calling deploy_host.sh..."
        echo ""
        source "${SCRIPT_DIR}/deploy_host.sh"
    fi
}

show_help() {
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -h, --help                  显示帮助信息"
    echo "  -w, --work_dir              部署路径"
    echo "                              默认: /opt/ccos-deploy/"
    echo "  -v, --vm_scalability         虚机扩展，若后续有虚机场景，则设置为 true；仅涉及 host 场景，则可设置为 false"
    echo "                              默认: true"
    echo "  -m, --machine_model         服务器型号：920v100,920v200"
    echo "                              默认: 920v200"
    echo "  -n, --need_sdf_utils_rpm    是否需要部署鲲鹏密码模块，可配置 true 或 false"
    echo "                              默认: true"
    echo ""
    echo "示例:"
    echo "  $0                          # 按照默认配置部署"
    echo "  $0 -w /opt/ccos-deploy      # 在 /opt/ccos-deploy 目录下进行安装和构建"
    echo "  $0 -m 920v200               # 为920v200服务器安装部署"
    echo "  $0 -m 920v200 -v false      # 为920v200服务器安装部署，且不涉及虚机场景"
    echo "  $0 -n false                 # 不需要部署鲲鹏密码模块"
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -w|--work_dir)
            WORK_DIR="$2"
            shift 2
            ;;
        -v|--vm_scalability)
            VM_SCALABILITY="$2"
            shift 2
            ;;
        -m|--machine_model)
            MACHINE_MODEL="$2"
            shift 2
            ;;
        -n|--need_sdf_utils_rpm)
            NEED_SDF_UTILS_RPM="$2"
            shift 2
            ;;
        *)
            log_error "未知参数: $1"
            show_help
            exit 1
            ;;
    esac
done

main
