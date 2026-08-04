set -e

cd ${WORK_DIR}

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
# Pre-deployment Check
# -----------------------------------------------------------------------------
pre_deployment_check() {
    # Check 1: sdf-utils RPM package must exist
    if [ ${NEED_SDF_UTILS_RPM} == "true" ]; then
        log_info "Checking sdf-utils RPM package..."
        if [[ ! -f "${SDF_UTILS_RPM}" ]]; then
            log_error "sdf-utils RPM package not found: ${SDF_UTILS_RPM}"
            log_info "Please ensure the sdf-utils RPM package is available in the specified path."
            exit 1
        fi
        log_info "Found sdf-utils RPM package: ${SDF_UTILS_RPM}"
    fi

    # Check 2: kunpeng_sec_drv.sec file must exist
    log_info "Checking kunpeng_sec_drv.sec file..."
    if [[ ! -f "${KUNPENG_SEC_DRV_FILE}" ]]; then
        log_error "kunpeng_sec_drv.sec file not found: ${KUNPENG_SEC_DRV_FILE}"
        log_info "Please ensure the kunpeng_sec_drv.sec file is available in the specified path."
        exit 1
    fi
    log_info "Found kunpeng_sec_drv.sec file: ${KUNPENG_SEC_DRV_FILE}"

    # Check 3: tzdriver.ko must not be loaded (this check must be last)
    log_info "Checking tzdriver.ko module..."
    if lsmod | grep -q "^tzdriver"; then
        log_error "tzdriver.ko module is already loaded!"
        log_error "Please reboot the machine and run this script again."
        log_info "After reboot, run: $0"
        exit 1
    fi
    log_info "tzdriver.ko module is not loaded"
    return 0
}
# -----------------------------------------------------------------------------
# Step 1: Install dependencies
# -----------------------------------------------------------------------------
install_dependencies() {
    log_step "[Step 1] Installing dependencies..."

    yum install -y gcc patch make git openssl-devel zlib-devel kernel-devel-"$(uname -r)" rpm-build || {
        log_error "Failed to install dependencies"
        return 1
    }

    if [[ "$VM_SCALABILITY" = "true" ]]; then
        log_info "Installing vm scalibility dependencies..."
        yum install -y ninja-build glib2 glib2-devel pixman-devel libxml2-devel libvirt-devel || {
            log_error "Failed to install vm scalability dependencies"
            return 1
        }

        local kernel_version
        kernel_version=$(uname -r | cut -d'-' -f1)
        local kernel_major kernel_minor
        kernel_major=$(echo "${kernel_version}" | cut -d'.' -f1)
        kernel_minor=$(echo "${kernel_version}" | cut -d'.' -f2)
        if [[ "${kernel_major}" -gt 6 ]] || { [[ "${kernel_major}" -eq 6 ]] && [[ "${kernel_minor}" -ge 6 ]]; }; then
            log_info "Kernel version ${kernel_version} >= 6.6, installing compat-openssl11-libs..."
            yum install -y compat-openssl11-libs || {
                log_error "Failed to install compat-openssl11-libs"
                return 1
            }
        fi
    fi

    log_info "Dependencies installed successfully"
}

# -----------------------------------------------------------------------------
# Step 3: Clone tee-gp-proxy repository
# -----------------------------------------------------------------------------
clone_tee_gp_proxy() {
    log_step "[Step 3] Cloning tee-gp-proxy..."

    if [[ -d "${TEE_GP_PROXY_DIR}" ]]; then
        if [[ "${LENIENT_MODE}" == "true" ]]; then
            log_info "tee-gp-proxy directory already exists, lenient mode enabled, skipping clone"
            return 0
        else
            log_warn "tee-gp-proxy directory already exists, delete it before clone"
            rm -rf ${TEE_GP_PROXY_DIR} || {
                log_error "Failed to delete tee-gp-proxy directory"
                return 1
            }
            log_info "Delete tee-gp-proxy directory successfully"
        fi
    fi

    git clone --branch ${TEE_GP_PROXY_BRANCH} ${TEE_GP_PROXY_REPO} || {
        log_error "Failed to clone tee-gp-proxy"
        return 1
    }

    log_info "tee-gp-proxy cloned successfully"
    return 0
}

# -----------------------------------------------------------------------------
# Step 9: build and install_vtz_proxy
# -----------------------------------------------------------------------------
build_and_install_vtz_proxy() {
    log_step "[Step 9] Building vtz-proxy..."

    # Build vtz_proxy
    log_info "Building vtz_proxy..."
    pushd "${VTZ_PROXY_RPM_DIR}/" > /dev/null || return 1

    sh build_rpm.sh || {
        log_error "Failed to build vtz_proxy"
        popd > /dev/null
        return 1
    }

    log_info "Installing vtz_proxy..."
    rpm -e vtz_proxy 2>/dev/null || true
    rpm -ivh output/*.rpm || {
        log_error "Failed to install vtz_proxy"
        popd > /dev/null
        return 1
    }

    popd > /dev/null
    log_info "vtz-proxy built and installed successfully"
    return 0
}

# -----------------------------------------------------------------------------
# Step 4: build and copy_vsock
# -----------------------------------------------------------------------------
build_and_copy_vsock() {
    log_step "[Step 4] Building and copying vhost_vsock..."

    local vsock_dir="${TEE_GP_PROXY_DIR}/trustzone-awared-vm/Host/"

    pushd "${vsock_dir}" > /dev/null || return 1

    sh build_vsock.sh || {
        log_error "Failed to build vhost_vsock"
        popd > /dev/null
        return 1
    }

    popd > /dev/null
    log_info "vhost_vsock built and replace successfully"
    return 0
}

# -----------------------------------------------------------------------------
# Step 5: Clone itrustee_tzdriver repository
# -----------------------------------------------------------------------------
clone_itrustee_tzdriver() {
    log_step "[Step 5] Cloning itrustee_tzdriver repository..."

    if [[ -d "${ITRUSTEE_TZDRIVER_DIR}" ]]; then
        if [[ "${LENIENT_MODE}" == "true" ]]; then
            log_info "itrustee_tzdriver directory already exists, lenient mode enabled, skipping clone"
            if [[ "$VM_SCALABILITY" = "true" ]]; then
                log_info "VM_SCALABILITY is enabled"
                pushd "${ITRUSTEE_TZDRIVER_DIR}" > /dev/null || return 1

                log_info "Applying tzdriver-00*.patch..."
                for patch in ${TEE_GP_PROXY_DIR}/trustzone-awared-vm/Host/tzdriver-00*.patch; do
                    log_info "Patching: $patch"
                    git am "$patch" || {
                        log_error "Patch failed: $patch"
                        popd > /dev/null
                        return 1
                    }
                done

                popd > /dev/null
                log_info "tzdriver patches applied successfully"
            fi
            return 0
        else
            log_warn "itrustee_tzdriver directory already exists, delete it before clone"
            rm -rf ${ITRUSTEE_TZDRIVER_DIR} || {
                log_error "Failed to delete itrustee_tzdriver directory"
                return 1
            }
            log_info "Delete itrustee_tzdriver directory successfully"
        fi
    fi

    git clone "${ITRUSTEE_TZDRIVER_REPO}" -b "${ITRUSTEE_TZDRIVER_BRANCH}" || {
        log_error "Failed to clone itrustee_tzdriver"
        return 1
    }

    if [[ "$VM_SCALABILITY" = "true" ]]; then
        pushd "${ITRUSTEE_TZDRIVER_DIR}" > /dev/null || return 1

        log_info "Applying tzdriver-00*.patch..."
        for patch in ${TEE_GP_PROXY_DIR}/trustzone-awared-vm/Host/tzdriver-00*.patch; do
            log_info "Patching: $patch"
            git am "$patch" || {
                log_error "Patch failed: $patch"
                popd > /dev/null
                return 1
            }
        done

        popd > /dev/null
        log_info "tzdriver patches applied successfully"
    fi

    log_info "itrustee_tzdriver cloned successfully"
}

# -----------------------------------------------------------------------------
# Step 7: Clone itrustee_client repository
# -----------------------------------------------------------------------------
clone_itrustee_client() {
    log_step "[Step 7] Cloning itrustee_client repository..."

    if [[ -d "${ITRUSTEE_CLIENT_DIR}" ]]; then
        if [[ "${LENIENT_MODE}" == "true" ]]; then
            log_info "itrustee_client directory already exists, lenient mode enabled, skipping clone"
            if [[ "$VM_SCALABILITY" = "true" ]]; then
                log_info "VM_SCALABILITY is enabled"
                pushd "${ITRUSTEE_CLIENT_DIR}" > /dev/null || return 1

                log_info "Applying client-000*.patch..."
                git am ${TEE_GP_PROXY_DIR}/trustzone-awared-vm/Host/client-000*.patch || {
                    log_error "Failed to apply client-000*.patch"
                    popd > /dev/null
                    return 1
                }

                popd > /dev/null
                log_info "client patches applied successfully"
            fi
            return 0
        else
            log_warn "itrustee_client directory already exists, delete it before clone"
            rm -rf ${ITRUSTEE_CLIENT_DIR} || {
                log_error "Failed to delete itrustee_client directory"
                return 1
            }
            log_info "Delete itrustee_client directory successfully"
        fi
    fi

    git clone "${ITRUSTEE_CLIENT_REPO}" -b "${ITRUSTEE_CLIENT_BRANCH}" || {
        log_error "Failed to clone itrustee_client"
        return 1
    }

    if [[ "$VM_SCALABILITY" = "true" ]]; then
        pushd "${ITRUSTEE_CLIENT_DIR}" > /dev/null || return 1

        log_info "Applying client-00*.patch..."
        for patch in ${TEE_GP_PROXY_DIR}/trustzone-awared-vm/Host/client-00*.patch; do
            log_info "Patching: $patch"
            git am "$patch" || {
                log_error "Patch failed: $patch"
                popd > /dev/null
                return 1
            }
        done

        popd > /dev/null
        log_info "tzdriver patches applied successfully"
    fi

    log_info "itrustee_client cloned successfully"
}

# -----------------------------------------------------------------------------
# Step 6: Build itrustee_tzdriver
# -----------------------------------------------------------------------------
build_and_install_tzdriver() {
    log_step "[Step 6] Building itrustee_tzdriver..."

    pushd "${ITRUSTEE_TZDRIVER_DIR}" > /dev/null || return 1

    # For Kylin V10 SP3 or UOS v20 Server, remove -fstack-protector-strong from Makefile
    if [[ "$OS_TYPE" == "Kylin" ]] || [[ "$OS_TYPE" == "UOS" ]]; then
        log_info "Detected ${OS_TYPE} OS, removing -fstack-protector-strong from Makefile..."
        sed -i 's/-fstack-protector-strong//g' Makefile
    fi

    pushd "rpm" > /dev/null || return 1
    rpm -e tzdriver 2>/dev/null || true
    sh build_rpm.sh || {
        log_error "Failed to build tzdriver"
        popd > /dev/null
        popd > /dev/null
        return 1
    }

    
    rpm -ivh output/*.rpm || {
        log_error "Failed to build tzdriver"
        popd > /dev/null
        popd > /dev/null
        return 1
    }

    popd > /dev/null
    popd > /dev/null
    log_info "tzdriver built successfully"
}

# -----------------------------------------------------------------------------
# Step 8: Build and install itrustee_client
# -----------------------------------------------------------------------------
build_itrustee_client() {
    log_step "[Step 8] Building and installing itrustee_client..."

    pushd "${ITRUSTEE_CLIENT_DIR}/rpm" > /dev/null || return 1

    sh build_rpm.sh || {
        log_error "Failed to build itrustee_client"
        popd > /dev/null
        return 1
    }

    rpm -e tee_client 2>/dev/null || true
    rpm -ivh output/*.rpm || {
        log_error "Failed to install itrustee_client"
        popd > /dev/null
        return 1
    }

    popd > /dev/null
    log_info "itrustee_client built and installed successfully"
}

# -----------------------------------------------------------------------------
# Step 2: Deploy security driver
# -----------------------------------------------------------------------------
deploy_security_driver() {
    log_step "[Step 2] Deploying security driver..."

    if [[ ! -d "${KUNPENG_SEC_DRV_DIR}" ]]; then
        log_info "tee_dynamic_drv directory does not exist, make directory first"
        mkdir -p "${KUNPENG_SEC_DRV_DIR}" || {
            log_error "Failed to create directory ${KUNPENG_SEC_DRV_DIR}"
            return 1
        }
    fi

    cp "${KUNPENG_SEC_DRV_FILE}" "${KUNPENG_SEC_DRV_DIR}/" || {
        log_error "Failed to copy kunpeng_sec_drv.sec"
        return 1
    }

    log_info "kunpeng_sec_drv.sec deployed successfully"
    return 0
}

# -----------------------------------------------------------------------------
# Step 10: Install sdf utils*.rpm
# -----------------------------------------------------------------------------
install_sdf_utils_rpm() {
    log_info "Checking sdf-utils RPM packages..."
    matching_packages=$(rpm -qa | grep '^sdf-utils')
    if [[ -n "$matching_packages" ]]; then
        log_info "All sdf-utils related rpm packages are as follows"
        log_info "$matching_packages"
        log_info "Uninstalling..."

        while IFS= read -r package; do
            log_info "Uninstalling: $package"
            rpm -e "$package" || {
                log_error "Uninstalled failed: $package"
                return 1
            }
            log_info "Uninstalled successfully: $package"
        done <<< "$matching_packages"

        log_info "All sdf-utils related rpm packages are uninstalled"
    else
        log_info "No sdf-utils related rpm packages"
    fi
    log_info "Installing sdf-utils RPM package..."

    rpm -ivh ${SDF_UTILS_RPM} || {
        log_error "Failed to install sdf-utils RPM"
        return 1
    }

    log_info "sdf-utils installed successfully"
    RPM_PKG_INSTALLED="true"
    return 0
}


cleanup() {
    log_info "Cleaning resources..."
    cd ${SCRIPT_DIR}

    if [ -d "$WORK_DIR" ]; then
        log_info "Remove directory: ${WORK_DIR}"
        rm -rf "$WORK_DIR" && log_info "Remove work directory successfully" || log_error "Fail to remove work directory"
    fi

    if [[ "${DEPLOYMENT_SUCCESS}" == "false" ]] &&
        command -v rpm &> /dev/null &&
        [[ "${RPM_PKG_INSTALLED}" == "true" ]]; then
        local packages=$(rpm -qa "sdf-utils*" 2>/dev/null)
        if [ -n "$packages" ]; then
            log_info "Uninstalling sdf-utils*.rpm packages ..."
            rpm -e ${packages} 2>/dev/null && \
            log_info "sdf-utils*.rpm packages uninstalled successfully" \
            || log_error "Fail to uninstall sdf-utils*.rpm packages"
        fi
    fi
    log_info "Complete cleaning"
    if [[ "${DEPLOYMENT_SUCCESS}" == "false" ]]; then
        log_error "========== Host deployment failed =========="
    fi
}

trap cleanup EXIT

# -----------------------------------------------------------------------------
# Main Deployment Function
# -----------------------------------------------------------------------------
deploy_host() {
    log_info "========== Starting Host Environment Deployment =========="

    # Execute all steps
    pre_deployment_check || { log_error "Step 0 failed"; return 1; }
    install_dependencies || { log_error "Step 1 failed"; return 1; }
    deploy_security_driver || { log_error "Step 2 failed"; return 1; }
    clone_tee_gp_proxy || { log_error "Step 3 failed"; return 1; }
    if [[ "$VM_SCALABILITY" = "true" ]]; then
        build_and_copy_vsock || { log_error "Step 4 failed"; return 1; }
    fi

    clone_itrustee_tzdriver || { log_error "Step 5 failed"; return 1; }
    build_and_install_tzdriver || { log_error "Step 6 failed"; return 1; }
    clone_itrustee_client || { log_error "Step 7 failed"; return 1; }
    build_itrustee_client || { log_error "Step 8 failed"; return 1; }
    if [[ "$VM_SCALABILITY" = "true" ]]; then
        build_and_install_vtz_proxy || { log_error "Step 9 failed"; return 1; }
    fi
    if [[ "$NEED_SDF_UTILS_RPM" = "true" ]]; then
        install_sdf_utils_rpm || { log_error "Step 10 failed"; return 1; }
    fi
    log_info "========== Host Environment Deployment Completed =========="
}

# -----------------------------------------------------------------------------
# Script Entry Point
# -----------------------------------------------------------------------------
main() {
    # Start deployment
    deploy_host
    DEPLOYMENT_SUCCESS="true"
    echo ""
    log_info "Host deployment completed successfully!"
}
main
