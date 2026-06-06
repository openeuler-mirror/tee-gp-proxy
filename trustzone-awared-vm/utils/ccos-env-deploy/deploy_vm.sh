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


pre_deployment_check() {
    log_info "Performing pre-deployment ..."

    # Check 1: teecd process - if running, kill it
    log_info "Checking teecd process..."
    if pgrep -x "teecd" > /dev/null; then
        log_warn "teecd process is running, stopping it..."
        pkill -x "teecd" || true
        sleep 1
        if pgrep -x "teecd" > /dev/null; then
            log_error "Failed to stop teecd process"
            return 1
        fi
        log_info "teecd process stopped successfully"
    else
        log_info "teecd process is not running"
    fi

    # Check 2: sdf-utils RPM package must exist
    if [ ${NEED_SDF_UTILS_RPM} == "true" ]; then
        log_info "Checking sdf-utils RPM package..."
        if [[ ! -f "${SDF_UTILS_RPM}" ]]; then
            log_error "sdf-utils RPM package not found: ${SDF_UTILS_RPM}"
            log_info "Please ensure the sdf-utils RPM package is available in the specified path."
            exit 1
        fi
        log_info "Found sdf-utils RPM package: ${SDF_UTILS_RPM}"
    fi

    # Check 3: vtzfdriver.ko must not be loaded (this check must be last)
    log_info "Checking vtzfdriver.ko module..."
    if lsmod | grep -q "^vtzfdriver"; then
        log_error "vtzfdriver.ko module is already loaded!"
        log_error "Please reboot the machine and run this script again."
        log_info "After reboot, run: $0"
        exit 1
    fi
    log_info "vtzfdriver.ko module is not loaded"

    log_info "All pre-deployment checks passed for VM"
    return 0
}

# -----------------------------------------------------------------------------
# Step 0: Install dependencies
# -----------------------------------------------------------------------------
install_dependencies() {
    log_step "[Step 0] Installing dependencies..."

    yum install -y git make gcc openssl-devel kernel-devel-"$(uname -r)" || {
        log_error "Failed to install dependencies"
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
    log_info "Dependencies installed successfully"
    return 0
}

# -----------------------------------------------------------------------------
# Step 1: Clone libboundscheck
# -----------------------------------------------------------------------------
clone_libboundscheck() {
    log_step "[Step 1] Cloning libboundscheck repository..."

    if [[ -d "${LIBBOUNDSCHECK_DIR}" ]]; then
        if [[ "${LENIENT_MODE}" == "true" ]]; then
            log_info "libboundscheck directory already exists, lenient mode enabled, skipping clone"
            return 0
        else
            log_warn "libboundscheck directory already exists, delete it before clone"
            rm -rf ${LIBBOUNDSCHECK_DIR} || {
                log_error "Failed to delete libboundscheck directory"
                return 1
            }
            log_info "Delete libboundscheck directory successfully"
        fi
    fi

    git clone "${LIBBOUNDSCHECK_REPO}" || {
        log_error "Failed to clone libboundscheck"
        return 1
    }

    log_info "libboundscheck cloned successfully"
    return 0
}

# -----------------------------------------------------------------------------
# Step 2: Clone tee_gp_proxy
# -----------------------------------------------------------------------------
clone_tee_gp_proxy() {
    log_step "[Step 2] Cloning tee-gp-proxy..."

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
# Step 3: Clone itrustee_client
# -----------------------------------------------------------------------------
clone_itrustee_client() {
    log_step "[Step 3] Cloning itrustee_client repository..."

    if [[ -d "${ITRUSTEE_CLIENT_DIR}" ]]; then
        if [[ "${LENIENT_MODE}" == "true" ]]; then
            log_info "itrustee_client directory already exists, lenient mode enabled, skipping clone"
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

    log_info "itrustee_client cloned successfully"
    return 0
}

# -----------------------------------------------------------------------------
# Step 4: Copy libboundscheck
# -----------------------------------------------------------------------------
copy_libboundscheck() {
    log_step "[Step 4] Copying libboundscheck to itrustee_client and vtzdriver..."

    cp -rf "${LIBBOUNDSCHECK_DIR}" "${ITRUSTEE_CLIENT_DIR}/" || {
        log_error "Failed to copy libboundscheck to itrustee_client"
        return 1
    }
    cp -rf "${LIBBOUNDSCHECK_DIR}" "${VTZDRIVER_DIR}/" || {
        log_error "Failed to copy libboundscheck to vtzdriver"
        return 1
    }

    if [[ ! -d "${ITRUSTEE_CLIENT_DIR}/libboundscheck" ]] || [[ ! -d "${VTZDRIVER_DIR}/libboundscheck" ]]; then
        log_error "copy libboundscheck failed"
        return 1
    fi

    log_info "libboundscheck copied successfully"
    return 0
}

# -----------------------------------------------------------------------------
# Step 5: Patch client
# -----------------------------------------------------------------------------
patch_client() {
    log_step "[Step 5] Patching client..."

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
    log_info "client patches applied successfully"
    return 0
}

# -----------------------------------------------------------------------------
# Step 6: Build and install itrustee_client
# -----------------------------------------------------------------------------
build_itrustee_client() {
    log_step "[Step 6] Building and installing itrustee_client..."

    pushd "${ITRUSTEE_CLIENT_DIR}" > /dev/null || return 1

    make || {
        log_error "Failed to build itrustee_client"
        popd > /dev/null
        return 1
    }

    make install || {
        log_error "Failed to install itrustee_client"
        popd > /dev/null
        return 1
    }

    popd > /dev/null
    log_info "itrustee_client built and installed successfully"
}

# -----------------------------------------------------------------------------
# Step 7: Build and copy vtzfdriver
# -----------------------------------------------------------------------------
build_and_copy_vtzfdriver() {
    log_step "[Step 7] Build and copy vtzfdriver..."
    pushd "${VTZDRIVER_DIR}" > /dev/null || return 1

    if [[ "$OS_TYPE" == "Kylin" ]] || [[ "$OS_TYPE" == "UOS" ]]; then
        log_info "Detected ${OS_TYPE} OS, removing -fstack-protector-strong from Makefile..."
        sed -i 's/-fstack-protector-strong//g' Makefile
    fi

    log_info "Building vtzfdriver..."
    make || {
        log_error "Failed to build vtzfdriver"
        popd > /dev/null
        return 1
    }

    log_info "vtzfdriver built successfully"

    if [[ ! -d "${TRUSTZONE_INSTALL_DIR}" ]]; then
        log_warn "trustzone install directory does not exist, make directory first"
        mkdir -p "${TRUSTZONE_INSTALL_DIR}"
    fi

    log_info "copying vtzfdriver.ko to trustzone install directory..."
    cp vtzfdriver.ko "${TRUSTZONE_INSTALL_DIR}/" || {
        log_error "Failed to copy vtzfdriver.ko"
        popd > /dev/null
        return 1
    }

    log_info "vtzfdriver.ko copyed to ${TRUSTZONE_INSTALL_DIR}"
    popd > /dev/null
    return 0
}

# -----------------------------------------------------------------------------
# Step 7.1: Install sdf utils*.rpm
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

# -----------------------------------------------------------------------------
# Step 8: add access permission of teecd directory for normal user
# -----------------------------------------------------------------------------
set_teecd_acl() {
  if [ -z "$USER" ]; then
    return 0
  fi
  log_step "[Step 8] set teecd acl..."

  local dir="/var/itrustee/teecd"
  if [ ! -d "$dir" ]; then
    log_error "Directory $dir does not exist"
    return 1
  fi

  log_info "Setting ACL for users: $USER"

  IFS=' ' read -ra USER_ARRAY <<< "$USER"
  for user in "${USER_ARRAY[@]}"; do
    if id "$user" &>/dev/null; then
      log_info "Processing user: $user"
      setfacl -m u:"$user":rwx "$dir"
      setfacl -d -m u:"$user":rw "$dir" || {
        log_error "Failed to set default ACL for $user"
        return 1
      }
    else
      log_warning "User $user does not exist, skipping"
    fi
  done
  
  log_info "ACL set successfully"
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
        log_error "========== VM deployment failed =========="
    fi
}

trap cleanup EXIT

# -----------------------------------------------------------------------------
# Main Deployment Function
# -----------------------------------------------------------------------------
deploy_vm() {
    log_info "========== Starting VM Environment Deployment =========="

    # Execute all steps
    pre_deployment_check || { log_error "pre deployment check failed"; return 1; }
    install_dependencies || { log_error "Step 0 failed"; return 1; }
    clone_libboundscheck || { log_error "Step 1 failed"; return 1; }
    clone_tee_gp_proxy || { log_error "Step 2 failed"; return 1; }
    clone_itrustee_client || { log_error "Step 3 failed"; return 1; }
    copy_libboundscheck || { log_error "Step 4 failed";  return 1; }
    patch_client || { log_error "Step 5 failed"; return 1; }
    build_itrustee_client || { log_error "Step 6 failed"; return 1; }
    build_and_copy_vtzfdriver || { log_error "Step 7 failed"; return 1; }
    if [[ "$NEED_SDF_UTILS_RPM" = "true" ]]; then
        install_sdf_utils_rpm || { log_error "Step 7.1 failed"; return 1; }
    fi
    set_teecd_acl || { log_error "Step 8 failed"; return 1; }
    log_info "========== VM Environment Deployment Completed =========="
}

# -----------------------------------------------------------------------------
# Script Entry Point
# -----------------------------------------------------------------------------
main() {
    # Start deployment
    deploy_vm
    DEPLOYMENT_SUCCESS=true
    echo ""
    log_info "VM deployment completed successfully!"
    echo ""
    log_info "Please run the following commands to start services in order:"
    log_info "  insmod /lib/modules/\$(uname -r)/kernel/drivers/trustzone/vtzfdriver.ko"
    log_info "  nohup /usr/bin/teecd &"
    log_info "NOTICE! Every time the system reboots, the commands above also need to be run."
    echo ""
}

main