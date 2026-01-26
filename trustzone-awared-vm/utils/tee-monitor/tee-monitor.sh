#!/bin/bash
#
# tee-monitor.sh - Process monitor script for TEE services
#
# This script monitors and keeps alive TEE-related processes:
#
# Host environment scenarios:
#   - Host + VM (default): tzdriver.ko, vtz_proxy, teecd
#   - Host + Container (CONTAINER_MODE=true): tzdriver.ko, teecd, sdf-utils
#   - Host Only (VM_MODE=false): tzdriver.ko, teecd
#
# VM environment scenarios:
#   - VM (5.10 kernel): virtio_console.ko (init only), vtzfdriver.ko, teecd
#   - VM (4.19 kernel): vtzfdriver.ko, teecd
#   - VM + Container (CONTAINER_MODE=true): adds sdf-utils monitoring
#
# Note: On Host, VM and Container scenarios are mutually exclusive.
#       CONTAINER_MODE=true takes precedence over VM_MODE setting.
#

# Configuration
CHECK_INTERVAL=${CHECK_INTERVAL:-30}  # Default: 30 seconds

# Host scenario configuration
# Three scenarios available (VM and container are mutually exclusive):
#   - CONTAINER_MODE=false, VM_MODE=true (default): Host + VM, monitors vtz_proxy + teecd
#   - CONTAINER_MODE=false, VM_MODE=false: Host Only, monitors teecd only
#   - CONTAINER_MODE=true: Host + Container, monitors teecd + sdf-utils
CONTAINER_MODE=${CONTAINER_MODE:-false}
VM_MODE=${VM_MODE:-true}
SDF_UTILS_PATH=${SDF_UTILS_PATH:-/usr/bin/sdf-utils}

# Process lists for different environments
HOST_PROCESSES_WITH_VTZ=("/usr/bin/vtz_proxy" "/usr/bin/teecd")  # Host + VM
HOST_PROCESSES_ONLY=("/usr/bin/teecd")                           # Host Only
HOST_PROCESSES_CONTAINER=("/usr/bin/teecd")                      # Host + Container (sdf-utils handled separately)
VM_PROCESSES=("/usr/bin/teecd")

# Kernel module paths
TRUSTZONE_MODULE_PATH="/lib/modules/$(uname -r)/kernel/drivers/trustzone"
HOST_MODULES=("tzdriver")
VM_MODULES=("vtzfdriver")

# Will be set based on environment detection
PROCESSES=()
MODULES=()

# Flag to indicate if container mode is active
CONTAINER_ACTIVE=false

# Log functions (timestamps provided by systemd journal)
log_info() {
    echo "[INFO] $1"
}

log_warn() {
    echo "[WARN] $1"
}

log_error() {
    echo "[ERROR] $1"
}

# Validate configuration values
validate_config() {
    local has_error=false

    # Validate CONTAINER_MODE (must be "true" or "false")
    if [[ "$CONTAINER_MODE" != "true" && "$CONTAINER_MODE" != "false" ]]; then
        log_error "Invalid value for CONTAINER_MODE: '$CONTAINER_MODE'"
        log_error "CONTAINER_MODE must be 'true' or 'false'"
        log_error "Please check your configuration:"
        log_error "  - systemctl edit tee-monitor"
        log_error "  - Or check: /etc/systemd/system/tee-monitor.service.d/override.conf"
        has_error=true
    fi

    # Validate VM_MODE (must be "true" or "false")
    if [[ "$VM_MODE" != "true" && "$VM_MODE" != "false" ]]; then
        log_error "Invalid value for VM_MODE: '$VM_MODE'"
        log_error "VM_MODE must be 'true' or 'false'"
        log_error "Please check your configuration:"
        log_error "  - systemctl edit tee-monitor"
        log_error "  - Or check: /etc/systemd/system/tee-monitor.service.d/override.conf"
        has_error=true
    fi

    # Validate CHECK_INTERVAL (must be a positive integer)
    if ! [[ "$CHECK_INTERVAL" =~ ^[0-9]+$ ]] || [[ "$CHECK_INTERVAL" -le 0 ]]; then
        log_error "Invalid value for CHECK_INTERVAL: '$CHECK_INTERVAL'"
        log_error "CHECK_INTERVAL must be a positive integer (seconds)"
        has_error=true
    fi

    # Warn if both CONTAINER_MODE and VM_MODE are set (CONTAINER_MODE takes precedence)
    if [[ "$CONTAINER_MODE" == "true" && "$VM_MODE" == "true" ]]; then
        log_warn "Both CONTAINER_MODE=true and VM_MODE=true are set"
        log_warn "CONTAINER_MODE takes precedence, VM_MODE will be ignored"
    fi

    if [[ "$has_error" == "true" ]]; then
        log_error "Configuration validation failed. Exiting."
        exit 1
    fi

    log_info "Configuration validated successfully"
}

# Get kernel major.minor version (e.g., "5.10" or "4.19")
get_kernel_version() {
    uname -r | cut -d'.' -f1,2
}

# Check if a kernel module is loaded
is_module_loaded() {
    local module_name="$1"
    lsmod | grep -q "^${module_name}[[:space:]]"
    return $?
}

# Get the path from which a module was loaded
get_module_load_path() {
    local module_name="$1"
    modinfo "$module_name" 2>/dev/null | grep "^filename:" | awk '{print $2}'
}

# Load a kernel module
load_module() {
    local module_name="$1"
    local module_path="${TRUSTZONE_MODULE_PATH}/${module_name}.ko"

    if [[ ! -f "$module_path" ]]; then
        log_error "Module file not found: $module_path"
        return 1
    fi

    log_info "Loading kernel module: $module_name from $module_path"
    if insmod "$module_path"; then
        log_info "Module loaded successfully: $module_name"
        return 0
    else
        log_error "Failed to load module: $module_name"
        return 1
    fi
}

# Unload a kernel module
unload_module() {
    local module_name="$1"

    log_info "Unloading kernel module: $module_name"
    if rmmod "$module_name" 2>/dev/null; then
        log_info "Module unloaded successfully: $module_name"
        return 0
    else
        log_error "Failed to unload module: $module_name"
        return 1
    fi
}

# Check and load a kernel module if not loaded
check_and_load_module() {
    local module_name="$1"

    if ! is_module_loaded "$module_name"; then
        log_warn "Module not loaded: $module_name"
        load_module "$module_name"
        return $?
    fi
    return 0
}

# Initialize virtio_console for VM (5.10 kernel only)
# Always unload first then reload from trustzone path
init_virtio_console() {
    local kernel_version
    kernel_version=$(get_kernel_version)

    # Skip for 4.19 kernel
    if [[ "$kernel_version" == "4.19" ]]; then
        log_info "Kernel version is 4.19, skipping virtio_console initialization"
        return 0
    fi

    local module_path="${TRUSTZONE_MODULE_PATH}/virtio_console.ko"

    # Check if module file exists
    if [[ ! -f "$module_path" ]]; then
        log_error "virtio_console.ko not found at: $module_path"
        return 1
    fi

    # Unload virtio_console first (ignore errors if not loaded)
    log_info "Unloading virtio_console module..."
    rmmod virtio_console 2>/dev/null
    sleep 1

    # Load from trustzone path
    log_info "Loading virtio_console from: $module_path"
    if insmod "$module_path"; then
        log_info "virtio_console loaded successfully from trustzone path"
        return 0
    else
        log_error "Failed to load virtio_console"
        return 1
    fi
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

# Set up process and module lists based on environment
setup_environment() {
    if is_virtual_machine; then
        log_info "Detected environment: Virtual Machine"
        PROCESSES=("${VM_PROCESSES[@]}")
        MODULES=("${VM_MODULES[@]}")

        # Check if sdf-utils monitoring should be enabled (for container scenarios in VM)
        if [ "$CONTAINER_MODE" = "true" ]; then
            if [[ -x "$SDF_UTILS_PATH" ]]; then
                log_info "Container scenario: SDF Utils monitoring enabled"
                log_info "SDF Utils path: $SDF_UTILS_PATH"
                CONTAINER_ACTIVE=true
            else
                log_warn "SDF Utils enabled but executable not found: $SDF_UTILS_PATH"
                CONTAINER_ACTIVE=false
            fi
        fi
    else
        log_info "Detected environment: Host"
        MODULES=("${HOST_MODULES[@]}")

        # Three Host scenarios (Container mode takes precedence over VTZ Proxy setting)
        if [ "$CONTAINER_MODE" = "true" ]; then
            # Host + Container scenario: teecd + sdf-utils, no vtz_proxy
            log_info "Host scenario: Container mode (CONTAINER_MODE=true)"
            log_info "Container scenario does not require vtz_proxy"
            PROCESSES=("${HOST_PROCESSES_CONTAINER[@]}")

            if [[ -x "$SDF_UTILS_PATH" ]]; then
                log_info "SDF Utils monitoring enabled: $SDF_UTILS_PATH"
                log_info "SDF Utils depends on: modules [${MODULES[*]}] and processes [${PROCESSES[*]}]"
                CONTAINER_ACTIVE=true
            else
                log_warn "SDF Utils enabled but executable not found: $SDF_UTILS_PATH"
                log_warn "Please ensure sdf-utils is installed at: $SDF_UTILS_PATH"
                CONTAINER_ACTIVE=false
            fi
        elif [ "$VM_MODE" = "true" ]; then
            # Host + VM scenario: vtz_proxy + teecd (default)
            log_info "Host scenario: VM mode (VM_MODE=true)"
            log_info "VTZ Proxy enabled for VM communication"
            PROCESSES=("${HOST_PROCESSES_WITH_VTZ[@]}")
        else
            # Host Only scenario: teecd only, no vtz_proxy, no sdf-utils
            log_info "Host scenario: Host-only mode (VM_MODE=false)"
            log_info "No VM communication, monitoring teecd only"
            PROCESSES=("${HOST_PROCESSES_ONLY[@]}")
        fi
    fi
}

# Check if a process is running
is_process_running() {
    local process_path="$1"
    pgrep -f "^${process_path}" > /dev/null 2>&1
    return $?
}

# Start a process
start_process() {
    local process_path="$1"

    if [[ ! -x "$process_path" ]]; then
        log_error "Executable not found or not executable: $process_path"
        return 1
    fi

    log_info "Starting process: $process_path"
    nohup "$process_path" > /dev/null 2>&1 &

    # Wait a moment and verify it started
    sleep 1
    if is_process_running "$process_path"; then
        log_info "Process started successfully: $process_path (PID: $(pgrep -f "^${process_path}"))"
        return 0
    else
        log_error "Failed to start process: $process_path"
        return 1
    fi
}

# Check and restart process if needed
check_and_restart() {
    local process_path="$1"

    if ! is_process_running "$process_path"; then
        log_warn "Process not running: $process_path"
        start_process "$process_path"
    fi
}

# Check if all dependencies (modules and processes) are ready
# Returns 0 if all dependencies are ready, 1 otherwise
check_dependencies_ready() {
    # Check all modules are loaded
    for module in "${MODULES[@]}"; do
        if ! is_module_loaded "$module"; then
            return 1
        fi
    done

    # Check all processes are running
    for process in "${PROCESSES[@]}"; do
        if ! is_process_running "$process"; then
            return 1
        fi
    done

    return 0
}

# Ensure all dependencies are ready (reload/restart if needed)
ensure_dependencies_ready() {
    local need_wait=false

    # Step 1: Check and reload modules
    for module in "${MODULES[@]}"; do
        if ! is_module_loaded "$module"; then
            log_warn "Dependency module not loaded: $module"
            load_module "$module"
            need_wait=true
        fi
    done

    # Step 2: Check and restart processes
    for process in "${PROCESSES[@]}"; do
        if ! is_process_running "$process"; then
            log_warn "Dependency process not running: $process"
            start_process "$process"
            need_wait=true
        fi
    done

    # Wait for dependencies to stabilize if any were restarted
    if $need_wait; then
        sleep 2
    fi
}

# Check and restart sdf-utils with dependency checking
# This function ensures all dependencies are ready before starting sdf-utils
check_and_restart_sdf_utils() {
    if [ "$CONTAINER_ACTIVE" != "true" ]; then
        return 0
    fi

    if ! is_process_running "$SDF_UTILS_PATH"; then
        log_warn "sdf-utils not running: $SDF_UTILS_PATH"
        log_info "Checking dependencies before restarting sdf-utils..."

        # First ensure all dependencies are ready
        ensure_dependencies_ready

        # Verify dependencies are now ready
        if check_dependencies_ready; then
            log_info "All dependencies ready, starting sdf-utils..."
            start_process "$SDF_UTILS_PATH"
        else
            log_error "Dependencies not ready, cannot start sdf-utils"
            log_error "Will retry on next check interval"
        fi
    fi
}

# Load all required kernel modules
load_required_modules() {
    log_info "Checking and loading required kernel modules..."

    # For VM with 5.10 kernel: initialize virtio_console first
    # This is a one-time operation, virtio_console is not monitored afterwards
    if is_virtual_machine; then
        init_virtio_console
    fi

    # Load other required modules
    for module in "${MODULES[@]}"; do
        check_and_load_module "$module"
    done

    # Give modules time to initialize
    sleep 1
}

# Check all modules are still loaded
# Note: For VM, virtio_console is only initialized once at startup,
#       monitoring loop only checks vtzfdriver (defined in MODULES)
check_modules() {
    for module in "${MODULES[@]}"; do
        check_and_load_module "$module"
    done
}

# Initial startup - load modules first, then start all processes
initial_startup() {
    log_info "=== TEE Monitor Starting ==="
    log_info "Check interval: ${CHECK_INTERVAL} seconds"
    log_info "Monitored modules: ${MODULES[*]}"
    log_info "Monitored processes: ${PROCESSES[*]}"
    if [ "$CONTAINER_ACTIVE" = "true" ]; then
        log_info "SDF Utils monitoring: enabled ($SDF_UTILS_PATH)"
    fi

    # Step 1: Load kernel modules first (required before starting processes)
    load_required_modules

    # Step 2: Start core processes
    for process in "${PROCESSES[@]}"; do
        if ! is_process_running "$process"; then
            start_process "$process"
        else
            log_info "Process already running: $process (PID: $(pgrep -f "^${process}"))"
        fi
    done

    # Step 3: Start sdf-utils after all dependencies are ready (if enabled)
    if [ "$CONTAINER_ACTIVE" = "true" ]; then
        log_info "Starting sdf-utils (depends on modules and processes being ready)..."
        # Give dependencies a moment to fully initialize
        sleep 1
        if check_dependencies_ready; then
            if ! is_process_running "$SDF_UTILS_PATH"; then
                start_process "$SDF_UTILS_PATH"
            else
                log_info "sdf-utils already running: $SDF_UTILS_PATH (PID: $(pgrep -f "^${SDF_UTILS_PATH}"))"
            fi
        else
            log_error "Dependencies not ready, sdf-utils start delayed to monitoring loop"
        fi
    fi
}

# Cleanup on exit
cleanup() {
    log_info "=== TEE Monitor Stopping ==="
    exit 0
}

# Set up signal handlers
trap cleanup SIGTERM SIGINT SIGHUP

# Check configuration only (for ExecStartPre)
check_config_only() {
    echo "=== TEE Monitor Configuration Check ==="
    echo "Configuration: CONTAINER_MODE=$CONTAINER_MODE, VM_MODE=$VM_MODE, CHECK_INTERVAL=$CHECK_INTERVAL"

    # Run validation
    validate_config

    # If we reach here, validation passed
    echo "[OK] Configuration check passed"
    exit 0
}

# Main function
main() {
    log_info "=== TEE Monitor Starting ==="
    log_info "Configuration: CONTAINER_MODE=$CONTAINER_MODE, VM_MODE=$VM_MODE, CHECK_INTERVAL=$CHECK_INTERVAL"

    # Validate configuration before proceeding
    validate_config

    setup_environment
    initial_startup

    log_info "Entering monitoring loop..."

    while true; do
        sleep "$CHECK_INTERVAL"

        # Step 1: Check and reload modules if needed (must be before processes)
        check_modules

        # Step 2: Check and restart core processes if needed
        for process in "${PROCESSES[@]}"; do
            check_and_restart "$process"
        done

        # Step 3: Check and restart sdf-utils if needed (with dependency check)
        # sdf-utils is checked last because it depends on all modules and processes
        check_and_restart_sdf_utils
    done
}

# Parse command line arguments
case "${1:-}" in
    --check|-c)
        check_config_only
        ;;
    --help|-h)
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --check, -c    Check configuration only, then exit"
        echo "  --help, -h     Show this help message"
        echo ""
        echo "Without options, starts the TEE monitor service."
        exit 0
        ;;
    "")
        main
        ;;
    *)
        echo "[ERROR] Unknown option: $1"
        echo "Use --help for usage information"
        exit 1
        ;;
esac
