#!/bin/bash
#
# build.sh - RPM Package Build Script
#
# Usage: ./build.sh [options]
#   Options:
#     -c, --clean     Clean build environment
#     -i, --install   Install after build
#     -h, --help      Show help information
#

set -e

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project configuration
PROJECT_NAME="tee-monitor"
VERSION="1.3.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RPMBUILD_DIR="$HOME/rpmbuild"

# Logging functions
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

# Show help information
show_help() {
    cat << EOF
用法: $0 [选项]

RPM 包构建脚本 - ${PROJECT_NAME}

选项:
    -c, --clean     清理构建环境后退出
    -i, --install   构建成功后自动安装 RPM 包
    -h, --help      显示此帮助信息

示例:
    $0              # 仅构建 RPM 包
    $0 -i           # 构建并安装
    $0 -c           # 清理构建环境
    $0 -c -i        # 清理、构建并安装

EOF
    exit 0
}

# Check dependencies
check_dependencies() {
    log_step "检查构建依赖..."

    local missing_deps=()

    if ! command -v rpmbuild &> /dev/null; then
        missing_deps+=("rpm-build")
    fi

    if ! command -v rpmdev-setuptree &> /dev/null; then
        missing_deps+=("rpmdevtools")
    fi

    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "缺少以下依赖: ${missing_deps[*]}"
        log_info "请执行以下命令安装依赖:"
        echo ""
        echo "    sudo yum install -y ${missing_deps[*]}"
        echo ""
        exit 1
    fi

    log_info "依赖检查通过"
}

# Check source files
check_source_files() {
    log_step "检查源文件..."

    local required_files=(
        "tee-monitor.sh"
        "tee-monitor.service"
        "tee-monitor.spec"
    )

    for file in "${required_files[@]}"; do
        if [ ! -f "${SCRIPT_DIR}/${file}" ]; then
            log_error "缺少源文件: ${file}"
            exit 1
        fi
    done

    log_info "源文件检查通过"
}

# Clean build environment
clean_build() {
    log_step "清理构建环境..."

    # Clean related files in rpmbuild directory
    rm -rf "${RPMBUILD_DIR}/BUILD/${PROJECT_NAME}-"*
    rm -rf "${RPMBUILD_DIR}/BUILDROOT/${PROJECT_NAME}-"*
    rm -f "${RPMBUILD_DIR}/SOURCES/${PROJECT_NAME}-"*.tar.gz
    rm -f "${RPMBUILD_DIR}/SPECS/${PROJECT_NAME}.spec"
    rm -f "${RPMBUILD_DIR}/RPMS/noarch/${PROJECT_NAME}-"*.rpm
    rm -f "${RPMBUILD_DIR}/SRPMS/${PROJECT_NAME}-"*.src.rpm

    # Clean local temporary files
    rm -rf "${SCRIPT_DIR}/${PROJECT_NAME}-${VERSION}"
    rm -f "${SCRIPT_DIR}/${PROJECT_NAME}-${VERSION}.tar.gz"

    log_info "清理完成"
}

# Setup RPM build environment
setup_rpmbuild() {
    log_step "设置 RPM 构建环境..."

    if [ ! -d "${RPMBUILD_DIR}" ]; then
        rpmdev-setuptree
        log_info "已创建 rpmbuild 目录结构"
    else
        log_info "rpmbuild 目录已存在"
    fi
}

# Create source tarball
create_source_tarball() {
    log_step "创建源码包..."

    local src_dir="${SCRIPT_DIR}/${PROJECT_NAME}-${VERSION}"

    # Create source directory
    mkdir -p "${src_dir}"

    # Copy source files
    cp "${SCRIPT_DIR}/tee-monitor.sh" "${src_dir}/"
    cp "${SCRIPT_DIR}/tee-monitor.service" "${src_dir}/"

    # Create tarball
    cd "${SCRIPT_DIR}"
    tar czvf "${PROJECT_NAME}-${VERSION}.tar.gz" "${PROJECT_NAME}-${VERSION}"

    # Copy to SOURCES directory
    cp "${PROJECT_NAME}-${VERSION}.tar.gz" "${RPMBUILD_DIR}/SOURCES/"

    # Clean temporary directory
    rm -rf "${src_dir}"
    rm -f "${PROJECT_NAME}-${VERSION}.tar.gz"

    log_info "源码包创建完成: ${RPMBUILD_DIR}/SOURCES/${PROJECT_NAME}-${VERSION}.tar.gz"
}

# Copy spec file
copy_spec_file() {
    log_step "复制 spec 文件..."

    cp "${SCRIPT_DIR}/tee-monitor.spec" "${RPMBUILD_DIR}/SPECS/"

    log_info "spec 文件已复制到: ${RPMBUILD_DIR}/SPECS/"
}

# Build RPM package
build_rpm() {
    log_step "开始构建 RPM 包..."

    cd "${RPMBUILD_DIR}/SPECS"

    if rpmbuild -ba "${PROJECT_NAME}.spec"; then
        log_info "RPM 包构建成功!"
        echo ""
        log_info "生成的文件:"
        echo "    二进制包: $(ls ${RPMBUILD_DIR}/RPMS/noarch/${PROJECT_NAME}-*.rpm 2>/dev/null)"
        echo "    源码包:   $(ls ${RPMBUILD_DIR}/SRPMS/${PROJECT_NAME}-*.src.rpm 2>/dev/null)"
        echo ""
        return 0
    else
        log_error "RPM 包构建失败!"
        return 1
    fi
}

# Install RPM package
install_rpm() {
    log_step "安装 RPM 包..."

    local rpm_file=$(ls ${RPMBUILD_DIR}/RPMS/noarch/${PROJECT_NAME}-*.rpm 2>/dev/null | head -1)

    if [ -z "${rpm_file}" ]; then
        log_error "未找到 RPM 包"
        return 1
    fi

    # Check if already installed
    if rpm -q "${PROJECT_NAME}" &> /dev/null; then
        log_warn "检测到已安装的版本，将进行升级..."
        sudo rpm -Uvh "${rpm_file}"
    else
        sudo rpm -ivh "${rpm_file}"
    fi

    if [ $? -eq 0 ]; then
        log_info "安装成功!"
        echo ""
        log_info "服务管理命令:"
        echo "    启动服务:     sudo systemctl start ${PROJECT_NAME}"
        echo "    停止服务:     sudo systemctl stop ${PROJECT_NAME}"
        echo "    查看状态:     sudo systemctl status ${PROJECT_NAME}"
        echo "    查看日志:     sudo journalctl -u ${PROJECT_NAME} -f"
        echo ""
    else
        log_error "安装失败!"
        return 1
    fi
}

# Show build summary
show_summary() {
    echo ""
    echo "=============================================="
    echo "           构建完成摘要"
    echo "=============================================="
    echo "  项目名称: ${PROJECT_NAME}"
    echo "  版本号:   ${VERSION}"
    echo "  构建目录: ${RPMBUILD_DIR}"
    echo "=============================================="
    echo ""
}

# Main function
main() {
    local do_clean=false
    local do_install=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -c|--clean)
                do_clean=true
                shift
                ;;
            -i|--install)
                do_install=true
                shift
                ;;
            -h|--help)
                show_help
                ;;
            *)
                log_error "未知选项: $1"
                show_help
                ;;
        esac
    done

    echo ""
    echo "=============================================="
    echo "    ${PROJECT_NAME} RPM 构建脚本"
    echo "=============================================="
    echo ""

    # If only cleaning
    if $do_clean && ! $do_install; then
        clean_build
        exit 0
    fi

    # Clean if specified
    if $do_clean; then
        clean_build
    fi

    # Check dependencies and source files
    check_dependencies
    check_source_files

    # Setup build environment
    setup_rpmbuild

    # Create source tarball
    create_source_tarball

    # Copy spec file
    copy_spec_file

    # Build RPM
    if build_rpm; then
        show_summary

        # Install if specified
        if $do_install; then
            install_rpm
        else
            log_info "如需安装，请执行:"
            echo "    sudo rpm -ivh ${RPMBUILD_DIR}/RPMS/noarch/${PROJECT_NAME}-${VERSION}-*.noarch.rpm"
            echo ""
            echo "或重新运行构建脚本并添加 -i 参数:"
            echo "    $0 -i"
            echo ""
        fi
    else
        exit 1
    fi
}

# Run main function
main "$@"
