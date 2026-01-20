Name:           tee-monitor
Version:        1.3.0
Release:        1%{?dist}
Summary:        Monitor service for TEE kernel modules and processes

License:        MIT
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
Requires:       bash
Requires:       systemd
Requires:       procps-ng
Requires:       kmod

%description
TEE Monitor is a systemd service that monitors and keeps alive
TEE-related kernel modules and processes. It automatically detects
the running environment (host or virtual machine) and manages the
appropriate components:

Host scenarios (three options):
- Host + VM (default): tzdriver.ko, vtz_proxy, teecd
- Host Only (VM_MODE=false): tzdriver.ko, teecd
- Host + Container (CONTAINER_MODE=true): tzdriver.ko, teecd, sdf-utils

VM scenarios:
- VM (5.10 kernel): virtio_console.ko (init only), vtzfdriver.ko, teecd
- VM (4.19 kernel): vtzfdriver.ko, teecd
- VM + Container: adds sdf-utils monitoring

Environment variables:
- CONTAINER_MODE: Enable container mode (true/false, default: false)
- VM_MODE: Enable vtz_proxy monitoring (true/false, default: true)
- CHECK_INTERVAL: Monitoring interval in seconds (default: 30)
- SDF_UTILS_PATH: Path to sdf-utils executable (default: /usr/bin/sdf-utils)

Features:
- Automatic environment detection (host vs VM)
- Configuration validation at startup
- Kernel module loading and monitoring
- Dependency order guarantee (modules before processes)
- Automatic process monitoring with configurable interval
- Automatic restart of unloaded modules or stopped processes
- Systemd integration with journal logging
- Boot-time auto-start capability

%prep
%setup -q

%build
# Nothing to build - shell script only

%install
# Install the monitor script
install -D -m 0755 tee-monitor.sh %{buildroot}%{_libexecdir}/tee-monitor.sh

# Install the systemd service file
install -D -m 0644 tee-monitor.service %{buildroot}/usr/lib/systemd/system/tee-monitor.service

%post
# Reload systemd daemon
systemctl daemon-reload >/dev/null 2>&1 || :
# Enable and start the service on new installations
if [ $1 -eq 1 ]; then
    systemctl enable tee-monitor.service >/dev/null 2>&1 || :
    systemctl start tee-monitor.service >/dev/null 2>&1 || :
fi

%preun
# Stop and disable the service before uninstallation
if [ $1 -eq 0 ]; then
    systemctl stop tee-monitor.service >/dev/null 2>&1 || :
    systemctl disable tee-monitor.service >/dev/null 2>&1 || :
fi

%postun
# Reload systemd daemon after uninstallation
systemctl daemon-reload >/dev/null 2>&1 || :
# Restart the service after upgrade
if [ $1 -ge 1 ]; then
    systemctl try-restart tee-monitor.service >/dev/null 2>&1 || :
fi

%files
%{_libexecdir}/tee-monitor.sh
/usr/lib/systemd/system/tee-monitor.service

%changelog
* Sun Jan 19 2025 xc <1097798774@qq.com> - 1.3.0-1
- Host environment now supports three scenarios: Host+VM, Host Only, Host+Container
- Rename ENABLE_SDF_UTILS to CONTAINER_MODE for better clarity
- Restore VM_MODE variable to support Host Only scenario (teecd only)
- Add configuration validation at startup (CONTAINER_MODE, VM_MODE, CHECK_INTERVAL)
- Add --check parameter for manual configuration validation
- Add ExecStartPre to show config errors directly on systemctl restart failure
- CONTAINER_MODE=true takes precedence over VM_MODE setting

* Thu Jan 16 2025 xc <1097798774@qq.com> - 1.2.0-1
- Add container scenario support for sdf-utils monitoring
- Add SDF_UTILS_PATH environment variable to specify sdf-utils path (default: /usr/bin/sdf-utils)
- sdf-utils monitoring includes dependency checking (modules and processes must be ready first)
- Simplify virtio_console initialization to always unload first then reload from trustzone path

* Tue Jan 14 2025 xc <1097798774@qq.com> - 1.1.0-1
- Add kernel module monitoring and loading
- Host: load and monitor tzdriver.ko
- VM (5.10 kernel): load and monitor virtio_console.ko and vtzfdriver.ko
- VM (4.19 kernel): load and monitor vtzfdriver.ko
- Ensure modules are loaded before starting processes
- Add kmod dependency for insmod/rmmod/lsmod/modinfo

* Mon Jan 13 2025 xc <1097798774@qq.com> - 1.0.0-1
- Rename project to tee-monitor
- Add automatic environment detection (host vs VM)
- Host: monitor vtz_proxy and teecd
- VM: monitor teecd only
