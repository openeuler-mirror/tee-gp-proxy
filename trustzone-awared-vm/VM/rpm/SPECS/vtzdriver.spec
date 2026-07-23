#Parameter
%{!?KVERSION: %define KVERSION %(uname -r)}
%define __strip /bin/true

Name:           vtzdriver
Version:        1.0.0
Release:        1%{?dist}
Group:          System Environment/Kernel
Summary:        itrustee driver
License:        GPLv3

%{?systemd_requires}
BuildRequires: systemd

%define kmodinstdir_prefix  /lib/modules/
%{!?kernel:  %{expand: %%define kernel %%(uname -r)}}
%description
vtzdriver is driver for tee

%pre

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p %{buildroot}/%{_sysconfdir}/modprobe.d
mkdir -p %{buildroot}%{kmodinstdir_prefix}%{kernel}/extra
install -m 0640 %{_sourcedir}/%{name}-blacklist.conf %{buildroot}/%{_sysconfdir}/modprobe.d
install -m 0550 %{_sourcedir}/%{name}.ko %{buildroot}%{kmodinstdir_prefix}%{kernel}/extra
find $RPM_BUILD_ROOT -name '*.la' -exec rm -f {} ';'
find %{buildroot} -type f -name \*.ko -exec %{__chmod} u+x \{\} \;

%post
if [[ %{KVERSION} != $(uname -r) ]]; then
    if [ ! -d "/lib/modules/$(uname -r)/extra" ];then
        mkdir -p /lib/modules/$(uname -r)/extra
    fi

    ln -sf /lib/modules/%{KVERSION}/extra/%{name}.ko /lib/modules/$(uname -r)/extra/%{name}.ko
fi
/sbin/depmod -a > /dev/null 2>&1

%postun
if [[ %{KVERSION} != $(uname -r) ]]; then
    rm -rf /lib/modules/$(uname -r)/extra/%{name}.ko > /dev/null 2>&1
fi
/sbin/depmod -a > /dev/null 2>&1

%files
%{_sysconfdir}/modprobe.d/%{name}-blacklist.conf
%{kmodinstdir_prefix}%{kernel}/extra/%{name}.ko

%changelog
* Mon Jul 20 2026 liuhao<liuhao365@h-partners.com>-1.0.0-1
- package init