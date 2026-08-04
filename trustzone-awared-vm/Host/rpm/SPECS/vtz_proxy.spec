Name:           vtz_proxy
Version:        1.0.0
Release:        1%{?dist}
Group:          System Environment/Daemons
Summary:        itrustee daemon
License:        MulanPSL-2.0

%{?systemd_requires}
BuildRequires: systemd

%description
vtz_proxy is daemon process for tee virtual machine

%pre

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_unitdir}
mkdir -p %{buildroot}/var/vtzb
install -m 0755 %{_sourcedir}/vtz_proxy %{buildroot}%{_bindir}/
install -m 0644 %{_sourcedir}/vtz_proxy.service %{buildroot}%{_unitdir}/
install -m 0644 %{_sourcedir}/vtzb_proxy.conf %{buildroot}/var/vtzb/

%post
systemctl daemon-reload || :
systemctl enable vtz_proxy.service || :
systemctl start vtz_proxy.service || :

%preun
if [ $1 -eq 0 ]; then
    systemctl disable vtz_proxy.service || :
    systemctl stop vtz_proxy.service || :
fi

%postun
if [ $1 -eq 0 ]; then
    systemctl daemon-reload || :
fi

%files
%defattr(-,root,root,-)
%{_bindir}/vtz_proxy
%{_unitdir}/vtz_proxy.service
%config /var/vtzb/vtzb_proxy.conf

%changelog
* Mon Jul 20 2026 liuhao<liuhao365@h-partners.com>-1.0.0-1
- package init