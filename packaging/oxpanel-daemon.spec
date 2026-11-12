Name:           oxpanel-daemon
Version:        0.1.0
Release:        1%{?dist}
Summary:        OxPanel system engine: tenant provisioning and Nginx virtual hosts over an authenticated UNIX-socket gRPC API
License:        Apache-2.0
URL:            https://github.com/OxServers/oxpanel
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  systemd-rpm-macros
# Rust toolchain: use `rustup` (see rust-toolchain.toml) or the rust-toolset module.

Requires:       nginx
Requires:       shadow-utils
Requires:       util-linux
Requires:       acl
Requires:       coreutils
Requires:       logrotate
# PHP is optional: without php-fpm, virtual hosts are static only.
Recommends:     php-fpm
# Likewise optional: Node.js applications. (Python 3 is part of the base system.)
Recommends:     nodejs
Recommends:     npm
Requires:       policycoreutils
Requires:       policycoreutils-python-utils
Requires:       libselinux-utils
%{?systemd_requires}
%{?sysusers_requires_compat}

%description
The open-source core of OxPanel. A root-privileged daemon that provisions
isolated hosting tenants (dedicated POSIX accounts, private homes, systemd
slices carrying cgroups-v2 limits) and manages Nginx virtual hosts, exposing
the operations over gRPC on a UNIX socket authenticated by peer credentials.

%prep
%autosetup -n oxpanel-%{version}

%build
cargo build --release --locked -p oxpanel-daemon -p oxpanel-ctl

%install
install -D -m 0755 target/release/oxpanel-daemon %{buildroot}%{_sbindir}/oxpanel-daemon
install -D -m 0755 target/release/oxpanel-ctl    %{buildroot}%{_bindir}/oxpanel-ctl
install -D -m 0644 packaging/systemd/oxpanel-daemon.service %{buildroot}%{_unitdir}/oxpanel-daemon.service
install -D -m 0644 packaging/sysusers.d/oxpanel.conf %{buildroot}%{_sysusersdir}/oxpanel.conf
install -D -m 0644 packaging/tmpfiles.d/oxpanel.conf %{buildroot}%{_tmpfilesdir}/oxpanel.conf
install -D -m 0640 packaging/daemon.env %{buildroot}%{_sysconfdir}/oxpanel/daemon.env
install -D -m 0644 packaging/logrotate.d/oxpanel %{buildroot}%{_sysconfdir}/logrotate.d/oxpanel
install -D -m 0644 packaging/selinux/oxpanel.cil %{buildroot}%{_datadir}/oxpanel/selinux/oxpanel.cil

%pre
%sysusers_create_compat packaging/sysusers.d/oxpanel.conf

%post
%systemd_post oxpanel-daemon.service
%tmpfiles_create oxpanel.conf
# Sites live under tenant homes: let the web server traverse and read them, and
# let a tenant's PHP (which runs in the web-server domain) write the tenant's own
# site (uploads, caches). File ownership still decides whose files those are.
if /usr/sbin/selinuxenabled 2>/dev/null; then /usr/sbin/setsebool -P httpd_enable_homedirs=on httpd_read_user_content=on httpd_unified=on || :; fi

# The domain tenant applications run in, and the label of their socket directories.
if /usr/sbin/selinuxenabled 2>/dev/null; then /usr/sbin/semodule -i %{_datadir}/oxpanel/selinux/oxpanel.cil || :; fi

%preun
%systemd_preun oxpanel-daemon.service

%postun
%systemd_postun_with_restart oxpanel-daemon.service
# On removal (not upgrade) take the policy module out again.
if [ "$1" -eq 0 ] && /usr/sbin/selinuxenabled 2>/dev/null; then /usr/sbin/semodule -r oxpanel 2>/dev/null || :; fi

%files
%license LICENSE
%doc oxpanel-daemon/README.md
%{_sbindir}/oxpanel-daemon
%{_bindir}/oxpanel-ctl
%{_unitdir}/oxpanel-daemon.service
%{_sysusersdir}/oxpanel.conf
%{_tmpfilesdir}/oxpanel.conf
%dir %attr(0750,root,oxpanel) %{_sysconfdir}/oxpanel
%config(noreplace) %attr(0640,root,root) %{_sysconfdir}/oxpanel/daemon.env
%config(noreplace) %{_sysconfdir}/logrotate.d/oxpanel
%dir %{_datadir}/oxpanel
%dir %{_datadir}/oxpanel/selinux
%{_datadir}/oxpanel/selinux/oxpanel.cil

%changelog
* Sat Sep 05 2026 OxPanel contributors - 0.1.0-1
- Initial packaging.
