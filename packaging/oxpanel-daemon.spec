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

%pre
%sysusers_create_compat packaging/sysusers.d/oxpanel.conf

%post
%systemd_post oxpanel-daemon.service
%tmpfiles_create oxpanel.conf

%preun
%systemd_preun oxpanel-daemon.service

%postun
%systemd_postun_with_restart oxpanel-daemon.service

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

%changelog
* Sat Sep 05 2026 OxPanel contributors - 0.1.0-1
- Initial packaging.
