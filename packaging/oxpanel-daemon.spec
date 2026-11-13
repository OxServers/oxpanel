Name:           oxpanel-daemon
Version:        0.2.0
Release:        1%{?dist}
Summary:        OxPanel engine: tenants, Nginx sites, apps and databases over a local gRPC API
License:        Apache-2.0
URL:            https://github.com/OxServers/oxpanel
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  systemd-rpm-macros
# Rust toolchain: 1.88 or newer (Cargo.toml rust-version; tested with the
# version pinned in rust-toolchain.toml). Use `rustup`, or the rust-toolset
# module only if it is at least 1.88.

Requires:       nginx
# Certificates are checked, and ACME keys and signing requests made, with OpenSSL;
# the ACME client trusts the system's CA bundle.
Requires:       openssl
Requires:       ca-certificates
Requires:       shadow-utils
Requires:       util-linux
Requires:       acl
Requires:       coreutils
Requires:       logrotate
# Backups: the archiver and its compressor (run as the tenant).
Requires:       tar
Requires:       gzip
# PHP is optional: without php-fpm, virtual hosts are static only.
Recommends:     php-fpm
# PHP scheduled tasks run PHP's command-line interpreter; without it they are
# refused (other tasks still work). URL tasks use curl (curl-minimal is enough).
Recommends:     php-cli
# Likewise optional: Node.js applications need Node.js 22 or newer. AlmaLinux 9
# only offers that as a module stream, so these are satisfied (and installed)
# only after `dnf module enable nodejs:22`. (Python 3 is part of the base system.)
Recommends:     nodejs >= 1:22
Recommends:     npm
# SFTP access for tenants needs sshd (normally installed already); disk
# quotas need xfs_quota and an XFS /home mounted with user quotas (see the
# handbook). Without them, those features are reported unavailable.
Recommends:     openssh-server
Recommends:     xfsprogs
# Tenant databases are optional too, and a database server is a decision for
# the operator (HANDBOOK §3.5 installs, hardens and starts it), so these are
# only suggested: dnf does not install them by itself.
Suggests:       mariadb-server
Suggests:       php-mysqlnd
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
cargo build --release --locked -p oxpanel-daemon -p oxpanel-ctl -p oxpanel-acme

%install
install -D -m 0755 target/release/oxpanel-daemon %{buildroot}%{_sbindir}/oxpanel-daemon
install -D -m 0755 target/release/oxpanel-ctl    %{buildroot}%{_bindir}/oxpanel-ctl
install -D -m 0755 target/release/oxpanel-acme   %{buildroot}%{_libexecdir}/oxpanel/oxpanel-acme
install -D -m 0644 packaging/systemd/oxpanel-daemon.service %{buildroot}%{_unitdir}/oxpanel-daemon.service
install -D -m 0644 packaging/sysusers.d/oxpanel.conf %{buildroot}%{_sysusersdir}/oxpanel.conf
install -D -m 0644 packaging/tmpfiles.d/oxpanel.conf %{buildroot}%{_tmpfilesdir}/oxpanel.conf
install -D -m 0640 packaging/daemon.env %{buildroot}%{_sysconfdir}/oxpanel/daemon.env
install -D -m 0644 packaging/logrotate.d/oxpanel %{buildroot}%{_sysconfdir}/logrotate.d/oxpanel
install -D -m 0644 packaging/selinux/oxpanel.cil %{buildroot}%{_datadir}/oxpanel/selinux/oxpanel.cil
install -D -m 0644 packaging/fail2ban/oxpanel-sshd.local %{buildroot}%{_datadir}/oxpanel/fail2ban/oxpanel-sshd.local

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
# The ACME challenge directory was created (by tmpfiles above) before the module
# that labels it for the web server was loaded.
if /usr/sbin/selinuxenabled 2>/dev/null; then /usr/sbin/restorecon -R /var/lib/oxpanel-acme /etc/pki/oxpanel || :; fi

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
%dir %{_libexecdir}/oxpanel
%{_libexecdir}/oxpanel/oxpanel-acme
%{_unitdir}/oxpanel-daemon.service
%{_sysusersdir}/oxpanel.conf
%{_tmpfilesdir}/oxpanel.conf
%dir %attr(0750,root,oxpanel) %{_sysconfdir}/oxpanel
%config(noreplace) %attr(0640,root,root) %{_sysconfdir}/oxpanel/daemon.env
%config(noreplace) %{_sysconfdir}/logrotate.d/oxpanel
%dir %{_datadir}/oxpanel
%dir %{_datadir}/oxpanel/selinux
%{_datadir}/oxpanel/selinux/oxpanel.cil
%dir %{_datadir}/oxpanel/fail2ban
%{_datadir}/oxpanel/fail2ban/oxpanel-sshd.local

%changelog
* Fri Nov 13 2026 OxPanel contributors - 0.2.0-1
- HTTPS: certificates (uploaded, or from an ACME authority through the new
  oxpanel-acme client), Automatic HTTPS for every site, HTTP-to-HTTPS
  redirect and HSTS, External Account Binding (ZeroSSL, Google).
- PHP-FPM per tenant, Node.js (22 or newer) and Python applications behind
  Nginx, per-site access and error logs with rotation.
- SFTP access for tenants (keys, opt-in passwords) confined by an sshd
  drop-in; XFS user disk quotas (disk and inode limits).
- Tenant databases and database users on MariaDB, with grants.
- Backup and restore jobs, with database dumps; retained backups of deleted
  tenants; retention in days.
- A database trash (deleted databases kept 30 days by default, restorable
  under a new name) and the deletion of a customer with everything it has,
  in one step and optionally after a final backup (a job).
- A file manager: list, read, edit, upload, move, copy, delete, compress and
  extract a tenant's files, always as the tenant and beneath its home.
- Engine: more drift kinds in Reconcile, per-peer API scopes, the OxPanel
  SELinux module (oxpanel_app_t), a fail2ban jail template under
  /usr/share/oxpanel/fail2ban. The one-command installer (install.sh)
  ships beside the package, not in it.
- Upgrade from 0.1.0: records written by 0.1.0 load unchanged and the daemon
  re-renders its configuration when it starts.

* Sat Sep 05 2026 OxPanel contributors - 0.1.0-1
- Initial packaging.
