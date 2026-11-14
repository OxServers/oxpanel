#!/usr/bin/env bash
# Collect a release into dist/release/: the engine RPM, install.sh, the handbook
# and a SHA256SUMS file over all of them. Nothing is tagged, signed or uploaded.
# Run by `make dist` after `make rpm` (host side; needs only coreutils).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
VER="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
SPEC_VER="$(sed -n 's/^Version:[[:space:]]*//p' packaging/oxpanel-daemon.spec)"
INST_VER="$(sed -n 's/^INSTALLER_VERSION="\(.*\)"/\1/p' install.sh)"
[ "$VER" = "$SPEC_VER" ] || { echo "version mismatch: Cargo.toml=$VER spec=$SPEC_VER" >&2; exit 1; }
[ "$VER" = "$INST_VER" ] || { echo "version mismatch: Cargo.toml=$VER install.sh=$INST_VER" >&2; exit 1; }

RPM="$(find dist/rpms -maxdepth 1 -name "oxpanel-daemon-$VER-*.rpm" ! -name '*debuginfo*' ! -name '*debugsource*' ! -name '*.src.rpm' | sort -V | tail -1)"
[ -n "$RPM" ] || { echo "no oxpanel-daemon-$VER RPM in dist/rpms (run make rpm)" >&2; exit 1; }

REL=dist/release
rm -rf "$REL"; mkdir -p "$REL"
cp "$RPM" "$REL/"
# The panel is a separate, proprietary product: it is never built from or kept
# in this repository. A bundle that includes it is assembled by naming its RPM
# (built in the panel's own repository): make dist PANEL_RPM=/path/oxpanel-panel-X.rpm
# install.sh then installs it by itself (--no-panel: not).
PANEL_NOTE=""
if [ -n "${PANEL_RPM:-}" ]; then
  [ -f "$PANEL_RPM" ] || { echo "PANEL_RPM=$PANEL_RPM: no such file" >&2; exit 1; }
  case "$(basename "$PANEL_RPM")" in oxpanel-panel-[0-9]*.rpm) ;; *) echo "PANEL_RPM must be an oxpanel-panel-<version>.rpm" >&2; exit 1;; esac
  cp "$PANEL_RPM" "$REL/"
  PANEL_NOTE="
This bundle includes the OxPanel panel ($(basename "$PANEL_RPM"), proprietary,
not covered by LICENSE): install.sh installs it, serves it over HTTPS on port
8443 and prints its first administrator's one-time password. --no-panel skips it."
fi
install -m 0755 install.sh "$REL/install.sh"
cp docs/HANDBOOK.md "$REL/HANDBOOK.md"
cp LICENSE "$REL/LICENSE"
cat >"$REL/README.txt" <<EOF
OxPanel engine $VER

  sudo ./install.sh            interactive installer for a fresh AlmaLinux 9 host
  sudo ./install.sh --help     every option (unattended use, fail2ban, disk quotas, ...)

install.sh installs the RPM beside it and performs the host steps of
HANDBOOK.md section 3. Check the files first:

  sha256sum -c SHA256SUMS

SHA256SUMS protects against a damaged download only; it is not a signature.
$PANEL_NOTE
EOF
(cd "$REL" && sha256sum -- * | grep -v ' SHA256SUMS$' | sort -k2 >SHA256SUMS && sha256sum -c --quiet SHA256SUMS)
echo "release $VER collected in $REL:"
ls -l "$REL"
