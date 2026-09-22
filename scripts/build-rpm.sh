#!/usr/bin/env bash
# Build the oxpanel-daemon RPM from the current working tree (uncommitted changes
# included). Runs inside the AlmaLinux 9 dev container; invoked by `make rpm`.
set -euo pipefail
WORK=/work
VER="$(sed -n 's/^version = "\(.*\)"/\1/p' "$WORK/Cargo.toml" | head -1)"
SPEC_VER="$(sed -n 's/^Version:\s*//p' "$WORK/packaging/oxpanel-daemon.spec")"
[ "$VER" = "$SPEC_VER" ] || { echo "version mismatch: Cargo.toml=$VER spec=$SPEC_VER" >&2; exit 1; }

TOP=/work/target/rpmbuild
rm -rf "$TOP"; mkdir -p "$TOP"/{SOURCES,SPECS,BUILD,BUILDROOT,RPMS,SRPMS}
tar -C "$WORK" --exclude=./target --exclude=./.git --exclude=./dist \
    --transform "s,^\./,oxpanel-$VER/," -czf "$TOP/SOURCES/oxpanel-daemon-$VER.tar.gz" .
cp "$WORK/packaging/oxpanel-daemon.spec" "$TOP/SPECS/"
rpmbuild --define "_topdir $TOP" -bb "$TOP/SPECS/oxpanel-daemon.spec" > "$TOP/rpmbuild.log" 2>&1 \
    || { tail -40 "$TOP/rpmbuild.log" >&2; exit 1; }
mkdir -p "$WORK/dist/rpms"
rm -f "$WORK"/dist/rpms/oxpanel-daemon-*.rpm
cp "$TOP"/RPMS/x86_64/oxpanel-daemon-*.rpm "$WORK/dist/rpms/"
ls -1 "$WORK/dist/rpms/"
