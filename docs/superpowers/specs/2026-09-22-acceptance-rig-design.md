# Real-host acceptance rig — design

Status: approved 2026-09-22. First of four testing work packages
(A: this rig · B: feature traceability · C: fuzzing, kill-and-resume, concurrency,
coverage · D: manual QA plan). B tags this rig's checks with feature IDs, C runs in
the existing dev container, D uses this rig's `KEEP=1` mode as its bench.

## Goal

Prove, on a real AlmaLinux 9 machine with SELinux enforcing, the things the
container-based `make integration` cannot: the RPM's dependency list, the SELinux
path (`semanage`/`restorecon`, zero AVC denials), the sandbox directives that need
real namespaces, survival across daemon restart/kill and a full reboot, and
stability under a create/destroy soak. One command, no host installs, identical
locally and in CI.

## Shape

Two halves, decoupled:

- **Provisioning** — a disposable KVM VM booted from the official AlmaLinux 9
  GenericCloud image by `qemu-kvm` running *inside* a podman container ("the rig")
  with `/dev/kvm` passed through; cloud-init seeds an SSH key. Cached image in the
  named volume `oxpanel-images`. Alternatively `TARGET=user@host` uses a machine you
  provide (destructive phases refuse to run without `I_UNDERSTAND=1`).
- **Acceptance** — given any SSH-reachable fresh host: install the RPM, run the
  phases below, collect artifacts, write `report.md`, exit non-zero on any failure.

```
tests-acceptance/Containerfile     rig image: AlmaLinux 9 + qemu-kvm + qemu-img + passt + openssh-clients + xorriso
tests-acceptance/acceptance.sh     driver (inside the rig): image → seed → boot → phases → artifacts → teardown
tests-acceptance/lib.sh            vm/ssh/report helpers
tests-acceptance/cloud-init/       user-data template, meta-data
tests-acceptance/phases/NN-*.sh    executed on the VM as root; print "ok   - …" / "FAIL: …"
scripts/acceptance.sh              host wrapper: /dev/kvm check, images, make rpm, podman run
scripts/build-rpm.sh               make rpm (inside the dev container) → dist/rpms/
dist/acceptance/<UTC stamp>/       report.md, phases/*.log, journal.txt, audit.log, nginx/, console.log, id_ed25519
```

Make: `rpm`, `acceptance` (`KEEP=1`, `PHASES="30 60"`, `SOAK_N=`, `RPM=`, `TARGET=`),
`acceptance-destroy`. `make integration` stays as the fast container path;
`tests-integration/run-inside.sh` is reused unchanged as phase 20 (`SKIP_INSTALL=1`).

## Phases

| # | Name | Proves |
|---|---|---|
| 10 | install | `dnf install` of the built RPM on a clean image resolves every `Requires:`; `rpm -V` clean; `oxpanel` group; `daemon.env 0640`; `--check-config` = 0; both services active; socket `root:oxpanel 0660` |
| 20 | integration | the existing 79 checks, now on real hardware under SELinux enforcing |
| 30 | selinux | `getenforce`=Enforcing; docroot labelled `httpd_sys_content_t`; `semanage fcontext` rule present then removed; site serves under enforcing; **zero AVC denials** for the run (denials printed in full) |
| 40 | sandbox | no "ignoring" in the unit's journal; daemon net namespace ≠ PID 1's and has only `lo`; UTS namespace private; `NoNewPrivs=1`, `Seccomp=2`; denied caps absent from `CapBnd`; `/usr` read-only and `/etc/nginx` writable from inside the service |
| 50 | resume | `systemctl restart` keeps tenants/sites; `kill -s KILL` → `Restart=on-failure` brings it back with a correct socket; a record forced to `provisioning` (daemon stopped, unit deleted) is completed by the next identical `CreateTenant` with exactly one `useradd` in the journal |
| 60 | reboot | with 2 tenants + 2 sites: reboot (boot id changes); both services active; sites serve; slices report limits; ACLs and records intact; no errors in the new boot's journal |
| 70 | soak | N (default 20) cycles create→site→curl 200→remove→delete; afterwards zero tenants, no slices, no `oxpanel.d/*.conf`, no homes, no uids in range, `nginx -t` clean, zero journal errors; daemon RSS growth reported |

A failing check stops later phases (`CONTINUE=1` overrides); artifact collection
always runs. Every phase has a timeout. A VM that never reaches SSH still leaves
`console.log`.

## VM

Official `AlmaLinux-9-GenericCloud-latest.x86_64.qcow2`, SHA-256 checked against the
published `CHECKSUM`. Per run: qcow2 overlay grown to 20 GB, fresh ed25519 key,
NoCloud seed (iso9660 labelled `cidata`) attached as a second virtio disk. 2 vCPU /
2 GB, `-cpu host`, headless, serial console to file. Networking: `-netdev user`
when the qemu build has it, otherwise `passt`; host(container) 2222→22 and 8080→80.
Wait for SSH then `cloud-init status --wait` (180 s). Teardown: `poweroff`, delete
overlay. `KEEP=1`: rig stays as container `oxpanel-acceptance-vm` with the two ports
published; the report prints the `ssh -i … -p 2222 root@127.0.0.1` line.

## CI

Job `acceptance`: pushes to `main`, nightly, and manual dispatch — not pull
requests. Enables `/dev/kvm` on the runner with the documented udev rule, runs
`make acceptance`, uploads `dist/acceptance` as a build artifact. Required before a
release tag.

## Out of scope (later packages)

Feature-ID traceability (B); fuzzing, real kill-during-`useradd`, concurrency and
coverage (C); the manual QA plan (D); GPG verification of the image checksum file;
multi-node or upgrade-from-previous-version testing.

## Results of the first runs (2026-09-22)

The rig was built and run the same day. Every phase now passes in RPM mode on
AlmaLinux 9.8 with SELinux enforcing (≈200 checks, ≈90 s of VM time after a
17 s boot). It found five defects that the container-based suite could not:

| # | Found by | Defect | Fix |
|---|---|---|---|
| 1 | phase 10 | Unit failed at `NAMESPACE`: `ReadWritePaths=-/var/lib/selinux` asks systemd to mount on `semanage_store_t`, a SELinux *security* file type that `init_t` may not mount on | list the parent `/var/lib` instead |
| 2 | phase 10 | `nginx -t` inside the sandbox fails: nginx opens `/var/log/nginx/error.log` even in test mode and `/var/log` is read-only under `ProtectSystem=strict` | add `/var/log/nginx` to `ReadWritePaths` |
| 3 | phase 20 | Sites returned 403: the docroot ended up `httpd_user_content_t`. `file_contexts.homedirs` overrides any local `semanage fcontext` rule under `/home`; the policy creates `~/public_html` with that type by named transition; and the type is *customizable*, so plain `restorecon` leaves it alone | use a path **equivalence** (`semanage fcontext -a -e /usr/share/nginx/html <docroot>`), `restorecon -RF`, set `httpd_enable_homedirs` + `httpd_read_user_content` in `%post` and the handbook, check them in preflight |
| 4 | phase 50 | After a resumed provisioning the site returned 403: the home-mode repair saw `0710` (ACL mask in the group bits) and `chmod 0700` wiped the web server's ACL grant | repair only owner/other/special bits; leave the group bits (the mask) alone |
| 5 | phase 70 | `oxpanel-ctl` panicked with "Broken pipe" when its reader closed early (`… \| head`) | write through a helper that exits quietly on `EPIPE` |

Test-data mistakes fixed along the way: two-character tenant names, dashed
tenant names queried by their unescaped unit name, `ls -A` on two directories,
`grep -q` on multi-line output under `pipefail`.

Not verified by the rig (still true): nothing about multi-node setups, upgrades
from a previous version, or GPG verification of the image checksum.
