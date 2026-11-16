# Releasing OxPanel

How a release is made: the engine (this repository, Apache-2.0) and the panel
(the console repository, proprietary) are released together, as one bundle.
Nothing here pushes, tags or uploads by itself; every step is run by hand.

## 1. Gates

Run every gate on the exact commits that will be tagged, and keep the results.
A gate that cannot be made green is a reason not to release, never a reason to
weaken a check.

Engine (this repository):

| Gate | Command | What it proves |
|---|---|---|
| Static and unit | `make check` | fmt, clippy pedantic `-D warnings`, tests, cargo-deny, traceability, shellcheck of `install.sh` |
| Integration | `make integration` | the RPM's files in a systemd container: every RPC end to end, Nginx, PHP, apps, ACME against a local Pebble |
| Real host | `INSTALL=rpm make acceptance` | an AlmaLinux 9 VM with SELinux enforcing: install, quotas, mail, integration on the host, SELinux (zero AVC denials), sandbox, resume, reboot, soak, attacks, performance |
| Installer | `INSTALL=installer VM_MEM=4096 make acceptance` | `install.sh` from the release bundle, all options (phase 17), uninstall |
| Upgrade | `INSTALL=upgrade OLD_REF=<previous tag> make acceptance` | the previous release installed by hand, then upgraded by `install.sh`; tenants, sites, mail and limits survive |
| Upgrade with the panel | `INSTALL=upgrade OLD_REF=<previous tag> PANEL_RPM=<new panel RPM> OLD_PANEL_RPM=<previous panel RPM> make acceptance` | the same, with the panel upgraded by the bundle (and a panel certificate installed by hand before) |
| Product | `INSTALL=product VM_MEM=4096 PANEL_RPM=<panel RPM> make acceptance` | engine and panel installed by `install.sh`, the product driven through the panel's HTTPS API (phase 25) |

Each acceptance run writes `dist/acceptance/<UTC time>/report.md` (phases,
counts, AVC denials) with the logs beside it; `dist/acceptance/latest` points at
the newest. Only one acceptance VM can exist at a time.

Panel (console repository): its `make check`, `make e2e`, `make ui-check`,
`make ui-e2e`, `make setup-test`, `make shellcheck`, `make rpm`, `make rpmlint`
and the UI bundle budgets.

## 2. Verify before tagging

- The versions agree: `Cargo.toml` (`workspace.package.version`),
  `packaging/oxpanel-daemon.spec`, `INSTALLER_VERSION` in `install.sh`, the
  version in `docs/FEATURES.md` and `docs/HANDBOOK.md`; the panel's spec
  requires the engine version it was tested with (`Requires: oxpanel-daemon >= …`).
- `docs/HANDBOOK.md` has the upgrade notes for this version (section 12).
- The working trees are clean and the gate reports name these commits.

## 3. Tag both repositories

Fast-forward each repository's `main` to the tested commit (no merge commit,
so the tag is on exactly what was tested), then tag it:

```sh
git checkout main && git merge --ff-only <tested branch>
git tag -a vX.Y.Z -m "OxPanel engine X.Y.Z"
```

The panel gets its own tag (its own version) in the console repository.

## 4. The bundle

```sh
make dist PANEL_RPM=/path/to/oxpanel-panel-<version>.el9.x86_64.rpm
cd dist/release && sha256sum -c SHA256SUMS
```

`dist/release/` then holds the engine RPM, the panel RPM, `install.sh`, the
handbook, the licence and `SHA256SUMS` over all of them. Sign the packages as
`docs/SIGNING.md` describes before the bundle leaves the build machine.

The panel RPM is **not published** while the console is private: the bundle with
the panel goes only to hosts the operator installs. A public engine release is
the bundle without `PANEL_RPM` (or the engine RPM with `install.sh`).

## 5. Upgrading a server

Copy the new bundle to the server and run its `install.sh` **with the same
options the server was installed with** (an answers file keeps them):

```sh
sudo ./install.sh --yes <the same options as before>
```

The installer upgrades the engine and, when the bundle has a newer one, the
panel, keeps every record and setting, and says what it changed
(`RESULT: ok changes=N`). Read the version's upgrade notes in
`docs/HANDBOOK.md` section 12 first.

## 6. Build environment

The host needs no toolchain: everything builds in podman containers.

| Variable | Meaning |
|---|---|
| `OXPANEL_DEV_IMAGE` | the build/test image (`tests-integration/Containerfile`) |
| `OXPANEL_TARGET_VOLUME` | the cargo target volume of this tree |
| `OXPANEL_OLD_TARGET_VOLUME` | the target volume `make rpm-old` uses for the previous release |
| `OXPANEL_RIG_IMAGE` | the acceptance rig image (`tests-acceptance/Containerfile`) |

The acceptance rig also reads `INSTALL`, `PHASES`, `KEEP`, `CONTINUE`,
`VM_MEM`, `VM_CPUS`, `OLD_REF`, `PANEL_RPM` and `OLD_PANEL_RPM` (see
`scripts/acceptance.sh`).
