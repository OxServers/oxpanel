# OxPanel

An open-core web-hosting control panel for enterprise Linux, built in Rust.

| Component | Directory | Status |
|---|---|---|
| **oxpanel-daemon** — the open-source system engine (root daemon, gRPC over UNIX socket) | [`oxpanel-daemon/`](oxpanel-daemon/) | tenants + Nginx virtual hosts working; see its README |
| **oxpanel-proto** — the API contract (`oxpanel.v1`) shared with every client | [`proto/`](proto/), [`oxpanel-proto/`](oxpanel-proto/) | v1 |
| **oxpanel-ctl** — admin CLI for the engine | [`oxpanel-ctl/`](oxpanel-ctl/) | working |
| panel-api / UI — proprietary layer (React + Go) | separate repository | — |

Target platform: **AlmaLinux 9** (RHEL 9 family), SELinux enforcing, systemd, Nginx.

```sh
make image        # one-time: AlmaLinux 9 build/test image (podman)
make check        # fmt + clippy (pedantic, -D warnings) + tests + cargo-deny
make integration  # root integration test in a systemd container on the real OS
```

Documentation: [feature list](docs/FEATURES.md) · [handbook — installation, configuration, operations](docs/HANDBOOK.md) · [engine README](oxpanel-daemon/README.md).

No host Rust toolchain is required — everything runs inside the target-OS container.
License: Apache-2.0 (see [LICENSE](LICENSE)).
