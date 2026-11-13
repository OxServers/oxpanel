//! OxPanel system engine.
//!
//! A root-privileged daemon that provisions isolated hosting tenants on
//! AlmaLinux 9 and exposes the operations over gRPC on an authenticated
//! UNIX-domain socket. See `CLAUDE.md` for the security invariants this crate
//! enforces and `packaging/` for how it is deployed.
//!
//! Module map:
//! - [`validate`] — allow-list validation of every API input.
//! - [`system`]   — the only place that spawns processes or looks up accounts;
//!   [`system::RealSystem`] for production, [`system::FakeSystem`] for tests.
//! - [`fsutil`]   — atomic file writes and permission checks.
//! - [`records`]  — on-disk state (`/var/lib/oxpanel`) that marks what OxPanel owns.
//! - [`tenant`], [`vhost`] — the provisioning workflows.
//! - [`php`]      — per-tenant PHP-FPM instances.
//! - [`app`]      — Node.js and Python applications behind virtual hosts.
//! - [`tls`]      — certificates of virtual hosts; [`acme`] obtains them from a
//!   certificate authority through a separate, unprivileged client;
//!   [`auto_https`] does so for every site by itself.
//! - [`sftp`]     — SFTP-only file access for tenants (sshd drop-in, keys, chroot).
//! - [`quota`]    — per-tenant disk quotas (XFS user quotas).
//! - [`db`]       — tenant databases and database users; one submodule per
//!   engine ([`db::mariadb`] is the only place that builds SQL or talks to
//!   the server).
//! - [`host`]     — host information and record ↔ OS reconciliation.
//! - [`auth`]     — peer-credential gate for the UNIX socket.
//! - [`server`]   — gRPC ↔ domain mapping.

#![cfg_attr(
    test,
    allow(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::field_reassign_with_default,
        clippy::needless_pass_by_value
    )
)]

pub mod acme;
pub mod app;
pub mod auth;
pub mod auto_https;
pub mod config;
pub mod ctx;
pub mod db;
pub mod error;
pub mod fsutil;
pub mod host;
pub mod nginx;
pub mod php;
pub mod quota;
pub mod records;
pub mod server;
pub mod sftp;
pub mod system;
pub mod systemd;
pub mod tenant;
pub mod tls;
pub mod validate;
pub mod vhost;

/// Property tests of crate-private parsers (the public ones are covered by
/// `tests/properties.rs`).
#[cfg(test)]
mod proptests;

pub use error::{Error, Result};
/// Generated API types (re-exported from `oxpanel-proto`).
pub use oxpanel_proto as proto;
