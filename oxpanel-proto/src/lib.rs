//! Generated gRPC types for the `oxpanel.v1` API.
//!
//! The schema lives in `proto/oxpanel/v1/panel.proto` at the repository root
//! and is compiled at build time with `protox` (pure Rust, no `protoc`).

#[allow(
    clippy::all,
    clippy::pedantic,
    unreachable_pub,
    missing_debug_implementations,
    rustdoc::all
)]
pub mod v1 {
    tonic::include_proto!("oxpanel.v1");
}

pub use prost_types::Timestamp;
