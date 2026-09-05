//! Generates the gRPC service and message types from `proto/oxpanel/v1/panel.proto`.
//!
//! `protox` compiles the schema in pure Rust, so no system `protoc` is needed.

use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("proto");
    let proto = proto_root.join("oxpanel").join("v1").join("panel.proto");
    println!("cargo:rerun-if-changed={}", proto.display());

    let fds = protox::compile([&proto], [&proto_root])?;
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_fds(fds)?;
    Ok(())
}
