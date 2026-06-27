/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

// Generates Rust types + the gRPC Operator service from the single IDL (AD-6).
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/osa.proto");
    tonic_prost_build::configure().compile_protos(&["proto/osa.proto"], &["proto"])?;
    Ok(())
}
