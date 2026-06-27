/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Shared protobuf contract for open-ssm-agent.
//!
//! One IDL system-wide (AD-6): the generated types are used at both edges —
//! operator↔coordinator (gRPC) and coordinator↔agent (protobuf bytes in the
//! MQTT payload). This crate sits at the root of the dependency direction
//! invariant (AD-26): `osa-core` depends only on it, and it depends on no other
//! workspace crate.

pub mod v1 {
    tonic::include_proto!("osa.v1");
}
