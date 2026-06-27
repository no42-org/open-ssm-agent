/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Domain core for open-ssm-agent — state machines and ports (traits), no I/O.
//!
//! This crate is the hexagon: it defines the domain types and the port traits
//! that every adapter implements, and it **never depends on an adapter or a
//! bin** (AD-26). It depends only on [`osa_proto`]. Wiring of concrete adapters
//! happens in the bins via constructor injection.

pub mod audit;
pub mod auth;
pub mod domain;
pub mod ports;
pub mod seal;
pub mod stream;
pub mod topics;

pub use domain::{HostId, JobId, Sid};
