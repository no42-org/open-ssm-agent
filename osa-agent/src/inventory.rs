/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Agent-side inventory collectors (AD-15, AD-16; story 5.1).
//!
//! Gather a host's observed facts into a structured [`Inventory`] snapshot:
//! the DMI serial (the NetBox match key, AD-16), core system facts (hostname,
//! OS, kernel, CPU, memory) and network interfaces. System/network facts come
//! from `sysinfo`; the DMI serial is read straight from Linux `sysfs`.
//!
//! Collection is **best-effort and never panics**: a fact that cannot be read is
//! recorded as a typed [`Gap`] and the rest of the snapshot is still produced.
//! The DMI serial in particular is often absent (a VM/container, or a root-only
//! sysfs) or a meaningless OEM placeholder — either way it becomes `None` plus a
//! gap, so the coordinator can refuse to match on an absent serial (AD-16) rather
//! than a collector crashing the whole report.
//!
//! # Scope (5.1)
//! This is agent-local collection only. Shipping the snapshot up the channel (as
//! an `osa-proto` message) and the coordinator's NetBox `InventorySink` land in
//! stories 5.2 / 5.3. [`collect`] does **blocking** filesystem/syscall work, so
//! the reporting wiring (5.3) must call it via `spawn_blocking` rather than on an
//! async worker. Interface/field scoping for NetBox is the sink's job (AD-16), so
//! collection here is deliberately unfiltered.

use std::net::IpAddr;
use std::path::Path;

use sysinfo::{Networks, System};

/// Where the Linux kernel exposes DMI/SMBIOS identifiers.
const DMI_ID_DIR: &str = "/sys/class/dmi/id";

/// DMI id files to try, in order, for the hardware serial. `product_serial` is
/// the system serial; `board_serial` is the motherboard's — a reasonable fallback
/// when the product serial is absent or a placeholder.
const DMI_SERIAL_FILES: [&str; 2] = ["product_serial", "board_serial"];

/// Case-insensitive DMI values that mean "no real serial" — many boards ship
/// these strings instead of leaving the field empty.
const SERIAL_PLACEHOLDERS: &[&str] = &[
    "none",
    "not specified",
    "not applicable",
    "to be filled by o.e.m.",
    "system serial number",
    "default string",
    "na",
    "n/a",
    "0",
];

/// A structured snapshot of a host's observed facts (AD-15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    /// The DMI hardware serial — the NetBox match key (AD-16). `None` when the
    /// host exposes no usable serial; the coordinator refuses to match on an
    /// absent serial rather than clobbering the wrong device.
    pub dmi_serial: Option<String>,
    pub system: SystemInfo,
    pub interfaces: Vec<NetworkInterface>,
    /// Facts that could not be collected — reported, never fatal.
    pub gaps: Vec<Gap>,
}

/// Core system facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemInfo {
    pub hostname: String,
    /// Human-readable OS description, e.g. `"Ubuntu 22.04.3 LTS"`.
    pub os: String,
    pub kernel: String,
    /// Logical CPU count.
    pub cpu_count: usize,
    /// Total physical memory, in bytes.
    pub memory_bytes: u64,
}

/// One network interface and its addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkInterface {
    pub name: String,
    pub mac: String,
    pub ips: Vec<IpAddr>,
}

/// Which fact a [`Gap`] is about — a closed set so a consumer (5.2) can branch
/// exhaustively rather than string-match, matching the codebase's typed-discriminant
/// style.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GapField {
    DmiSerial,
    Hostname,
    Os,
    Kernel,
    CpuCount,
    MemoryBytes,
    Interfaces,
}

impl GapField {
    /// Stable label for logs / operator-facing output.
    pub fn as_str(self) -> &'static str {
        match self {
            GapField::DmiSerial => "dmi_serial",
            GapField::Hostname => "hostname",
            GapField::Os => "os",
            GapField::Kernel => "kernel",
            GapField::CpuCount => "cpu_count",
            GapField::MemoryBytes => "memory_bytes",
            GapField::Interfaces => "interfaces",
        }
    }
}

/// A fact that collection could not obtain. Typed so a caller can reason about
/// which attribute is missing and why, without a panic or a lost snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    /// The missing fact.
    pub field: GapField,
    /// Why it is missing, for operator diagnostics.
    pub reason: String,
}

/// Collect a full inventory snapshot for this host.
pub fn collect() -> Inventory {
    let mut gaps = Vec::new();
    let dmi_serial = read_dmi_serial(Path::new(DMI_ID_DIR), &mut gaps);
    let system = collect_system(&mut gaps);
    let interfaces = collect_interfaces();
    // Every host has at least a loopback; an empty enumeration means collection
    // was blocked (a restricted network namespace), not "genuinely none".
    if interfaces.is_empty() {
        gaps.push(Gap {
            field: GapField::Interfaces,
            reason: "no network interfaces enumerated".to_string(),
        });
    }
    Inventory {
        dmi_serial,
        system,
        interfaces,
        gaps,
    }
}

/// Read the DMI serial from `dmi_id_dir`, trying each [`DMI_SERIAL_FILES`] source
/// and normalizing away placeholders. Returns `None` and pushes a typed [`Gap`]
/// when no usable serial is found — a missing serial is never an error here.
fn read_dmi_serial(dmi_id_dir: &Path, gaps: &mut Vec<Gap>) -> Option<String> {
    // Keep the most actionable reason across the sources, not just the last:
    // a read error (a real serial likely exists but needs root) outranks a
    // placeholder, which outranks the default "not present". Rank: 2 > 1 > 0.
    let mut reason =
        "no product_serial/board_serial in sysfs (VM, container, or non-Linux host)".to_string();
    let mut rank = 0u8;
    for file in DMI_SERIAL_FILES {
        match std::fs::read_to_string(dmi_id_dir.join(file)) {
            Ok(raw) => match normalize_serial(&raw) {
                Some(serial) => return Some(serial),
                // Present but empty or a placeholder — remember why, try the next.
                None if rank < 1 => {
                    reason = format!("{file} holds only an empty/placeholder value");
                    rank = 1;
                }
                None => {}
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            // Permission denied (root-only sysfs) or any other read error — the
            // most actionable signal, so it wins over a placeholder.
            Err(e) if rank < 2 => {
                reason = format!("{file} is not readable: {e}");
                rank = 2;
            }
            Err(_) => {}
        }
    }
    gaps.push(Gap {
        field: GapField::DmiSerial,
        reason,
    });
    None
}

/// Trim a raw DMI value and reject empties, well-known OEM placeholders, and
/// malformed values, returning the real serial or `None`. Some BIOSes NUL- or
/// whitespace-pad the field; an interior control byte means a corrupt read, which
/// must not become the (match-key) serial.
fn normalize_serial(raw: &str) -> Option<String> {
    let s = raw.trim_matches(|c: char| c.is_whitespace() || c.is_control());
    if s.is_empty()
        || s.chars().any(char::is_control)
        || SERIAL_PLACEHOLDERS.contains(&s.to_ascii_lowercase().as_str())
    {
        return None;
    }
    Some(s.to_string())
}

/// A string fact, or `""` plus a typed [`Gap`] when the host doesn't report it.
fn string_or_gap(value: Option<String>, field: GapField, gaps: &mut Vec<Gap>) -> String {
    value.unwrap_or_else(|| {
        gaps.push(Gap {
            field,
            reason: "not reported by the host".to_string(),
        });
        String::new()
    })
}

/// Collect core system facts. An unavailable field is recorded as a [`Gap`] and
/// left empty/zero rather than aborting the snapshot — including the numeric
/// facts, so a `0` CPU/memory reading is a reported gap, not a silent default.
fn collect_system(gaps: &mut Vec<Gap>) -> SystemInfo {
    let mut sys = System::new();
    sys.refresh_memory();
    sys.refresh_cpu_all();

    let hostname = string_or_gap(System::host_name(), GapField::Hostname, gaps);
    let os = string_or_gap(
        System::long_os_version().or_else(System::name),
        GapField::Os,
        gaps,
    );
    let kernel = string_or_gap(System::kernel_version(), GapField::Kernel, gaps);

    let cpu_count = sys.cpus().len();
    if cpu_count == 0 {
        gaps.push(Gap {
            field: GapField::CpuCount,
            reason: "no CPUs reported by the host".to_string(),
        });
    }
    let memory_bytes = sys.total_memory();
    if memory_bytes == 0 {
        gaps.push(Gap {
            field: GapField::MemoryBytes,
            reason: "no physical memory reported by the host".to_string(),
        });
    }

    SystemInfo {
        hostname,
        os,
        kernel,
        cpu_count,
        memory_bytes,
    }
}

/// Sort and de-duplicate an interface's addresses so the snapshot is stable
/// regardless of the OS enumeration order — AD-16 dedups NetBox writes on a
/// content hash, so an unchanged host must hash identically every cycle.
fn sorted_deduped(mut ips: Vec<IpAddr>) -> Vec<IpAddr> {
    ips.sort();
    ips.dedup();
    ips
}

/// Collect network interfaces, sorted by name (and by address within each) for a
/// deterministic snapshot.
fn collect_interfaces() -> Vec<NetworkInterface> {
    let networks = Networks::new_with_refreshed_list();
    let mut interfaces: Vec<NetworkInterface> = networks
        .iter()
        .map(|(name, data)| NetworkInterface {
            name: name.clone(),
            mac: data.mac_address().to_string(),
            ips: sorted_deduped(data.ip_networks().iter().map(|n| n.addr).collect()),
        })
        .collect();
    interfaces.sort_by(|a, b| a.name.cmp(&b.name));
    interfaces
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dmi_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn normalize_serial_keeps_a_real_serial_and_rejects_junk() {
        assert_eq!(normalize_serial("  ABC123 \n"), Some("ABC123".to_string()));
        assert_eq!(normalize_serial(""), None);
        assert_eq!(normalize_serial("   \t\n"), None);
        // Placeholders are rejected case-insensitively.
        assert_eq!(normalize_serial("To Be Filled By O.E.M."), None);
        assert_eq!(normalize_serial("none"), None);
        assert_eq!(normalize_serial("Default string"), None);
        // BIOS NUL/whitespace padding is stripped; an interior control byte means
        // a corrupt read and must not become the match key.
        assert_eq!(normalize_serial("SN-7\0\0"), Some("SN-7".to_string()));
        assert_eq!(normalize_serial("AB\0CD"), None);
    }

    #[test]
    fn interface_addresses_are_sorted_and_deduped() {
        let a: IpAddr = "10.0.0.2".parse().unwrap();
        let b: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(sorted_deduped(vec![a, b, a]), vec![b, a]);
        assert_eq!(sorted_deduped(vec![]), Vec::<IpAddr>::new());
    }

    #[test]
    fn a_present_product_serial_is_read() {
        let dir = dmi_dir();
        std::fs::write(dir.path().join("product_serial"), "SN-42\n").unwrap();
        let mut gaps = Vec::new();
        assert_eq!(
            read_dmi_serial(dir.path(), &mut gaps),
            Some("SN-42".to_string())
        );
        assert!(gaps.is_empty(), "a real serial records no gap");
    }

    #[test]
    fn a_missing_serial_is_a_typed_gap_not_a_crash() {
        let dir = dmi_dir(); // empty: no dmi files at all
        let mut gaps = Vec::new();
        assert_eq!(read_dmi_serial(dir.path(), &mut gaps), None);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].field, GapField::DmiSerial);
        assert!(!gaps[0].reason.is_empty(), "the gap carries a reason");
    }

    #[test]
    fn a_placeholder_product_serial_falls_back_to_the_board_serial() {
        let dir = dmi_dir();
        std::fs::write(
            dir.path().join("product_serial"),
            "To be filled by O.E.M.\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("board_serial"), "BOARD-9\n").unwrap();
        let mut gaps = Vec::new();
        assert_eq!(
            read_dmi_serial(dir.path(), &mut gaps),
            Some("BOARD-9".to_string())
        );
        assert!(gaps.is_empty());
    }

    #[test]
    fn only_placeholder_serials_yield_a_gap() {
        let dir = dmi_dir();
        std::fs::write(dir.path().join("product_serial"), "None\n").unwrap();
        std::fs::write(dir.path().join("board_serial"), "Not Specified\n").unwrap();
        let mut gaps = Vec::new();
        assert_eq!(read_dmi_serial(dir.path(), &mut gaps), None);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].field, GapField::DmiSerial);
        assert!(
            gaps[0].reason.contains("placeholder"),
            "reason should note the placeholder: {}",
            gaps[0].reason
        );
    }

    #[test]
    fn collect_produces_a_plausible_snapshot_without_panicking() {
        // Runs against the real test host (macOS dev / Linux CI): we can't assert
        // exact values, but collection must never panic and must return plausible
        // core facts. The DMI serial is environment-dependent (usually absent or
        // root-only here), so it is asserted deterministically above, not here.
        let inv = collect();
        assert!(inv.system.cpu_count >= 1, "at least one logical CPU");
        assert!(inv.system.memory_bytes > 0, "some physical memory");
    }
}
