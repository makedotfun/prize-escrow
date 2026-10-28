//! The program bytes the Rust tests run: the release build at chain/target/deploy/prize_escrow.so
//! (scripts/chain/build.ts RELEASE_SO), read from disk the first time a test asks for it, never
//! embedded at compile time. An `include_bytes!` of it was only as fresh as cargo's mtime check:
//! a .so pair restored with `cp -p` (or `cp -c`) keeps its source's older mtime, so the test
//! binaries stayed "fresh" and ran whatever bytes they embedded at their last compile (#757 P2-2).
//!
//! - PRIZE_ESCROW_SO, when set, names another file to load (a cached pair under review).
//! - PRIZE_ESCROW_SO_SHA256, when set, is the sha256 (hex) the bytes must have: the land gate sets
//!   it from the pair being landed (its SHA256SUMS, or the release build's provenance record), and
//!   every test that loads the program then fails on any other bytes.
//!
//! Each test binary writes one line to stderr naming the file and its sha256, past libtest's
//! output capture, so a run's log records which bytes it tested.

use std::{io::Write, path::PathBuf, sync::OnceLock};

/// Where the release build lands: chain/target/deploy/prize_escrow.so.
pub const RELEASE_SO: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/deploy/prize_escrow.so"
);

/// The file the tests load: PRIZE_ESCROW_SO, or RELEASE_SO.
pub fn path() -> PathBuf {
    match std::env::var("PRIZE_ESCROW_SO") {
        Ok(path) if !path.trim().is_empty() => PathBuf::from(path.trim()),
        _ => PathBuf::from(RELEASE_SO),
    }
}

/// The sha256 the bytes must have (PRIZE_ESCROW_SO_SHA256, lowercased), or None when unset.
pub fn pinned_sha256() -> Option<String> {
    std::env::var("PRIZE_ESCROW_SO_SHA256")
        .ok()
        .map(|sha| sha.trim().to_ascii_lowercase())
        .filter(|sha| !sha.is_empty())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    solana_sha256_hasher::hash(bytes)
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Whether `bytes` match the pin `expected` (a 64-digit hex sha256); every bytes do with no pin.
pub fn check(bytes: &[u8], expected: Option<&str>) -> Result<String, String> {
    let actual = sha256_hex(bytes);
    let Some(expected) = expected else {
        return Ok(actual);
    };
    if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "PRIZE_ESCROW_SO_SHA256 {expected:?} is not a sha256 (64 hex digits)"
        ));
    }
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(format!(
            "its sha256 is {actual}, not the pinned PRIZE_ESCROW_SO_SHA256 {expected}: these are not the bytes being landed"
        ));
    }
    Ok(actual)
}

/// The program's bytes, read once per test binary from path() and held to the pin; panics (so
/// every test that loads them fails) when the file is missing or the pin differs.
pub fn bytes() -> &'static [u8] {
    static SO: OnceLock<Vec<u8>> = OnceLock::new();
    SO.get_or_init(|| {
        let path = path();
        let bytes = std::fs::read(&path).unwrap_or_else(|e| {
            panic!(
                "{}: {e}: build it with `node scripts/chain/build.ts release`, or name the pair under test with PRIZE_ESCROW_SO",
                path.display()
            )
        });
        let pin = pinned_sha256();
        match check(&bytes, pin.as_deref()) {
            Ok(sha) => {
                let pinned = if pin.is_some() {
                    "= PRIZE_ESCROW_SO_SHA256"
                } else {
                    "(PRIZE_ESCROW_SO_SHA256 unset: not pinned)"
                };
                // Straight to the process's stderr: libtest captures eprintln! of a passing test.
                let _ = writeln!(
                    std::io::stderr(),
                    "prize_escrow.so {} ({} bytes) sha256 {sha} {pinned}",
                    path.display(),
                    bytes.len()
                );
            }
            Err(e) => panic!("{}: {e}", path.display()),
        }
        bytes
    })
}
