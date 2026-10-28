//! Stamps the source revision into security.txt (lib.rs): SOURCE_REVISION when set, else
//! GITHUB_SHA (a GitHub Actions build), else empty. Nothing else in the program reads it, so an
//! unset revision changes only the security.txt bytes.

fn main() {
    let revision = std::env::var("SOURCE_REVISION")
        .or_else(|_| std::env::var("GITHUB_SHA"))
        .unwrap_or_default();
    // A revision is a hex commit id: anything else would land in the program's bytes as is.
    let revision = if revision.chars().all(|c| c.is_ascii_hexdigit()) {
        revision
    } else {
        String::new()
    };
    println!("cargo:rustc-env=PRIZE_ESCROW_SOURCE_REVISION={revision}");
    println!("cargo:rerun-if-env-changed=SOURCE_REVISION");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
}
