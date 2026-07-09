//! Build script: embeds the release version as `SOV_VERSION` for the daemon to
//! report over RPC (`sov_version` / `sov_getPeerInfo`).
// Bake a human-meaningful RELEASE version into the daemon so it can report it over
// RPC (`sov_version` / `sov_getPeerInfo`). The crate's own version is `0.0.0` — the
// real version is the git tag (e.g. `v0.1.79`), so prefer, in order:
//   1. $SOV_BUILD_VERSION  — an explicit override the release workflow can set,
//   2. `git describe --tags --always --dirty`  — the tag on a release checkout,
//   3. `v<CARGO_PKG_VERSION>`  — last-resort fallback.
use std::process::Command;

fn main() {
    let version = std::env::var("SOV_BUILD_VERSION")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            Command::new("git")
                .args(["describe", "--tags", "--always", "--dirty"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| format!("v{}", env!("CARGO_PKG_VERSION")));

    println!("cargo:rustc-env=SOV_VERSION={version}");
    println!("cargo:rerun-if-env-changed=SOV_BUILD_VERSION");
    // Refresh the embedded version when HEAD moves (repo root is three levels up).
    println!("cargo:rerun-if-changed=../../../.git/HEAD");
}
