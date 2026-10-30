fn main() {
    // The target triple, so a dev build finds `<name>-<triple>` exactly
    // among the app's sidecar binaries (a prefix match confused
    // `x-holochain-` with `x-holochain-07-`).
    if let Ok(t) = std::env::var("TARGET") {
        println!("cargo:rustc-env=HC_LINES_TARGET_TRIPLE={}", t);
    }
}
