//! A platform fix for the app's own webview: WebKitGTK 2.52 segfaults on a
//! page change when NVIDIA's EGL draws the window (Linux, the NVIDIA driver
//! loaded; seen in three apps and in WebKit's own MiniBrowser, 2026-10).
//!
//! The fix is a pair of environment variables set before the webview
//! starts: Mesa's EGL vendor file, and WebKit's GBM path off. Mesa's EGL
//! alone aborts at startup on a machine whose only GPU is NVIDIA ("Could not
//! create GBM EGL display"); the pair works on NVIDIA-only machines, Optimus
//! laptops and machines without NVIDIA alike.
//!
//! Call [`apply`] first thing in `main`, before any thread starts (it sets
//! process environment variables). Nothing is set when the person set either
//! variable themselves, or set `FLOWSTA_WEBVIEW_FIX=0`. Sidecars spawned
//! through [`crate::process::SidecarCommand`] never inherit what was set
//! here: the fix is for the webview only.

use std::path::PathBuf;
use std::sync::OnceLock;

/// The EGL vendor selection variable (libglvnd).
pub const EGL_VENDOR_VAR: &str = "__EGL_VENDOR_LIBRARY_FILENAMES";
/// WebKitGTK's switch for the GBM buffer path of its DMA-BUF renderer.
pub const DISABLE_GBM_VAR: &str = "WEBKIT_DMABUF_RENDERER_DISABLE_GBM";
/// `0` turns the fix off.
pub const OPT_OUT_VAR: &str = "FLOWSTA_WEBVIEW_FIX";

/// Where distributions install Mesa's EGL vendor file, most common first.
pub const MESA_VENDOR_FILES: &[&str] = &[
    "/usr/share/glvnd/egl_vendor.d/50_mesa.json",
    "/etc/glvnd/egl_vendor.d/50_mesa.json",
];

/// What the machine looks like, as far as the fix cares.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Facts {
    /// The NVIDIA kernel driver is loaded.
    pub nvidia_loaded: bool,
    /// The person set [`EGL_VENDOR_VAR`] themselves.
    pub egl_vendor_set: bool,
    /// The person set [`DISABLE_GBM_VAR`] themselves.
    pub disable_gbm_set: bool,
    /// [`OPT_OUT_VAR`] is `0`.
    pub opted_out: bool,
    /// Mesa's EGL vendor file, when one exists.
    pub mesa_vendor_file: Option<PathBuf>,
}

/// What [`apply`] did, for the app to log once its logger is up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Both variables set.
    Applied { mesa_vendor_file: PathBuf },
    /// Nothing set, and why.
    Skipped(&'static str),
}

/// The decision, from the facts alone.
pub fn decide(f: &Facts) -> Outcome {
    if f.opted_out {
        return Outcome::Skipped("turned off with FLOWSTA_WEBVIEW_FIX=0");
    }
    if !f.nvidia_loaded {
        return Outcome::Skipped("the NVIDIA driver is not loaded");
    }
    if f.egl_vendor_set || f.disable_gbm_set {
        return Outcome::Skipped("the EGL or WebKit renderer variables are already set");
    }
    match &f.mesa_vendor_file {
        // Never one variable without the other: Mesa's EGL alone aborts on an
        // NVIDIA-only machine, and GBM off alone does not avoid the crash.
        None => Outcome::Skipped("Mesa's EGL vendor file is not installed"),
        Some(p) => Outcome::Applied { mesa_vendor_file: p.clone() },
    }
}

static SET_HERE: OnceLock<Vec<&'static str>> = OnceLock::new();

/// The variables [`apply`] set in this process (empty when it set none or
/// was not called). Sidecar spawns remove them from the child.
pub fn set_here() -> &'static [&'static str] {
    SET_HERE.get().map(Vec::as_slice).unwrap_or(&[])
}

/// Read the facts and set the pair when they call for it. Linux only; a
/// no-op elsewhere. Call before any thread starts.
pub fn apply() -> Outcome {
    #[cfg(target_os = "linux")]
    {
        use std::path::Path;
        let facts = Facts {
            nvidia_loaded: Path::new("/proc/driver/nvidia/version").exists() || Path::new("/sys/module/nvidia").exists(),
            egl_vendor_set: std::env::var_os(EGL_VENDOR_VAR).is_some(),
            disable_gbm_set: std::env::var_os(DISABLE_GBM_VAR).is_some(),
            opted_out: std::env::var_os(OPT_OUT_VAR).as_deref() == Some(std::ffi::OsStr::new("0")),
            mesa_vendor_file: MESA_VENDOR_FILES.iter().map(PathBuf::from).find(|p| p.is_file()),
        };
        let outcome = decide(&facts);
        if let Outcome::Applied { mesa_vendor_file } = &outcome {
            std::env::set_var(EGL_VENDOR_VAR, mesa_vendor_file.as_os_str());
            std::env::set_var(DISABLE_GBM_VAR, "1");
            let _ = SET_HERE.set(vec![EGL_VENDOR_VAR, DISABLE_GBM_VAR]);
        }
        outcome
    }
    #[cfg(not(target_os = "linux"))]
    {
        Outcome::Skipped("not Linux")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nvidia() -> Facts {
        Facts { nvidia_loaded: true, mesa_vendor_file: Some(PathBuf::from(MESA_VENDOR_FILES[0])), ..Facts::default() }
    }

    #[test]
    fn applies_with_nvidia_and_mesa() {
        assert_eq!(decide(&nvidia()), Outcome::Applied { mesa_vendor_file: PathBuf::from(MESA_VENDOR_FILES[0]) });
    }

    #[test]
    fn skips_without_the_nvidia_driver() {
        assert!(matches!(decide(&Facts { nvidia_loaded: false, ..nvidia() }), Outcome::Skipped(_)));
    }

    #[test]
    fn never_overrides_the_persons_own_settings() {
        assert!(matches!(decide(&Facts { egl_vendor_set: true, ..nvidia() }), Outcome::Skipped(_)));
        assert!(matches!(decide(&Facts { disable_gbm_set: true, ..nvidia() }), Outcome::Skipped(_)));
    }

    #[test]
    fn opt_out_wins() {
        assert!(matches!(decide(&Facts { opted_out: true, ..nvidia() }), Outcome::Skipped(_)));
    }

    #[test]
    fn never_half_the_pair() {
        // Without Mesa's vendor file nothing is set, not even GBM off.
        assert!(matches!(decide(&Facts { mesa_vendor_file: None, ..nvidia() }), Outcome::Skipped(_)));
    }

    #[test]
    fn nothing_recorded_when_not_applied() {
        assert!(set_here().is_empty());
    }
}
