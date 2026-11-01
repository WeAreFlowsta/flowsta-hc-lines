//! Finding a sidecar binary.

use crate::{Error, Result};
use std::path::{Path, PathBuf};

/// The target triple this library (and so the app) was built for.
pub const TARGET_TRIPLE: &str = env!("HC_LINES_TARGET_TRIPLE");

/// Where an app's sidecar binaries can be found.
#[derive(Clone, Debug, Default)]
pub struct SidecarSource {
    /// The app's development binaries folder (`src-tauri/binaries` in a
    /// Tauri app), searched in a dev build for exactly `<name>-<triple>`.
    /// The app passes it: inside a library, `CARGO_MANIFEST_DIR` and
    /// `debug_assertions` describe the library, not the app.
    pub dev_dir: Option<PathBuf>,
    /// The folder of the app's executable, where bundlers install sidecars.
    /// `None` = the running executable's folder.
    pub exe_dir: Option<PathBuf>,
    /// Folders of kits restored from the cache (`kit::RestoredKit::dir`),
    /// searched after the app's own folder for `<name>` as bundled.
    pub kit_dirs: Vec<PathBuf>,
    /// Fall back to a bare name for the system PATH. Off in release builds:
    /// a missing sidecar is an error that says where it looked.
    pub allow_path_lookup: bool,
}

/// Find the sidecar `name` (the file name the app's bundle gives it,
/// without a target triple or `.exe`).
pub fn resolve_sidecar(name: &str, source: &SidecarSource) -> Result<PathBuf> {
    let mut searched = Vec::new();
    if let Some(dev) = &source.dev_dir {
        let exact = dev.join(format!("{}-{}{}", name, TARGET_TRIPLE, exe_suffix()));
        if exact.exists() {
            return Ok(exact);
        }
        searched.push(exact);
    }
    let exe_dir = source.exe_dir.clone().or_else(|| std::env::current_exe().ok().and_then(|e| e.parent().map(Path::to_path_buf)));
    if let Some(dir) = exe_dir {
        let candidate = dir.join(format!("{}{}", name, exe_suffix()));
        if candidate.exists() {
            return Ok(candidate);
        }
        searched.push(candidate);
    }
    for dir in &source.kit_dirs {
        let candidate = dir.join(format!("{}{}", name, exe_suffix()));
        if candidate.exists() {
            return Ok(candidate);
        }
        searched.push(candidate);
    }
    if source.allow_path_lookup {
        return Ok(PathBuf::from(name));
    }
    Err(Error::SidecarMissing { name: name.to_string(), searched })
}

pub(crate) fn exe_suffix() -> &'static str {
    if cfg!(target_os = "windows") {
        ".exe"
    } else {
        ""
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dev_build_finds_its_exact_triple_never_the_other_line() {
        let dir = std::env::temp_dir().join(format!("hclines-sidecar-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let s = exe_suffix();
        std::fs::write(dir.join(format!("app-holochain-07-{}{}", TARGET_TRIPLE, s)), b"").unwrap();
        let src = SidecarSource { dev_dir: Some(dir.clone()), exe_dir: Some(dir.join("none")), kit_dirs: Vec::new(), allow_path_lookup: false };
        assert!(resolve_sidecar("app-holochain", &src).is_err(), "the 0.7 file is not the 0.6 sidecar");
        std::fs::write(dir.join(format!("app-holochain-{}{}", TARGET_TRIPLE, s)), b"").unwrap();
        assert_eq!(resolve_sidecar("app-holochain", &src).unwrap(), dir.join(format!("app-holochain-{}{}", TARGET_TRIPLE, s)));
        assert_eq!(resolve_sidecar("app-holochain-07", &src).unwrap(), dir.join(format!("app-holochain-07-{}{}", TARGET_TRIPLE, s)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_sidecar_says_where_it_looked() {
        let src = SidecarSource { dev_dir: Some("/nonexistent/dev".into()), exe_dir: Some("/nonexistent/exe".into()), kit_dirs: vec!["/nonexistent/kit".into()], allow_path_lookup: false };
        let e = resolve_sidecar("app-lair", &src).unwrap_err().to_string();
        assert!(e.contains("app-lair") && e.contains("/nonexistent/dev") && e.contains("/nonexistent/exe") && e.contains("/nonexistent/kit"), "{e}");
        let open = SidecarSource { allow_path_lookup: true, ..src };
        assert_eq!(resolve_sidecar("app-lair", &open).unwrap(), PathBuf::from("app-lair"));
    }
}
