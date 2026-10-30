//! Small file helpers every app needs around its conductors.

use std::path::Path;

/// Write a file only this OS account can read (Unix mode 0600). The file
/// is replaced, not rewritten: a mode applies only when a file is created,
/// and one left by an earlier version may be readable by others. On Windows
/// an app's data folder is already private to the account.
pub fn write_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let _ = std::fs::remove_file(path);
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
        file.write_all(contents)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
    }
}

/// Write a file so a reader sees either the old contents or the new, never
/// half: write `<name>.tmp`, flush it to disk, rename it over the target.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut tmp_name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

/// The first `max_chars` characters of `text`, cut on a character boundary
/// (slicing bytes panics inside a multibyte character, which a conductor's
/// log can contain), with `...` when it was cut.
pub fn log_excerpt(text: &str, max_chars: usize) -> String {
    let trimmed = text.trim();
    match trimmed.char_indices().nth(max_chars) {
        Some((cut, _)) => format!("{}...", &trimmed[..cut]),
        None => trimmed.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_log_excerpt_never_cuts_inside_a_character() {
        assert_eq!(log_excerpt("  short  ", 10), "short");
        let s = "é".repeat(600);
        let e = log_excerpt(&s, 500);
        assert_eq!(e.chars().count(), 503);
        assert!(e.ends_with("..."));
    }

    #[test]
    fn private_and_atomic_writes() {
        let dir = std::env::temp_dir().join(format!("hclines-files-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("cfg.yaml");
        std::fs::write(&p, b"old").unwrap();
        write_private(&p, b"secret").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"secret");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let a = dir.join("state.json");
        write_atomic(&a, b"{}").unwrap();
        assert_eq!(std::fs::read(&a).unwrap(), b"{}");
        assert!(!dir.join("state.json.tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
