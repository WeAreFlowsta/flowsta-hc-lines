//! The one-time copy of the previous line's key store for the current
//! line's lair. Lair 0.7.1 opens a 0.6.3 store unchanged and signs with the
//! same keys, including seeds that cannot be exported; the copy only has to
//! carry every file and point its config at the new folder.

use super::{config_path, io, yaml_scalar, yaml_value, KeyStoreError, SocketPlan, CONFIG_FILE, STORE_FILES};
use crate::{Error, Result};
use std::path::{Path, PathBuf};

/// Written into a copied store: the source folder and the time of the copy.
pub const COPIED_FROM_FILE: &str = "copied-from";

/// A finished copy.
#[derive(Debug)]
pub struct CopiedStore {
    pub dir: PathBuf,
    /// The copy's connection URL. It carries the connection key: never log it.
    pub connection_url: String,
    /// Bytes of store data copied.
    pub bytes: u64,
}

/// Copy the store in `from` to `to` for another line's lair. The source is
/// only read.
///
/// - Refuses while the source's lair is running (its `pid_file` names a live
///   lair process): a running store may have writes not yet in its files.
///   The caller must also hold no child of its own for it.
/// - Never replaces a store at `to`, since there is no way to see what it
///   holds. An empty folder there is fine.
/// - Streams `store_file` with its `-wal` and `-shm` into new files. The
///   write-ahead log can hold most of the keys, so the main file alone
///   loses them.
/// - Rewrites the config: `storeFile` and `pidFile` into `to`, the socket
///   into `to` (or its short runtime path where that does not fit), or a new
///   Windows pipe. The connection key is kept.
/// - Refuses the copy when any config line still names the source, in any
///   spelling: two lairs on one store, or one socket, would each break the
///   other.
/// - Builds the copy in a temporary folder beside `to` and renames it into
///   place, so an interrupted copy leaves no half store at `to`.
pub fn copy_store(from: &Path, to: &Path, plan: &SocketPlan) -> Result<CopiedStore> {
    if to == from || to.starts_with(from) {
        return Err(KeyStoreError::Config { path: to.to_path_buf(), what: "the copy must be outside the source store".into() }.into());
    }
    if !config_path(from).exists() || !from.join(STORE_FILES[0]).exists() {
        return Err(KeyStoreError::Config { path: from.to_path_buf(), what: "no key store to copy".into() }.into());
    }
    if to.exists() {
        let empty = std::fs::read_dir(to).map_err(io("read the copy's folder", to))?.next().is_none();
        if !empty {
            return Err(KeyStoreError::DestinationExists(to.to_path_buf()).into());
        }
        std::fs::remove_dir(to).map_err(io("remove the copy's empty folder", to))?;
    }
    if source_running(from) {
        return Err(KeyStoreError::SourceRunning(from.to_path_buf()).into());
    }

    let parent = to.parent().ok_or_else(|| Error::from(KeyStoreError::Config { path: to.to_path_buf(), what: "no parent folder".into() }))?;
    let name = to.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let prefix = format!("{name}.copying-");
    remove_leftover_copies(parent, &prefix);
    let staging = parent.join(format!("{prefix}{}", std::process::id()));
    std::fs::create_dir_all(&staging).map_err(io("create the copy's folder", &staging))?;

    let result = (|| -> Result<CopiedStore> {
        let mut bytes = 0;
        for file in STORE_FILES {
            let src = from.join(file);
            if src.exists() {
                bytes += stream_copy(&src, &staging.join(file))?;
            }
        }
        let content = std::fs::read_to_string(config_path(from)).map_err(io("read the key store config", from))?;
        let (lines, connection_url) = rewrite_config(&content, to, plan)?;
        if let Some(key) = names_source(&lines, from) {
            return Err(KeyStoreError::CopyStillNamesSource { key }.into());
        }
        let staged_config = staging.join(CONFIG_FILE);
        crate::files::write_private(&staged_config, (lines.join("\n") + "\n").as_bytes())
            .map_err(io("write the copy's config", &staged_config))?;
        let stamp = format!("{}\n{}\n", from.display(), unix_secs());
        let staged_stamp = staging.join(COPIED_FROM_FILE);
        std::fs::write(&staged_stamp, stamp).map_err(io("write the copy's stamp", &staged_stamp))?;
        std::fs::rename(&staging, to).map_err(io("move the copy into place", to))?;
        Ok(CopiedStore { dir: to.to_path_buf(), connection_url, bytes })
    })();
    if result.is_err() && staging.exists() {
        let _ = std::fs::remove_dir_all(&staging);
    }
    if let Ok(copied) = &result {
        log::info!("[lair] key store copied from {:?} to {:?} ({} bytes)", from, to, copied.bytes);
    }
    result
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Remove `<prefix>*` folders in `parent`: copies this function started and
/// never finished.
fn remove_leftover_copies(parent: &Path, prefix: &str) {
    let Ok(entries) = std::fs::read_dir(parent) else { return };
    for entry in entries.flatten() {
        if entry.file_name().to_string_lossy().starts_with(prefix) && entry.path().is_dir() {
            log::info!("[lair] removing an unfinished copy {:?}", entry.path());
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// Whether the store's `pid_file` names a running lair. Lair leaves the file
/// behind even on a clean stop, so a pid alone proves nothing: the process
/// must be alive and be a lair.
fn source_running(from: &Path) -> bool {
    let mut files = vec![from.join("pid_file")];
    if let Ok(p) = super::read_key(from, "pidFile") {
        let p = PathBuf::from(p);
        if !files.contains(&p) {
            files.push(p);
        }
    }
    files.iter().any(|f| pid_file_names_live(f, |name| name.to_ascii_lowercase().contains("lair")))
}

fn pid_file_names_live(pid_file: &Path, is_lair: impl Fn(&str) -> bool) -> bool {
    let Ok(text) = std::fs::read_to_string(pid_file) else { return false };
    let Ok(pid) = text.trim().parse::<u32>() else { return false };
    let mut sys = sysinfo::System::new();
    let spid = sysinfo::Pid::from_u32(pid);
    sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[spid]), true);
    sys.process(spid).map(|p| is_lair(&p.name().to_string_lossy())).unwrap_or(false)
}

/// Copy `src` into a new file at `dst` by streaming the bytes: no
/// permissions, timestamps or extended attributes come along.
fn stream_copy(src: &Path, dst: &Path) -> Result<u64> {
    let mut input = std::fs::File::open(src).map_err(io("open a store file", src))?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(dst).map_err(io("create a store file", dst))?;
    let n = std::io::copy(&mut input, &mut output).map_err(io("copy a store file", dst))?;
    output.sync_all().map_err(io("flush a store file", dst))?;
    Ok(n)
}

/// The copy's config lines and connection URL.
fn rewrite_config(content: &str, to: &Path, plan: &SocketPlan) -> Result<(Vec<String>, String)> {
    let mut lines = Vec::new();
    let mut connection_url = None;
    for line in content.lines() {
        let trimmed = line.trim_start();
        let indent = &line[..line.len() - trimmed.len()];
        if let Some(rest) = trimmed.strip_prefix("connectionUrl:") {
            let url = copied_url(&yaml_value(rest), to, plan)?;
            lines.push(format!("{indent}connectionUrl: {url}"));
            connection_url = Some(url);
        } else if trimmed.starts_with("pidFile:") {
            lines.push(format!("{indent}pidFile: {}", yaml_scalar(&to.join("pid_file").to_string_lossy())));
        } else if trimmed.starts_with("storeFile:") {
            lines.push(format!("{indent}storeFile: {}", yaml_scalar(&to.join(STORE_FILES[0]).to_string_lossy())));
        } else {
            lines.push(line.to_string());
        }
    }
    let connection_url =
        connection_url.ok_or_else(|| Error::from(KeyStoreError::Config { path: to.to_path_buf(), what: "the source config has no connectionUrl".into() }))?;
    Ok((lines, connection_url))
}

/// The copy's connection URL: same connection key, its own socket or pipe.
fn copied_url(original: &str, to: &Path, plan: &SocketPlan) -> Result<String> {
    let scheme = original.split(':').next().unwrap_or_default();
    match scheme {
        #[cfg(not(windows))]
        "unix" => {
            let _ = plan;
            let in_folder = to.join("socket");
            let socket = if super::socket_fits(&in_folder) {
                in_folder
            } else {
                let short = super::runtime_socket_path(to, plan);
                if !super::socket_fits(&short) {
                    return Err(KeyStoreError::SocketTooLong(short).into());
                }
                if let Some(dir) = short.parent() {
                    std::fs::create_dir_all(dir).map_err(io("create the socket folder", dir))?;
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
                }
                short
            };
            Ok(super::unix_url_for(&socket, original))
        }
        "named-pipe" => {
            let _ = plan;
            let query = original.split_once('?').map(|(_, q)| format!("?{q}")).unwrap_or_default();
            Ok(format!("named-pipe:\\\\.\\pipe\\{}{}", pipe_name(to), query))
        }
        other => Err(KeyStoreError::Config { path: to.to_path_buf(), what: format!("unsupported connection scheme '{other}'") }.into()),
    }
}

/// A pipe name of the copy's own: lair names its pipes at random, and two
/// lairs on one name would fight over it.
fn pipe_name(to: &Path) -> String {
    use sha2::{Digest, Sha256};
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let mut h = Sha256::new();
    h.update(to.to_string_lossy().as_bytes());
    h.update(nanos.to_le_bytes());
    h.update(std::process::id().to_le_bytes());
    format!("lair-{}", &hex::encode(h.finalize())[..20])
}

/// The key of the first line that still names `source`, in any spelling:
/// as written, with either slash, with doubled backslashes, or
/// percent-encoded. A match counts only where the path ends (a separator,
/// a quote, the query, white space or the line's end), so a sibling such as
/// `lair-07` beside `lair` is not the source.
fn names_source(lines: &[String], source: &Path) -> Option<String> {
    let plain = source.to_string_lossy().into_owned();
    let mut spellings = vec![
        plain.clone(),
        plain.replace('\\', "/"),
        plain.replace('/', "\\"),
        plain.replace('\\', "\\\\"),
        plain.replace('/', "\\\\"),
    ];
    const KEEP: &percent_encoding::AsciiSet =
        &percent_encoding::NON_ALPHANUMERIC.remove(b'/').remove(b'.').remove(b'-').remove(b'_');
    for s in spellings.clone() {
        spellings.push(percent_encoding::utf8_percent_encode(&s, KEEP).to_string());
        spellings.push(s.replace(' ', "%20"));
    }
    let fold = |s: &str| if cfg!(windows) { s.to_lowercase() } else { s.to_string() };
    let spellings: Vec<String> = spellings.iter().map(|s| fold(s)).filter(|s| !s.is_empty()).collect();
    for line in lines {
        let hay = fold(line);
        for s in &spellings {
            let mut at = 0;
            while let Some(i) = hay[at..].find(s.as_str()) {
                let end = at + i + s.len();
                let rest = &hay[end..];
                let boundary = rest.is_empty()
                    || rest.starts_with(|c: char| "/\\?\"'".contains(c) || c.is_whitespace())
                    || rest.starts_with("%2f")
                    || rest.starts_with("%2F")
                    || rest.starts_with("%5c")
                    || rest.starts_with("%5C");
                if boundary {
                    // Only a plain key is named: a line can carry secrets.
                    let key = line.trim_start().split(':').next().unwrap_or("");
                    let plain = !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
                    return Some(if plain { key.to_string() } else { "a config line".into() });
                }
                at = end;
            }
        }
    }
    None
}

#[cfg(test)]
pub(super) fn pid_file_names_live_for_test(pid_file: &Path, is_lair: impl Fn(&str) -> bool) -> bool {
    pid_file_names_live(pid_file, is_lair)
}

#[cfg(test)]
pub(super) fn names_source_for_test(lines: &[String], source: &Path) -> Option<String> {
    names_source(lines, source)
}
