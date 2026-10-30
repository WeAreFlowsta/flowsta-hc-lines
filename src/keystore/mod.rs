//! Lair key stores, one per line: start, wait, connect and seed import; the
//! one-time copy of the previous line's store; the conductor's database key
//! rewrap.
//!
//! A conductor accepts only a lair of its own version, so each line runs its
//! own key store. Both lines can hold the same agents in two ways:
//! - import one seed into each store under one tag ([`v06::import_seed`],
//!   [`v07::import_seed`]), so the key is the same on both lines;
//! - copy the previous line's store once for the current line's lair
//!   ([`copy_store`]). Lair 0.7.1 opens a 0.6.3 store unchanged, including
//!   seeds that cannot be exported.
//!
//! **`list_entries` is never called.** A lair connection carries at most
//! 8 KiB per message (0.6.3 and 0.7.1 alike), so listing a large store
//! aborts the connection. Keys are looked up by tag.
//!
//! A connection URL carries the store's connection key (`?k=`). Nothing here
//! logs it or puts it in an error.

mod client;
mod copy;
mod dbkey;

#[cfg(feature = "line-06")]
pub use client::v06;
#[cfg(feature = "line-07")]
pub use client::v07;
pub use copy::{copy_store, CopiedStore, COPIED_FROM_FILE};
pub use dbkey::{rekey_db_key, Rekeyed};

use crate::files::log_excerpt;
use crate::process::{SidecarChild, SidecarCommand};
use crate::{Error, Result};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Lair's config file inside a store folder.
pub const CONFIG_FILE: &str = "lair-keystore-config.yaml";
/// Lair's database, with SQLite's write-ahead log and its index. The log can
/// hold most of the keys (it is not folded into the main file for months
/// at a time), so the three always travel together.
pub const STORE_FILES: [&str; 3] = ["store_file", "store_file-wal", "store_file-shm"];

/// Key store errors. Developer text: the app words what a person sees.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeyStoreError {
    #[error("lair init failed (status {status}): {log_tail}")]
    InitFailed { status: std::process::ExitStatus, log_tail: String },
    /// Lair exited soon after starting. Lair checks its passphrase only after
    /// binding its socket, so a wrong passphrase shows up as this exit, never
    /// as a connect error.
    #[error("the key store stopped right after starting (status {status}): {log_tail}")]
    Stopped { status: std::process::ExitStatus, log_tail: String },
    #[error("the key store socket was not ready after {secs}s ({path})")]
    NotReady { secs: u64, path: PathBuf },
    #[error("the key store is running but did not answer within {secs} seconds")]
    ConnectTimeout { secs: u64 },
    #[error("could not connect to the key store: {0}")]
    Connect(String),
    #[error("the key store already holds a different key under '{tag}'")]
    TagHoldsOtherKey { tag: String },
    #[error("the key store derived a different key from the same seed")]
    DerivedKeyMismatch,
    #[error("the key store holds no key under '{tag}'")]
    KeyAbsent { tag: String },
    #[error("the key store at {} is still running", .0.display())]
    SourceRunning(PathBuf),
    #[error("a key store already exists at {}", .0.display())]
    DestinationExists(PathBuf),
    #[error("the copied key store config still names the original store ({key})")]
    CopyStillNamesSource { key: String },
    #[error("no socket path short enough for the key store ({})", .0.display())]
    SocketTooLong(PathBuf),
    #[error("key store config {}: {what}", .path.display())]
    Config { path: PathBuf, what: String },
    #[error("the conductor's database key at {} doesn't open with the current password", .0.display())]
    DbKeyWrongPassword(PathBuf),
    #[error("the conductor's database key at {} is malformed: {what}", .path.display())]
    DbKeyMalformed { path: PathBuf, what: String },
    /// A lair call failed for another reason; the text is lair's.
    #[error("key store call failed: {0}")]
    Lair(String),
}

/// Where a key store's socket goes when lair's default, inside the store's
/// own folder, is over the Unix-socket limit (macOS under
/// `~/Library/Application Support` with a longer name). Windows key stores
/// use named pipes, which have no such limit.
#[derive(Clone, Debug)]
pub struct SocketPlan {
    /// The per-user folder for short sockets: `$TMPDIR/<dir_name>` on macOS,
    /// `$XDG_RUNTIME_DIR/<dir_name>` on Linux, else `/tmp/<dir_name>-<uid>`.
    pub dir_name: String,
    /// The store folder whose short socket is named after its parent: the
    /// first store an app had, which existing configs already point at.
    /// Any other store is named after its own folder, so two stores under
    /// one root never share a socket.
    pub legacy_store_dir: String,
}

impl SocketPlan {
    pub fn new(dir_name: impl Into<String>, legacy_store_dir: impl Into<String>) -> Self {
        Self { dir_name: dir_name.into(), legacy_store_dir: legacy_store_dir.into() }
    }
}

fn io(what: &'static str, path: &Path) -> impl FnOnce(std::io::Error) -> Error {
    let path = path.to_path_buf();
    move |source| Error::Io { what, path, source }
}

fn config_error(path: &Path, what: impl Into<String>) -> Error {
    KeyStoreError::Config { path: path.to_path_buf(), what: what.into() }.into()
}

// ── Sockets ─────────────────────────────────────────────────────────────

/// The Unix-socket path budget: Linux 108 bytes, macOS 104, minus a margin.
#[cfg(not(windows))]
pub fn socket_path_budget() -> usize {
    let limit: usize = if cfg!(target_os = "macos") { 104 } else { 108 };
    limit.saturating_sub(4)
}

#[cfg(not(windows))]
pub fn socket_fits(path: &Path) -> bool {
    path.as_os_str().len() < socket_path_budget()
}

/// The per-user folder for short sockets (see [`SocketPlan::dir_name`]).
#[cfg(not(windows))]
pub fn short_socket_dir(plan: &SocketPlan) -> PathBuf {
    let base = if cfg!(target_os = "macos") { std::env::var_os("TMPDIR") } else { std::env::var_os("XDG_RUNTIME_DIR") };
    if let Some(b) = base {
        let b = PathBuf::from(b);
        if b.is_absolute() && b.is_dir() {
            return b.join(&plan.dir_name);
        }
    }
    PathBuf::from(format!("/tmp/{}-{}", plan.dir_name, current_uid()))
}

/// The user's id, read off the home folder; a hash of `$HOME` if that
/// cannot be read. Kept as the apps have it so existing socket names hold.
#[cfg(not(windows))]
fn current_uid() -> String {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::MetadataExt;
    match std::env::var_os("HOME") {
        Some(h) => match std::fs::metadata(&h) {
            Ok(m) => m.uid().to_string(),
            Err(_) => hex::encode(Sha256::digest(h.to_string_lossy().as_bytes()))[..8].to_string(),
        },
        None => "u".to_string(),
    }
}

/// The short socket named after `root`: 16 hex of SHA-256 over the path.
#[cfg(not(windows))]
pub fn short_socket_path(root: &Path, plan: &SocketPlan) -> PathBuf {
    use sha2::{Digest, Sha256};
    let h = hex::encode(Sha256::digest(root.to_string_lossy().as_bytes()));
    short_socket_dir(plan).join(format!("{}.sock", &h[..16]))
}

/// The short socket for the store in `store_dir` (see
/// [`SocketPlan::legacy_store_dir`] for the naming rule).
#[cfg(not(windows))]
pub fn runtime_socket_path(store_dir: &Path, plan: &SocketPlan) -> PathBuf {
    let legacy = store_dir.file_name().map(|n| *n == *plan.legacy_store_dir).unwrap_or(false);
    match (legacy, store_dir.parent()) {
        (true, Some(parent)) => short_socket_path(parent, plan),
        _ => short_socket_path(store_dir, plan),
    }
}

/// The socket path a `unix://` connection URL names, percent-decoded
/// (`Application%20Support` on every Mac).
#[cfg(not(windows))]
pub fn socket_path_from_url(connection_url: &str) -> Result<PathBuf> {
    let url = url::Url::parse(connection_url)
        .map_err(|e| Error::from(KeyStoreError::Connect(format!("invalid connection URL: {e}"))))?;
    let decoded = percent_encoding::percent_decode_str(url.path()).decode_utf8_lossy();
    Ok(PathBuf::from(decoded.as_ref()))
}

/// A `unix://` URL for `socket` with the query (the connection key) of
/// `original`.
#[cfg(not(windows))]
fn unix_url_for(socket: &Path, original: &str) -> String {
    const KEEP: &percent_encoding::AsciiSet =
        &percent_encoding::NON_ALPHANUMERIC.remove(b'/').remove(b'.').remove(b'-').remove(b'_');
    let encoded = percent_encoding::utf8_percent_encode(&socket.to_string_lossy(), KEEP).to_string();
    let query = original.split_once('?').map(|(_, q)| format!("?{q}")).unwrap_or_default();
    format!("unix://{encoded}{query}")
}

// ── The config file ─────────────────────────────────────────────────────

pub fn config_path(store_dir: &Path) -> PathBuf {
    store_dir.join(CONFIG_FILE)
}

/// A YAML scalar as lair's config holds it: plain, or quoted when it had to be.
fn yaml_value(raw: &str) -> String {
    let raw = raw.trim();
    if raw.len() >= 2 && raw.starts_with('\'') && raw.ends_with('\'') {
        return raw[1..raw.len() - 1].replace("''", "'");
    }
    if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        return raw[1..raw.len() - 1].replace("\\\"", "\"").replace("\\\\", "\\");
    }
    raw.to_string()
}

/// `value` as a YAML scalar: plain when that reads back the same, else
/// single-quoted.
fn yaml_scalar(value: &str) -> String {
    let needs_quotes = value.is_empty()
        || value.contains(": ")
        || value.contains(" #")
        || value.ends_with(':')
        || value.starts_with(|c: char| c.is_whitespace() || "!&*-?{}[],#|>@%'\"`".contains(c))
        || value.ends_with(char::is_whitespace);
    if needs_quotes {
        format!("'{}'", value.replace('\'', "''"))
    } else {
        value.to_string()
    }
}

/// The value of top-level `key:` in the config.
fn read_key(store_dir: &Path, key: &str) -> Result<String> {
    let path = config_path(store_dir);
    let content = std::fs::read_to_string(&path).map_err(io("read the key store config", &path))?;
    let prefix = format!("{key}:");
    content
        .lines()
        .find_map(|l| l.trim().strip_prefix(&prefix).map(yaml_value))
        .ok_or_else(|| config_error(&path, format!("no {key}")))
}

/// The connection URL from the store's config.
pub fn read_connection_url(store_dir: &Path) -> Result<String> {
    read_key(store_dir, "connectionUrl")
}

/// Replace the config with `lines`, atomically.
fn write_config(store_dir: &Path, lines: &[String]) -> Result<()> {
    let path = config_path(store_dir);
    crate::files::write_atomic(&path, (lines.join("\n") + "\n").as_bytes()).map_err(io("write the key store config", &path))
}

/// Lair writes `connectionUrl: unix://<store>/socket?k=...` at init. Where
/// that path is over the Unix-socket limit, point the URL at the short
/// runtime socket ([`runtime_socket_path`]); the store, the pid file and the
/// connection key stay as lair wrote them. A config that already fits is
/// left alone.
#[cfg(not(windows))]
pub fn ensure_socket_fits(store_dir: &Path, plan: &SocketPlan) -> Result<()> {
    let url = read_connection_url(store_dir)?;
    let current = socket_path_from_url(&url)?;
    if socket_fits(&current) {
        return Ok(());
    }
    let short = runtime_socket_path(store_dir, plan);
    if !socket_fits(&short) {
        return Err(KeyStoreError::SocketTooLong(short).into());
    }
    if let Some(dir) = short.parent() {
        std::fs::create_dir_all(dir).map_err(io("create the socket folder", dir))?;
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    let new_url = unix_url_for(&short, &url);
    let path = config_path(store_dir);
    let content = std::fs::read_to_string(&path).map_err(io("read the key store config", &path))?;
    let lines: Vec<String> = content
        .lines()
        .map(|l| if l.trim_start().starts_with("connectionUrl:") { format!("connectionUrl: {new_url}") } else { l.to_string() })
        .collect();
    write_config(store_dir, &lines)?;
    log::info!(
        "[lair] socket moved to the runtime folder: {:?} ({} bytes; the in-folder path was {} bytes)",
        short,
        short.as_os_str().len(),
        current.as_os_str().len()
    );
    Ok(())
}

/// Make the config point at the folder it now lives in.
///
/// Lair writes three absolute paths at init: `connectionUrl`, `pidFile` and
/// `storeFile`. The URL's path is percent-encoded, so replacing the old
/// folder as plain text fixes the two file paths and leaves the socket
/// behind; this compares decoded paths and lets the URL type encode. A
/// socket already on this store's short runtime path stays. Windows pipes
/// are left alone. Returns whether anything changed; safe on every start.
pub fn repoint_config(store_dir: &Path, plan: &SocketPlan) -> Result<bool> {
    let path = config_path(store_dir);
    if !path.exists() {
        return Ok(false);
    }
    let content = std::fs::read_to_string(&path).map_err(io("read the key store config", &path))?;
    let mut changed = false;
    let mut out: Vec<String> = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim_start();
        let indent = &line[..line.len() - trimmed.len()];
        if let Some(rest) = trimmed.strip_prefix("connectionUrl:") {
            if let Some(fixed) = repointed_url(&yaml_value(rest), store_dir, plan) {
                out.push(format!("{indent}connectionUrl: {fixed}"));
                changed = true;
                continue;
            }
        }
        let file_key = [("pidFile:", "pid_file"), ("storeFile:", "store_file")]
            .into_iter()
            .find_map(|(key, file)| trimmed.strip_prefix(key).map(|rest| (key, file, yaml_value(rest))));
        if let Some((key, file, current)) = file_key {
            let expected = store_dir.join(file);
            if Path::new(&current) != expected {
                out.push(format!("{indent}{key} {}", yaml_scalar(&expected.to_string_lossy())));
                changed = true;
                continue;
            }
        }
        out.push(line.to_string());
    }
    if changed {
        write_config(store_dir, &out)?;
        log::info!("[lair] key store config repointed to {:?}", store_dir);
    }
    Ok(changed)
}

/// The URL `raw` should become for a store now in `store_dir`, or None when
/// it is right as it is.
#[cfg(not(windows))]
fn repointed_url(raw: &str, store_dir: &Path, plan: &SocketPlan) -> Option<String> {
    let url = url::Url::parse(raw).ok()?;
    if url.scheme() != "unix" {
        return None;
    }
    let current = socket_path_from_url(raw).ok()?;
    let expected = store_dir.join("socket");
    if current == expected || current == runtime_socket_path(store_dir, plan) {
        return None;
    }
    Some(unix_url_for(&expected, raw))
}

#[cfg(windows)]
fn repointed_url(_raw: &str, _store_dir: &Path, _plan: &SocketPlan) -> Option<String> {
    None
}

// ── Running lair ────────────────────────────────────────────────────────

/// Lair's own output (stderr, else stdout), cut to 500 characters.
pub fn read_logs(store_dir: &Path) -> String {
    let stderr = std::fs::read_to_string(store_dir.join("lair-stderr.log")).unwrap_or_default();
    let stdout = std::fs::read_to_string(store_dir.join("lair-stdout.log")).unwrap_or_default();
    let output = if !stderr.trim().is_empty() { stderr } else { stdout };
    let tail = log_excerpt(output.trim(), 500);
    if tail.is_empty() { "(no output)".to_string() } else { tail }
}

/// Start lair's server for the store in `store_dir`, creating the store on
/// first run. `lair_bin` must be the lair of the line this store serves.
///
/// Before the server starts, the config is repointed at `store_dir` (a
/// moved folder) and, on Unix, the socket moves to the short runtime path
/// when lair's default does not fit. A stale `socket` and `pid_file` are
/// removed: lair leaves its `pid_file` even on a clean stop, and an empty
/// one (a power cut) makes it refuse to start. Lair's output goes to
/// `lair-stdout.log` and `lair-stderr.log` beside the store.
///
/// Returns the child and the connection URL. The URL carries the store's
/// connection key: never log it.
pub fn start(store_dir: &Path, lair_bin: &Path, passphrase: &str, plan: &SocketPlan) -> Result<(SidecarChild, String)> {
    std::fs::create_dir_all(store_dir).map_err(io("create the key store folder", store_dir))?;
    log::info!("[lair] using {:?}", lair_bin);

    if !config_path(store_dir).exists() {
        log::info!("[lair:init] first run - creating the key store");
        let started = Instant::now();
        let out = store_dir.join("lair-init-stdout.log");
        let err = store_dir.join("lair-init-stderr.log");
        let mut child = SidecarCommand::new(lair_bin)
            .arg("init")
            .arg("--piped")
            .current_dir(store_dir)
            .stdout(std::fs::File::create(&out).map_err(io("create the lair init log", &out))?)
            .stderr(std::fs::File::create(&err).map_err(io("create the lair init log", &err))?)
            .spawn()
            .map_err(io("start lair init", lair_bin))?;
        if let Some(mut stdin) = child.stdin.take() {
            if let Err(e) = stdin.write_all(format!("{passphrase}\n").as_bytes()) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io("write the passphrase to lair init", lair_bin)(e));
            }
        }
        let status = child.wait().map_err(io("wait for lair init", lair_bin))?;
        if !status.success() {
            let tail = log_excerpt(std::fs::read_to_string(&err).unwrap_or_default().trim(), 500);
            return Err(KeyStoreError::InitFailed { status, log_tail: tail }.into());
        }
        log::info!("[lair:init] done in {}ms", started.elapsed().as_millis());
    }

    repoint_config(store_dir, plan)?;
    #[cfg(not(windows))]
    ensure_socket_fits(store_dir, plan)?;
    let connection_url = read_connection_url(store_dir)?;

    for stale in ["socket", "pid_file"] {
        let path = store_dir.join(stale);
        if path.exists() {
            log::info!("[lair] removing a stale {}: {:?}", stale, path);
            let _ = std::fs::remove_file(&path);
        }
    }
    #[cfg(not(windows))]
    if let Ok(sock) = socket_path_from_url(&connection_url) {
        if sock.exists() && sock != store_dir.join("socket") {
            log::info!("[lair] removing a stale socket: {:?}", sock);
            let _ = std::fs::remove_file(&sock);
        }
    }

    let out = store_dir.join("lair-stdout.log");
    let err = store_dir.join("lair-stderr.log");
    let started = Instant::now();
    let mut child = SidecarCommand::new(lair_bin)
        .arg("server")
        .arg("--piped")
        .current_dir(store_dir)
        .stdout(std::fs::File::create(&out).map_err(io("create the lair log", &out))?)
        .stderr(std::fs::File::create(&err).map_err(io("create the lair log", &err))?)
        .spawn()
        .map_err(io("start the lair server", lair_bin))?;
    if let Some(mut stdin) = child.stdin.take() {
        if let Err(e) = stdin.write_all(format!("{passphrase}\n").as_bytes()) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io("write the passphrase to the lair server", lair_bin)(e));
        }
    }
    log::info!("[lair:server] started (pid {}) in {}ms", child.id(), started.elapsed().as_millis());
    Ok((child, connection_url))
}

/// The error to fail a start with if lair has exited.
pub fn exited(child: &mut SidecarChild, store_dir: &Path) -> Option<Error> {
    match child.try_wait() {
        Ok(Some(status)) => Some(KeyStoreError::Stopped { status, log_tail: read_logs(store_dir) }.into()),
        Ok(None) => None,
        Err(e) => Some(Error::Io { what: "check the key store process", path: store_dir.to_path_buf(), source: e }),
    }
}

/// Wait for lair to come up, watching the child the whole time: lair binds
/// its socket before it checks the passphrase, so a socket file alone proves
/// nothing. On Unix this polls for the socket and then waits one more tick;
/// on Windows (a named pipe, nothing to poll) it watches the child for 3 s
/// and leaves the rest to the connect retries.
pub async fn wait_ready(connection_url: &str, timeout: Duration, child: &mut SidecarChild, store_dir: &Path) -> Result<()> {
    let tick = Duration::from_millis(200);

    #[cfg(windows)]
    {
        let _ = (connection_url, timeout);
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if let Some(err) = exited(child, store_dir) {
                return Err(err);
            }
            tokio::time::sleep(tick).await;
        }
        return match exited(child, store_dir) {
            Some(err) => Err(err),
            None => Ok(()),
        };
    }

    #[cfg(not(windows))]
    {
        let socket = socket_path_from_url(connection_url)?;
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(err) = exited(child, store_dir) {
                return Err(err);
            }
            if socket.exists() {
                // The socket appears a moment before the passphrase check;
                // one more tick catches the common immediate exit here.
                tokio::time::sleep(tick).await;
                if let Some(err) = exited(child, store_dir) {
                    return Err(err);
                }
                log::info!("[lair] socket ready at {:?}", socket);
                return Ok(());
            }
            tokio::time::sleep(tick).await;
        }
        Err(KeyStoreError::NotReady { secs: timeout.as_secs(), path: socket }.into())
    }
}

#[cfg(test)]
mod tests;
