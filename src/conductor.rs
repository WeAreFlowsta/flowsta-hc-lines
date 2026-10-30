//! A line's conductor: its config file, admin port, origin and process.
//!
//! The config is written fresh for every start, so nothing about a previous
//! version's config survives an update.

use crate::files::log_excerpt;
use crate::process::{SidecarChild, SidecarCommand};
use crate::rendezvous::Rendezvous;
use crate::{Error, Line, Result};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Conductor errors. Developer text: the app words what a person sees.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConductorError {
    #[error("every admin port is in use ({candidates:?})")]
    PortsTaken { candidates: Vec<u16> },
    #[error("the conductor exited right after starting (status {status}): {log_tail}")]
    ExitedAtStart { status: std::process::ExitStatus, log_tail: String },
    #[error("the conductor exited during startup (status {status}): {log_tail}")]
    ExitedDuringStart { status: std::process::ExitStatus, log_tail: String },
    #[error("the conductor's admin interface was not ready after {secs}s on port {port}: {log_tail}")]
    AdminNotReady { port: u16, secs: u64, log_tail: String },
}

/// How many bytes of ops one gossip exchange may offer a 0.7 conductor
/// (kitsune2's default is 100 MB). Holochain 0.7.1 checks which offered ops
/// it already holds in one database query that binds every op id three
/// times, and SQLite refuses a query past 32,766 bound values: an exchange
/// offering more than about 10.9k ids is dropped, and two devices of a
/// large identity never finish a sync. 1 MiB keeps a batch to a few
/// thousand ids; a larger backlog arrives over several rounds.
pub const GOSSIP_OP_BYTES_07: u32 = 1024 * 1024;

/// Per-line network and logging settings.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetworkTuning {
    /// kitsune2's request timeout (its default is 60 s).
    pub request_timeout_s: Option<u32>,
    /// The 0.7 gossip cap ([`GOSSIP_OP_BYTES_07`] by default). Ignored on 0.6.
    pub gossip_max_op_bytes: Option<u32>,
    /// The 0.7 `db_sync_level` (`Normal`, `Full`, `Off`). Ignored on 0.6.
    pub db_sync_level: Option<String>,
    /// `RUST_LOG` for the conductor when this process has none: the
    /// conductor logs nothing without it. A developer's own `RUST_LOG` is
    /// inherited instead.
    pub rust_log: Option<String>,
}

impl NetworkTuning {
    /// The defaults for `line`: the gossip cap on 0.7, warnings logged.
    pub fn for_line(line: Line) -> Self {
        Self {
            request_timeout_s: None,
            gossip_max_op_bytes: (line == Line::V07).then_some(GOSSIP_OP_BYTES_07),
            db_sync_level: None,
            rust_log: Some("warn".into()),
        }
    }
}

/// What one conductor config holds.
#[derive(Clone, Copy, Debug)]
pub struct ConfigInput<'a> {
    pub line: Line,
    pub conductor_dir: &'a Path,
    pub lair_url: &'a str,
    pub admin_port: u16,
    /// The only origin the conductor's interfaces accept ([`fresh_origin`]).
    pub origin: &'a str,
    pub rendezvous: &'a Rendezvous,
    pub tuning: &'a NetworkTuning,
}

/// A YAML single-quoted string: backslashes pass through (a Windows path in
/// double quotes reads `\U` as an escape), a quote is doubled.
fn single_quoted(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// The conductor config for `input.line`. The two lines differ: 0.6 needs
/// `signal_url`; 0.7 refuses it (an unknown field fails the parse) and takes
/// the gossip cap and `db_sync_level`.
pub fn config_yaml(input: &ConfigInput) -> String {
    let r = input.rendezvous;
    let mut y = format!(
        "data_root_path: {}\nkeystore:\n  type: lair_server\n  connection_url: {}\nadmin_interfaces:\n- driver:\n    type: websocket\n    port: {}\n    allowed_origins: {}\nnetwork:\n  bootstrap_url: {}\n",
        single_quoted(&input.conductor_dir.display().to_string()),
        single_quoted(input.lair_url),
        input.admin_port,
        single_quoted(input.origin),
        r.bootstrap_url,
    );
    if input.line == Line::V06 {
        y.push_str(&format!("  signal_url: {}\n", r.signal_url()));
    }
    y.push_str(&format!("  relay_url: {}\n", r.relay_url()));
    if let Some(m) = r.auth_material.as_deref().filter(|m| !m.is_empty()) {
        y.push_str(&format!("  base64_auth_material_bootstrap: \"{m}\"\n  base64_auth_material_relay: \"{m}\"\n"));
    }
    if let Some(t) = input.tuning.request_timeout_s {
        y.push_str(&format!("  request_timeout_s: {t}\n"));
    }
    if input.line == Line::V07 {
        if let Some(b) = input.tuning.gossip_max_op_bytes {
            y.push_str(&format!("  advanced:\n    k2Gossip:\n      maxGossipOpBytes: {b}\n      maxRequestGossipOpBytes: {b}\n"));
        }
        if let Some(level) = &input.tuning.db_sync_level {
            y.push_str(&format!("db_sync_level: {level}\n"));
        }
    }
    y
}

/// Write `conductor-config.yaml` into the conductor's folder, readable only
/// by this OS account (it holds the origin and the key store's address).
pub fn write_config(input: &ConfigInput) -> Result<PathBuf> {
    let dir = input.conductor_dir;
    std::fs::create_dir_all(dir).map_err(|source| Error::Io { what: "create the conductor folder", path: dir.to_path_buf(), source })?;
    let path = dir.join("conductor-config.yaml");
    crate::files::write_private(&path, config_yaml(input).as_bytes())
        .map_err(|source| Error::Io { what: "write the conductor config", path: path.clone(), source })?;
    log::info!("[conductor {}] config written to {:?}", input.line, path);
    Ok(path)
}

/// The first free port of `candidates` on 127.0.0.1.
pub fn pick_admin_port(candidates: &[u16]) -> Result<u16> {
    for &port in candidates {
        match std::net::TcpListener::bind(("127.0.0.1", port)) {
            Ok(_listener) => {
                log::info!("[conductor] admin port {port}");
                return Ok(port);
            }
            // After the reaper has run this is a live holder: another copy
            // of the app, or a conductor that survived it.
            Err(_) => log::warn!("[conductor] admin port {port} in use, trying the next"),
        }
    }
    Err(ConductorError::PortsTaken { candidates: candidates.to_vec() }.into())
}

/// A new origin for a conductor start: `<prefix>-<32 hex>`, random. It goes
/// only into the conductor's private config and the app's own connections,
/// so a web page (which always presents its own address) and another OS
/// account cannot open the conductor's interfaces.
pub fn fresh_origin(prefix: &str) -> String {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("the system random source");
    format!("{prefix}-{}", hex::encode(bytes))
}

/// The conductor's own output (stderr, else stdout), cut to 500 characters.
pub fn read_logs(conductor_dir: &Path) -> String {
    let stderr = std::fs::read_to_string(conductor_dir.join("holochain-stderr.log")).unwrap_or_default();
    let stdout = std::fs::read_to_string(conductor_dir.join("holochain-stdout.log")).unwrap_or_default();
    let output = if !stderr.trim().is_empty() { stderr } else { stdout };
    log_excerpt(output.trim(), 500)
}

/// Start the conductor `conductor_bin` on `config_path`, its passphrase on
/// stdin. Its output goes to `holochain-stdout.log` / `holochain-stderr.log`
/// in `conductor_dir`; the previous run's are kept as `*.previous.log` (a
/// restart is the usual cure for a network problem, and it used to erase
/// the only evidence). Fails if the conductor exits within half a second
/// (a config it refuses).
pub async fn start(
    conductor_bin: &Path,
    config_path: &Path,
    conductor_dir: &Path,
    passphrase: &str,
    tuning: &NetworkTuning,
) -> Result<SidecarChild> {
    let io = |what: &'static str, path: &Path| {
        let path = path.to_path_buf();
        move |source| Error::Io { what, path, source }
    };
    let stdout_path = conductor_dir.join("holochain-stdout.log");
    let stderr_path = conductor_dir.join("holochain-stderr.log");
    let _ = std::fs::rename(&stdout_path, conductor_dir.join("holochain-stdout.previous.log"));
    let _ = std::fs::rename(&stderr_path, conductor_dir.join("holochain-stderr.previous.log"));
    let stdout = std::fs::File::create(&stdout_path).map_err(io("create the conductor log", &stdout_path))?;
    let stderr = std::fs::File::create(&stderr_path).map_err(io("create the conductor log", &stderr_path))?;

    log::info!("[conductor] using {:?}", conductor_bin);
    let mut cmd = SidecarCommand::new(conductor_bin).arg("-c").arg(config_path).arg("--piped").stdout(stdout).stderr(stderr);
    if let (Some(level), None) = (&tuning.rust_log, std::env::var_os("RUST_LOG")) {
        cmd = cmd.env("RUST_LOG", level);
    }
    let started = Instant::now();
    let mut child = cmd.spawn().map_err(io("start the conductor", conductor_bin))?;
    let pid = child.id();
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        if let Err(e) = stdin.write_all(format!("{passphrase}\n").as_bytes()) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io("write the passphrase to the conductor", conductor_bin)(e));
        }
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    match child.try_wait() {
        Ok(Some(status)) => Err(ConductorError::ExitedAtStart { status, log_tail: read_logs(conductor_dir) }.into()),
        Ok(None) => {
            log::info!("[conductor:{pid}] running ({}ms since spawn)", started.elapsed().as_millis());
            Ok(child)
        }
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(io("check the conductor process", conductor_dir)(e))
        }
    }
}

/// Wait for the admin interface on `port`, watching the conductor: one that
/// exits meanwhile fails at once with what it logged.
pub async fn wait_admin(port: u16, timeout: Duration, child: &mut SidecarChild, conductor_dir: &Path) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut attempt = 0u32;
    while Instant::now() < deadline {
        attempt += 1;
        match child.try_wait() {
            Ok(Some(status)) => return Err(ConductorError::ExitedDuringStart { status, log_tail: read_logs(conductor_dir) }.into()),
            Ok(None) => {}
            Err(source) => return Err(Error::Io { what: "check the conductor process", path: conductor_dir.to_path_buf(), source }),
        }
        if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            log::info!("[conductor] admin interface ready on port {port} (attempt {attempt})");
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(ConductorError::AdminNotReady { port, secs: timeout.as_secs(), log_tail: read_logs(conductor_dir) }.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendezvous() -> Rendezvous {
        Rendezvous { bootstrap_url: "https://b.example.com".into(), signal_url: None, auth_material: Some("eyJmb28iOiJiYXIifQ==".into()) }
    }

    /// The exact bytes each line's conductor is given.
    #[test]
    fn each_line_gets_its_own_config_shape() {
        let dir = Path::new("/data/it's here/conductor");
        let r = rendezvous();
        let mut t06 = NetworkTuning::for_line(Line::V06);
        t06.request_timeout_s = Some(240);
        let c06 = config_yaml(&ConfigInput { line: Line::V06, conductor_dir: dir, lair_url: "unix:///s/a%20b/socket?k=K", admin_port: 4455, origin: "fv-00", rendezvous: &r, tuning: &t06 });
        assert_eq!(
            c06,
            "data_root_path: '/data/it''s here/conductor'\nkeystore:\n  type: lair_server\n  connection_url: 'unix:///s/a%20b/socket?k=K'\n\
             admin_interfaces:\n- driver:\n    type: websocket\n    port: 4455\n    allowed_origins: 'fv-00'\nnetwork:\n\
             \x20 bootstrap_url: https://b.example.com\n  signal_url: wss://b.example.com\n  relay_url: https://b.example.com./\n\
             \x20 base64_auth_material_bootstrap: \"eyJmb28iOiJiYXIifQ==\"\n  base64_auth_material_relay: \"eyJmb28iOiJiYXIifQ==\"\n\
             \x20 request_timeout_s: 240\n"
        );
        let mut t07 = NetworkTuning::for_line(Line::V07);
        t07.request_timeout_s = Some(240);
        t07.db_sync_level = Some("Normal".into());
        let c07 = config_yaml(&ConfigInput { line: Line::V07, conductor_dir: dir, lair_url: "named-pipe:\\\\.\\pipe\\x?k=K", admin_port: 4458, origin: "fv-00", rendezvous: &r, tuning: &t07 });
        assert_eq!(
            c07,
            "data_root_path: '/data/it''s here/conductor'\nkeystore:\n  type: lair_server\n  connection_url: 'named-pipe:\\\\.\\pipe\\x?k=K'\n\
             admin_interfaces:\n- driver:\n    type: websocket\n    port: 4458\n    allowed_origins: 'fv-00'\nnetwork:\n\
             \x20 bootstrap_url: https://b.example.com\n  relay_url: https://b.example.com./\n\
             \x20 base64_auth_material_bootstrap: \"eyJmb28iOiJiYXIifQ==\"\n  base64_auth_material_relay: \"eyJmb28iOiJiYXIifQ==\"\n\
             \x20 request_timeout_s: 240\n  advanced:\n    k2Gossip:\n      maxGossipOpBytes: 1048576\n      maxRequestGossipOpBytes: 1048576\n\
             db_sync_level: Normal\n"
        );
    }

    #[test]
    fn the_07_default_carries_the_gossip_cap_and_no_open_server_gets_auth() {
        let r = Rendezvous::new("https://open.example.com");
        let t = NetworkTuning::for_line(Line::V07);
        let c = config_yaml(&ConfigInput { line: Line::V07, conductor_dir: Path::new("/c"), lair_url: "u", admin_port: 1, origin: "o", rendezvous: &r, tuning: &t });
        assert!(c.contains("maxGossipOpBytes: 1048576"));
        assert!(!c.contains("base64_auth_material") && !c.contains("signal_url") && !c.contains("request_timeout_s"));
        assert_eq!(NetworkTuning::for_line(Line::V06).gossip_max_op_bytes, None);
    }

    #[test]
    fn the_config_is_private_and_origins_are_fresh() {
        let tmp = tempfile::tempdir().unwrap();
        let r = rendezvous();
        let t = NetworkTuning::for_line(Line::V07);
        let a = fresh_origin("fv");
        assert!(a.starts_with("fv-") && a.len() == 35);
        assert_ne!(a, fresh_origin("fv"));
        let path = write_config(&ConfigInput { line: Line::V07, conductor_dir: &tmp.path().join("c"), lair_url: "u", admin_port: 1, origin: &a, rendezvous: &r, tuning: &t }).unwrap();
        assert!(std::fs::read_to_string(&path).unwrap().contains(&format!("allowed_origins: '{a}'")));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn a_taken_port_is_skipped() {
        let held = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let taken = held.local_addr().unwrap().port();
        let free = { std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port() };
        assert_eq!(pick_admin_port(&[taken, free]).unwrap(), free);
        let err = pick_admin_port(&[taken]).unwrap_err();
        assert!(matches!(err, Error::Conductor(ConductorError::PortsTaken { .. })), "{err}");
    }
}
