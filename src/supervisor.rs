//! The lines of one data root.
//!
//! [`start_line`] starts one line, key store through conductor: the app then
//! installs its DNAs on the admin port and attaches its app interface. Any
//! failure stops what the start had started, conductor first.

use crate::conductor::{self, NetworkTuning};
use crate::keystore::{self, SocketPlan};
use crate::process::{stop_gracefully, SidecarChild, StopOutcome};
use crate::rendezvous::Rendezvous;
use crate::{Error, Line, Result};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Where a line's agent key comes from.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum KeySource {
    /// This seed under this tag. A tag already present is reused only when
    /// it holds this seed. One seed imported into both lines' stores gives
    /// the same key on both.
    Seed { seed: [u8; 32], tag: String },
    /// A random seed that never leaves the store; a tag already present is
    /// that key.
    NewSeed { tag: String },
    /// A key that must already be in the store (a copied one).
    Existing { tag: String },
}

/// The steps of a line's start, for an app that narrates them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StartStep {
    KeyStore,
    Connect,
    Agents,
    Conductor,
    WaitAdmin,
}

/// How long each wait of a start may take.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Timeouts {
    /// For the key store's socket.
    pub socket: Duration,
    /// For the conductor's admin interface (a conductor takes 5-15 s).
    pub admin: Duration,
    /// The grace a conductor gets to stop before it is killed.
    pub conductor_stop: Duration,
    /// The same for the key store.
    pub lair_stop: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            socket: Duration::from_secs(15),
            admin: Duration::from_secs(30),
            conductor_stop: Duration::from_secs(5),
            lair_stop: Duration::from_secs(2),
        }
    }
}

/// Everything one line's start needs.
#[derive(Clone, Debug)]
pub struct LineStart<'a> {
    pub line: Line,
    /// That line's lair and conductor (each line accepts only its own).
    pub lair_bin: &'a Path,
    pub conductor_bin: &'a Path,
    pub lair_dir: &'a Path,
    pub conductor_dir: &'a Path,
    pub passphrase: &'a str,
    pub sockets: &'a SocketPlan,
    /// Admin port candidates; the first free one is used.
    pub admin_ports: &'a [u16],
    /// The origin the conductor accepts ([`conductor::fresh_origin`]). Both
    /// lines of one app start share one.
    pub origin: &'a str,
    pub rendezvous: &'a Rendezvous,
    pub tuning: &'a NetworkTuning,
    pub agents: &'a [KeySource],
    pub timeouts: Timeouts,
}

/// A running line: its key store and conductor.
pub struct LineProcess {
    pub line: Line,
    pub lair: SidecarChild,
    pub conductor: SidecarChild,
    pub admin_port: u16,
    /// The key store's address. It carries the connection key: never log it.
    pub lair_url: String,
    /// The agent keys, in the order of [`LineStart::agents`].
    pub agents: Vec<[u8; 32]>,
    pub conductor_dir: PathBuf,
    pub timeouts: Timeouts,
}

/// What a stop did to each process.
#[derive(Debug)]
pub struct StopReport {
    pub conductor: std::io::Result<StopOutcome>,
    pub lair: std::io::Result<StopOutcome>,
}

impl LineProcess {
    /// Whether the conductor still runs.
    pub fn conductor_alive(&mut self) -> bool {
        matches!(self.conductor.try_wait(), Ok(None))
    }

    /// Stop the conductor, then the key store: each asked first and killed
    /// only after its grace. A conductor killed in the middle of a write is
    /// what this avoids (measured: both lines' conductors exit about 0.1 s
    /// after the request, lair in under 10 ms).
    pub fn stop(&mut self) -> StopReport {
        let line = self.line;
        let report = StopReport {
            conductor: stop_gracefully(&mut self.conductor, self.timeouts.conductor_stop),
            lair: stop_gracefully(&mut self.lair, self.timeouts.lair_stop),
        };
        for (what, outcome, grace) in [
            ("conductor", &report.conductor, self.timeouts.conductor_stop),
            ("key store", &report.lair, self.timeouts.lair_stop),
        ] {
            match outcome {
                Ok(StopOutcome::Killed) => log::warn!("[{line}] the {what} did not stop within {grace:?} and was killed"),
                Ok(_) => log::info!("[{line}] the {what} stopped"),
                Err(e) => log::warn!("[{line}] stopping the {what}: {e}"),
            }
        }
        report
    }
}

fn stop_child(child: &mut SidecarChild, grace: Duration) {
    let _ = stop_gracefully(child, grace);
}

/// Connect to the key store just started and ensure each of `s.agents`,
/// on the line's own client crate.
macro_rules! ensure_agents {
    ($v:ident, $url:expr, $s:expr, $lair:expr, $on_step:expr) => {{
        let client = keystore::$v::connect_with_retries($url, $s.passphrase, $lair, $s.lair_dir).await?;
        $on_step(StartStep::Agents);
        let mut keys = Vec::with_capacity($s.agents.len());
        for agent in $s.agents {
            keys.push(match agent {
                KeySource::Seed { seed, tag } => keystore::$v::import_seed(&client, seed, tag).await?,
                KeySource::NewSeed { tag } => keystore::$v::new_seed(&client, tag).await?,
                KeySource::Existing { tag } => keystore::$v::existing(&client, tag).await?,
            });
        }
        Ok(keys)
    }};
}

async fn agents_on(url: &str, s: &LineStart<'_>, lair: &mut SidecarChild, on_step: &mut (dyn FnMut(StartStep) + Send)) -> Result<Vec<[u8; 32]>> {
    match s.line {
        #[cfg(feature = "line-06")]
        Line::V06 => ensure_agents!(v06, url, s, lair, on_step),
        #[cfg(feature = "line-07")]
        Line::V07 => ensure_agents!(v07, url, s, lair, on_step),
        #[allow(unreachable_patterns)]
        other => Err(Error::LineNotCompiled(other)),
    }
}

/// Start one line: the key store (created on first run), the agents, a free
/// admin port, the config, the conductor, its admin interface. `on_step` is
/// called as each step begins. On any failure what was started is stopped.
pub async fn start_line(s: &LineStart<'_>, mut on_step: impl FnMut(StartStep) + Send) -> Result<LineProcess> {
    on_step(StartStep::KeyStore);
    let (mut lair, url) = keystore::start(s.lair_dir, s.lair_bin, s.passphrase, s.sockets)?;
    let lair_up = async {
        keystore::wait_ready(&url, s.timeouts.socket, &mut lair, s.lair_dir).await?;
        on_step(StartStep::Connect);
        agents_on(&url, s, &mut lair, &mut on_step).await
    }
    .await;
    let agents = match lair_up {
        Ok(a) => a,
        Err(e) => {
            stop_child(&mut lair, s.timeouts.lair_stop);
            return Err(e);
        }
    };

    on_step(StartStep::Conductor);
    let conductor_up = async {
        let admin_port = conductor::pick_admin_port(s.admin_ports)?;
        let config = conductor::write_config(&conductor::ConfigInput {
            line: s.line,
            conductor_dir: s.conductor_dir,
            lair_url: &url,
            admin_port,
            origin: s.origin,
            rendezvous: s.rendezvous,
            tuning: s.tuning,
        })?;
        let child = conductor::start(s.conductor_bin, &config, s.conductor_dir, s.passphrase, s.tuning).await?;
        Ok::<_, Error>((admin_port, child))
    }
    .await;
    let (admin_port, mut conductor) = match conductor_up {
        Ok(v) => v,
        Err(e) => {
            stop_child(&mut lair, s.timeouts.lair_stop);
            return Err(e);
        }
    };

    on_step(StartStep::WaitAdmin);
    if let Err(e) = conductor::wait_admin(admin_port, s.timeouts.admin, &mut conductor, s.conductor_dir).await {
        stop_child(&mut conductor, s.timeouts.conductor_stop);
        stop_child(&mut lair, s.timeouts.lair_stop);
        return Err(e);
    }
    log::info!("[{}] key store and conductor up (admin port {admin_port})", s.line);
    Ok(LineProcess {
        line: s.line,
        lair,
        conductor,
        admin_port,
        lair_url: url,
        agents,
        conductor_dir: s.conductor_dir.to_path_buf(),
        timeouts: s.timeouts,
    })
}

/// A start runs on a multi-threaded runtime: its future must be `Send`.
#[allow(dead_code)]
fn start_line_is_send(s: &'static LineStart<'static>) {
    fn send<T: Send>(_: T) {}
    send(start_line(s, |_| {}));
}

#[cfg(all(test, feature = "line-06", feature = "line-07"))]
mod tests {
    use super::*;

    /// Both lines with the real binaries, offline: one seed gives one key on
    /// both, each admin interface answers, the 0.7 config carries the gossip
    /// cap, both stop on request. A start that fails after its key store is
    /// up leaves no key store running.
    ///
    /// `HC_LINES_LAIR_06= HC_LINES_LAIR_07= HC_LINES_CONDUCTOR_06= HC_LINES_CONDUCTOR_07= cargo test --lib -- --ignored live_`
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn live_both_lines_start_with_one_key_and_stop_cleanly() {
        let bin = |var: &str| PathBuf::from(std::env::var(var).unwrap_or_else(|_| panic!("set {var}")));
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let sockets = SocketPlan::new("hcl-live", "lair");
        let origin = conductor::fresh_origin("hcl");
        let rendezvous = Rendezvous::new("https://127.0.0.1:9");
        let agents = [KeySource::Seed { seed: [5u8; 32], tag: "device".into() }];
        let mut started = Vec::new();
        for (line, lair, cond, lair_dir, cond_dir, ports) in [
            (Line::V06, "HC_LINES_LAIR_06", "HC_LINES_CONDUCTOR_06", "lair", "conductor", [47810u16, 47811]),
            (Line::V07, "HC_LINES_LAIR_07", "HC_LINES_CONDUCTOR_07", "lair-07", "conductor-07", [47812, 47813]),
        ] {
            let (lair_bin, cond_bin) = (bin(lair), bin(cond));
            let (lair_dir, cond_dir) = (root.join(lair_dir), root.join(cond_dir));
            let tuning = NetworkTuning::for_line(line);
            let mut steps = Vec::new();
            let p = start_line(
                &LineStart {
                    line,
                    lair_bin: &lair_bin,
                    conductor_bin: &cond_bin,
                    lair_dir: &lair_dir,
                    conductor_dir: &cond_dir,
                    passphrase: "live",
                    sockets: &sockets,
                    admin_ports: &ports,
                    origin: &origin,
                    rendezvous: &rendezvous,
                    tuning: &tuning,
                    agents: &agents,
                    timeouts: Timeouts::default(),
                },
                |s| steps.push(s),
            )
            .await
            .unwrap_or_else(|e| panic!("{line}: {e}"));
            assert_eq!(steps, [StartStep::KeyStore, StartStep::Connect, StartStep::Agents, StartStep::Conductor, StartStep::WaitAdmin]);
            assert!(tokio::net::TcpStream::connect(("127.0.0.1", p.admin_port)).await.is_ok());
            let config = std::fs::read_to_string(cond_dir.join("conductor-config.yaml")).unwrap();
            assert_eq!(config.contains("maxGossipOpBytes: 1048576"), line == Line::V07);
            started.push(p);
        }
        assert_eq!(started[0].agents, started[1].agents, "one seed, one key on both lines");
        for mut p in started {
            let report = p.stop();
            assert!(matches!(report.conductor, Ok(StopOutcome::Exited)), "{:?}: {:?}", p.line, report.conductor);
            assert!(matches!(report.lair, Ok(StopOutcome::Exited)), "{:?}: {:?}", p.line, report.lair);
        }

        // Every admin port taken: the start fails after its key store came up,
        // and that key store is stopped.
        let held = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = held.local_addr().unwrap().port();
        let (lair_bin, cond_bin) = (bin("HC_LINES_LAIR_07"), bin("HC_LINES_CONDUCTOR_07"));
        let lair_dir = root.join("lair-07");
        let tuning = NetworkTuning::for_line(Line::V07);
        let err = start_line(
            &LineStart {
                line: Line::V07,
                lair_bin: &lair_bin,
                conductor_bin: &cond_bin,
                lair_dir: &lair_dir,
                conductor_dir: &root.join("conductor-07"),
                passphrase: "live",
                sockets: &sockets,
                admin_ports: &[port],
                origin: &origin,
                rendezvous: &rendezvous,
                tuning: &tuning,
                agents: &agents,
                timeouts: Timeouts::default(),
            },
            |_| {},
        )
        .await
        .err()
        .expect("no free port");
        assert!(matches!(err, Error::Conductor(conductor::ConductorError::PortsTaken { .. })), "{err}");
        let pid: u32 = std::fs::read_to_string(lair_dir.join("pid_file")).unwrap().trim().parse().unwrap();
        assert!(!crate::process::pid_alive(pid), "the key store it started was stopped");
    }
}
