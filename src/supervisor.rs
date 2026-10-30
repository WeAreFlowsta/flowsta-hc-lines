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

// ── The supervisor: the running lines of one data root ─────────────────

/// Where a line stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LineState {
    Off,
    Starting,
    Serving,
}

/// A running line as the supervisor holds it: its processes and the app
/// interface the app attached.
pub struct RunningLine {
    pub process: LineProcess,
    pub app_port: u16,
}

impl RunningLine {
    pub fn line(&self) -> Line {
        self.process.line
    }
    pub fn admin_port(&self) -> u16 {
        self.process.admin_port
    }
}

const LINES: [Line; 2] = [Line::V06, Line::V07];

fn slot(line: Line) -> usize {
    match line {
        Line::V06 => 0,
        Line::V07 => 1,
    }
}

#[derive(Default)]
struct Session {
    /// 0 = no session.
    id: u64,
    primary: Option<Line>,
    agent_key: Option<[u8; 32]>,
    lines: [Option<RunningLine>; 2],
}

/// The lines of one data root, owned in one place.
///
/// A **session** is one start of the app's lines: it begins when the
/// primary line is up ([`Supervisor::begin_session`]) and ends at a stop.
/// The other line comes up later from a task and joins only the session it
/// was started for ([`Supervisor::attach`]); one that arrives after its
/// session ended is handed back to be stopped. Each line also has a
/// [`LineState`], and the app's connections present one origin, shared by
/// both lines of a start.
pub struct Supervisor {
    origin_prefix: String,
    origin: std::sync::RwLock<String>,
    sessions: std::sync::atomic::AtomicU64,
    current: std::sync::Mutex<Session>,
    states: std::sync::Mutex<[LineState; 2]>,
    attaching: [std::sync::atomic::AtomicBool; 2],
}

/// Held while one line is being attached; dropping it lets the next try in.
pub struct AttachGuard<'a> {
    flag: &'a std::sync::atomic::AtomicBool,
}

impl Drop for AttachGuard<'_> {
    fn drop(&mut self) {
        self.flag.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Supervisor {
    /// `origin_prefix` names this app in its origins (`<prefix>-<32 hex>`).
    pub fn new(origin_prefix: impl Into<String>) -> Self {
        Self {
            origin_prefix: origin_prefix.into(),
            origin: std::sync::RwLock::new(String::new()),
            sessions: std::sync::atomic::AtomicU64::new(0),
            current: std::sync::Mutex::new(Session::default()),
            states: std::sync::Mutex::new([LineState::Off; 2]),
            attaching: [std::sync::atomic::AtomicBool::new(false), std::sync::atomic::AtomicBool::new(false)],
        }
    }

    /// The origin in force; empty before the first start.
    pub fn origin(&self) -> String {
        self.origin.read().unwrap().clone()
    }

    /// A new origin for a start about to begin, in force from now on.
    pub fn fresh_origin(&self) -> String {
        let origin = conductor::fresh_origin(&self.origin_prefix);
        *self.origin.write().unwrap() = origin.clone();
        origin
    }

    /// The origin in force, made first if there is none.
    pub fn origin_or_fresh(&self) -> String {
        let current = self.origin();
        if current.is_empty() { self.fresh_origin() } else { current }
    }

    /// The current session's number, if one runs.
    pub fn session(&self) -> Option<u64> {
        let s = self.current.lock().unwrap();
        (s.id != 0).then_some(s.id)
    }

    pub fn primary(&self) -> Option<Line> {
        self.current.lock().unwrap().primary
    }

    /// The key the lines run as (the same on both).
    pub fn agent_key(&self) -> Option<[u8; 32]> {
        self.current.lock().unwrap().agent_key
    }

    /// Begin a session on its primary line, which is up. A session still
    /// running is ended first; its lines are returned for the caller to stop.
    pub fn begin_session(&self, primary: RunningLine, agent_key: [u8; 32]) -> (u64, Vec<RunningLine>) {
        let line = primary.line();
        let id = self.sessions.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        let old = {
            let mut s = self.current.lock().unwrap();
            let old: Vec<RunningLine> = s.lines.iter_mut().filter_map(Option::take).collect();
            *s = Session { id, primary: Some(line), agent_key: Some(agent_key), lines: [None, None] };
            s.lines[slot(line)] = Some(primary);
            old
        };
        let mut states = self.states.lock().unwrap();
        *states = [LineState::Off; 2];
        states[slot(line)] = LineState::Serving;
        (id, old)
    }

    /// Attach `running` to session `session`. Handed back when that session
    /// has ended or the line is already there: the caller stops it.
    pub fn attach(&self, session: u64, running: RunningLine) -> std::result::Result<(), RunningLine> {
        let line = running.line();
        let mut s = self.current.lock().unwrap();
        if s.id != session || s.id == 0 || s.lines[slot(line)].is_some() {
            return Err(running);
        }
        s.lines[slot(line)] = Some(running);
        drop(s);
        self.set_state(line, LineState::Serving);
        Ok(())
    }

    /// One attach of `line` at a time: None while another is in flight.
    pub fn begin_attach(&self, line: Line) -> Option<AttachGuard<'_>> {
        let flag = &self.attaching[slot(line)];
        (!flag.swap(true, std::sync::atomic::Ordering::SeqCst)).then_some(AttachGuard { flag })
    }

    pub fn state(&self, line: Line) -> LineState {
        self.states.lock().unwrap()[slot(line)]
    }

    pub fn set_state(&self, line: Line, state: LineState) {
        self.states.lock().unwrap()[slot(line)] = state;
    }

    /// Whether `line` is in the current session.
    pub fn has(&self, line: Line) -> bool {
        self.current.lock().unwrap().lines[slot(line)].is_some()
    }

    /// `line`'s admin and app ports, when it runs.
    pub fn ports(&self, line: Line) -> Option<(u16, u16)> {
        self.current.lock().unwrap().lines[slot(line)].as_ref().map(|l| (l.admin_port(), l.app_port))
    }

    /// Whether `line`'s conductor still runs; None without that line.
    pub fn alive(&self, line: Line) -> Option<bool> {
        self.current.lock().unwrap().lines[slot(line)].as_mut().map(|l| l.process.conductor_alive())
    }

    /// Whether the primary line's conductor still runs (false with no session).
    pub fn primary_alive(&self) -> bool {
        let mut s = self.current.lock().unwrap();
        match s.primary {
            Some(p) => s.lines[slot(p)].as_mut().map(|l| l.process.conductor_alive()).unwrap_or(false),
            None => false,
        }
    }

    /// The primary line's admin port (0 with no session).
    pub fn primary_admin_port(&self) -> u16 {
        let s = self.current.lock().unwrap();
        s.primary.and_then(|p| s.lines[slot(p)].as_ref().map(|l| l.admin_port())).unwrap_or(0)
    }

    /// Stop `line` and take it out of the session (its state goes Off). The
    /// session goes on. Blocking: up to the line's stop graces.
    pub fn stop_line(&self, line: Line) {
        let taken = self.current.lock().unwrap().lines[slot(line)].take();
        if let Some(mut l) = taken {
            l.process.stop();
        }
        self.set_state(line, LineState::Off);
    }

    /// End the session: every line stopped, the 0.7 line first. Blocking.
    /// Returns whether a session was running.
    pub fn stop(&self) -> bool {
        let (was, lines) = {
            let mut s = self.current.lock().unwrap();
            let was = s.id != 0;
            let mut lines: Vec<RunningLine> = s.lines.iter_mut().filter_map(Option::take).collect();
            lines.reverse();
            *s = Session::default();
            (was, lines)
        };
        for mut l in lines {
            l.process.stop();
        }
        *self.states.lock().unwrap() = [LineState::Off; 2];
        was
    }

    /// The lines that run, newest line first.
    pub fn running_lines(&self) -> Vec<Line> {
        let s = self.current.lock().unwrap();
        LINES.iter().rev().copied().filter(|l| s.lines[slot(*l)].is_some()).collect()
    }
}

// ── The start order: the primary line, then the other from a task ──────

/// The part a line plays in a start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The line the app is ready on: its start is awaited.
    Primary,
    /// The other line: started from a task once the session has begun.
    Secondary,
}

/// What an app supplies for its lines; the supervisor runs the order.
#[async_trait::async_trait]
pub trait LineHooks: Send + Sync + 'static {
    /// Start one line's key store and conductor, normally with [`start_line`]
    /// and the app's settings for that line.
    async fn start(&self, line: Line, role: Role) -> std::result::Result<LineProcess, String>;
    /// Install the app's DNAs on a line that just came up and attach its app
    /// interface; returns the app port. A failure stops the line.
    async fn setup(&self, line: Line, role: Role, process: &mut LineProcess) -> std::result::Result<u16, String>;
    /// The primary line failed once; prepare the one retry (for example,
    /// set aside a key store that will not open). Default: retry as it is.
    async fn before_retry(&self, _line: Line, _error: &str) {}
    /// A line joined session `session`: the primary as the session began, a
    /// secondary when it attached.
    async fn joined(&self, _line: Line, _role: Role, _session: u64, _admin_port: u16, _app_port: u16) {}
    /// A secondary line did not start; the session goes on without it.
    async fn secondary_failed(&self, _line: Line, _error: &str) {}
    /// A secondary line came up after its session had ended, and was stopped.
    async fn secondary_late(&self, _line: Line) {}
}

/// Start and set up one line; a setup failure stops what was started.
async fn start_and_setup(hooks: &dyn LineHooks, line: Line, role: Role) -> std::result::Result<RunningLine, String> {
    let mut process = hooks.start(line, role).await?;
    match hooks.setup(line, role, &mut process).await {
        Ok(app_port) => Ok(RunningLine { process, app_port }),
        Err(e) => {
            let _ = tokio::task::spawn_blocking(move || {
                process.stop();
            })
            .await;
            Err(e)
        }
    }
}

impl Supervisor {
    /// Start the `primary` line (with one retry after
    /// [`LineHooks::before_retry`] and a 2 s pause, so ports and processes are
    /// released), begin a session on it, then start `secondary`, if any, from
    /// a task ([`Supervisor::attach_line`]). Returns once the primary is up;
    /// nothing waits for the secondary.
    pub async fn start_lines(
        self: &std::sync::Arc<Self>,
        primary: Line,
        secondary: Option<Line>,
        hooks: std::sync::Arc<dyn LineHooks>,
    ) -> std::result::Result<u64, String> {
        let running = match start_and_setup(hooks.as_ref(), primary, Role::Primary).await {
            Ok(r) => r,
            Err(e) => {
                log::warn!("[{primary}] the primary line did not start ({e}) - one more try");
                hooks.before_retry(primary, &e).await;
                tokio::time::sleep(Duration::from_secs(2)).await;
                start_and_setup(hooks.as_ref(), primary, Role::Primary).await?
            }
        };
        let (admin_port, app_port) = (running.admin_port(), running.app_port);
        let key = running.process.agents.first().copied().unwrap_or([0u8; 32]);
        let (session, leftover) = self.begin_session(running, key);
        for mut line in leftover {
            log::warn!("[{}] a line was still running at a new start - stopped", line.line());
            let _ = tokio::task::spawn_blocking(move || {
                line.process.stop();
            })
            .await;
        }
        hooks.joined(primary, Role::Primary, session, admin_port, app_port).await;
        if let Some(other) = secondary {
            self.attach_line(session, other, hooks);
        }
        Ok(session)
    }

    /// Start `line` from a task and attach it to session `session`. Best
    /// effort; one attach per line at a time. A line that comes up after its
    /// session ended is stopped again.
    pub fn attach_line(self: &std::sync::Arc<Self>, session: u64, line: Line, hooks: std::sync::Arc<dyn LineHooks>) {
        let sup = self.clone();
        tokio::spawn(async move {
            let Some(_attaching) = sup.begin_attach(line) else { return };
            if sup.session() != Some(session) || sup.has(line) {
                return;
            }
            sup.set_state(line, LineState::Starting);
            match start_and_setup(hooks.as_ref(), line, Role::Secondary).await {
                Ok(running) => {
                    let (admin_port, app_port) = (running.admin_port(), running.app_port);
                    match sup.attach(session, running) {
                        Ok(()) => hooks.joined(line, Role::Secondary, session, admin_port, app_port).await,
                        Err(mut late) => {
                            let _ = tokio::task::spawn_blocking(move || {
                                late.process.stop();
                            })
                            .await;
                            hooks.secondary_late(line).await;
                        }
                    }
                }
                Err(e) => {
                    if sup.session() == Some(session) {
                        sup.set_state(line, LineState::Off);
                    }
                    hooks.secondary_failed(line, &e).await;
                }
            }
        });
    }
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

#[cfg(all(test, unix))]
mod session_tests {
    use super::*;
    use crate::process::SidecarCommand;

    fn running(line: Line, port: u16) -> RunningLine {
        let sleeper = || SidecarCommand::new("/bin/sh").arg("-c").arg("sleep 30").spawn().unwrap();
        RunningLine {
            process: LineProcess {
                line,
                lair: sleeper(),
                conductor: sleeper(),
                admin_port: port,
                lair_url: String::new(),
                agents: vec![[1u8; 32]],
                conductor_dir: PathBuf::new(),
                timeouts: Timeouts::default(),
            },
            app_port: port + 100,
        }
    }

    #[test]
    fn a_late_line_joins_only_its_own_session() {
        let sup = Supervisor::new("t");
        assert_eq!(sup.session(), None);
        let (first, old) = sup.begin_session(running(Line::V06, 1), [1u8; 32]);
        assert!(old.is_empty());
        assert_eq!((sup.primary(), sup.state(Line::V06), sup.state(Line::V07)), (Some(Line::V06), LineState::Serving, LineState::Off));
        sup.set_state(Line::V07, LineState::Starting);
        assert!(sup.attach(first, running(Line::V07, 2)).is_ok());
        assert_eq!((sup.state(Line::V07), sup.ports(Line::V07)), (LineState::Serving, Some((2, 102))));
        let mut twice = sup.attach(first, running(Line::V07, 3)).expect_err("the line is already there");
        twice.process.stop();
        assert_eq!(sup.running_lines(), [Line::V07, Line::V06]);

        assert!(sup.stop());
        assert_eq!((sup.session(), sup.state(Line::V06), sup.state(Line::V07)), (None, LineState::Off, LineState::Off));
        let mut late = sup.attach(first, running(Line::V07, 4)).expect_err("its session ended");
        late.process.stop();

        let (second, _) = sup.begin_session(running(Line::V07, 5), [1u8; 32]);
        assert!(second > first);
        let mut stale = sup.attach(first, running(Line::V06, 6)).expect_err("an earlier session's line");
        stale.process.stop();
        assert_eq!(sup.primary_admin_port(), 5);
        sup.stop();
    }

    #[test]
    fn a_dead_line_reads_dead_and_leaves_the_session_when_stopped() {
        let sup = Supervisor::new("t");
        let (id, _) = sup.begin_session(running(Line::V06, 1), [1u8; 32]);
        assert!(sup.primary_alive());
        assert_eq!(sup.alive(Line::V07), None);
        let mut l07 = running(Line::V07, 2);
        let _ = l07.process.conductor.kill();
        let _ = l07.process.conductor.wait();
        sup.attach(id, l07).ok().unwrap();
        assert_eq!(sup.alive(Line::V07), Some(false));
        sup.stop_line(Line::V07);
        assert_eq!((sup.has(Line::V07), sup.state(Line::V07), sup.session()), (false, LineState::Off, Some(id)));
        sup.stop();
        assert!(!sup.primary_alive());
    }

    #[test]
    fn one_attach_at_a_time_and_one_origin_per_start() {
        let sup = Supervisor::new("fv");
        let first = sup.begin_attach(Line::V06).expect("free");
        assert!(sup.begin_attach(Line::V06).is_none());
        assert!(sup.begin_attach(Line::V07).is_some(), "the other line has its own");
        drop(first);
        assert!(sup.begin_attach(Line::V06).is_some());
        assert_eq!(sup.origin(), "");
        let a = sup.origin_or_fresh();
        assert!(a.starts_with("fv-"));
        assert_eq!(sup.origin_or_fresh(), a, "kept while in force");
        assert_ne!(sup.fresh_origin(), a);
    }
}

#[cfg(all(test, unix))]
mod order_tests {
    use super::*;
    use crate::process::SidecarCommand;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Fake {
        fail_starts: Mutex<Vec<(Line, u32)>>,
        fail_setup: Mutex<Vec<Line>>,
        secondary_delay_ms: u64,
        starts: AtomicU32,
        retries: AtomicU32,
        events: Mutex<Vec<String>>,
    }

    fn sleeper() -> SidecarChild {
        SidecarCommand::new("/bin/sh").arg("-c").arg("sleep 30").spawn().unwrap()
    }

    #[async_trait::async_trait]
    impl LineHooks for Fake {
        async fn start(&self, line: Line, role: Role) -> std::result::Result<LineProcess, String> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            if role == Role::Secondary && self.secondary_delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(self.secondary_delay_ms)).await;
            }
            {
                let mut f = self.fail_starts.lock().unwrap();
                if let Some(entry) = f.iter_mut().find(|(l, n)| *l == line && *n > 0) {
                    entry.1 -= 1;
                    return Err(format!("{line} would not start"));
                }
            }
            Ok(LineProcess {
                line,
                lair: sleeper(),
                conductor: sleeper(),
                admin_port: if line == Line::V06 { 1 } else { 2 },
                lair_url: String::new(),
                agents: vec![[9u8; 32]],
                conductor_dir: PathBuf::new(),
                timeouts: Timeouts::default(),
            })
        }
        async fn setup(&self, line: Line, _role: Role, process: &mut LineProcess) -> std::result::Result<u16, String> {
            if self.fail_setup.lock().unwrap().contains(&line) {
                return Err("setup failed".into());
            }
            Ok(process.admin_port + 100)
        }
        async fn before_retry(&self, _line: Line, _error: &str) {
            self.retries.fetch_add(1, Ordering::SeqCst);
        }
        async fn joined(&self, line: Line, role: Role, _session: u64, admin: u16, app: u16) {
            self.events.lock().unwrap().push(format!("joined {line} {role:?} {admin}/{app}"));
        }
        async fn secondary_failed(&self, line: Line, error: &str) {
            self.events.lock().unwrap().push(format!("failed {line}: {error}"));
        }
        async fn secondary_late(&self, line: Line) {
            self.events.lock().unwrap().push(format!("late {line}"));
        }
    }

    async fn wait_for(f: impl Fn() -> bool) {
        for _ in 0..100 {
            if f() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("condition not reached");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_primary_starts_and_the_secondary_joins_its_session() {
        let sup = Arc::new(Supervisor::new("t"));
        let hooks = Arc::new(Fake::default());
        let session = sup.start_lines(Line::V06, Some(Line::V07), hooks.clone()).await.unwrap();
        assert_eq!(sup.primary(), Some(Line::V06));
        wait_for(|| sup.has(Line::V07)).await;
        assert_eq!(sup.session(), Some(session));
        assert_eq!((sup.state(Line::V06), sup.state(Line::V07)), (LineState::Serving, LineState::Serving));
        assert_eq!(*hooks.events.lock().unwrap(), ["joined 0.6 Primary 1/101", "joined 0.7 Secondary 2/102"]);
        sup.stop();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn one_primary_failure_is_retried_two_give_up() {
        let sup = Arc::new(Supervisor::new("t"));
        let once = Arc::new(Fake { fail_starts: Mutex::new(vec![(Line::V07, 1)]), ..Fake::default() });
        sup.start_lines(Line::V07, None, once.clone()).await.unwrap();
        assert_eq!((once.retries.load(Ordering::SeqCst), once.starts.load(Ordering::SeqCst)), (1, 2));
        sup.stop();
        let twice = Arc::new(Fake { fail_starts: Mutex::new(vec![(Line::V07, 2)]), ..Fake::default() });
        assert!(sup.start_lines(Line::V07, None, twice.clone()).await.is_err());
        assert_eq!(sup.session(), None, "no session without a primary");
        let setup_fails = Arc::new(Fake { fail_setup: Mutex::new(vec![Line::V07]), ..Fake::default() });
        assert_eq!(sup.start_lines(Line::V07, None, setup_fails).await.unwrap_err(), "setup failed");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_secondary_leaves_the_session_running() {
        let sup = Arc::new(Supervisor::new("t"));
        let hooks = Arc::new(Fake { fail_starts: Mutex::new(vec![(Line::V06, 1)]), ..Fake::default() });
        let session = sup.start_lines(Line::V07, Some(Line::V06), hooks.clone()).await.unwrap();
        wait_for(|| hooks.events.lock().unwrap().iter().any(|e| e.starts_with("failed"))).await;
        assert_eq!((sup.session(), sup.has(Line::V06), sup.state(Line::V06)), (Some(session), false, LineState::Off));
        sup.stop();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_secondary_after_its_session_ended_is_stopped() {
        let sup = Arc::new(Supervisor::new("t"));
        let hooks = Arc::new(Fake { secondary_delay_ms: 400, ..Fake::default() });
        sup.start_lines(Line::V06, Some(Line::V07), hooks.clone()).await.unwrap();
        // The secondary's start is under way (the second start call) when the session ends.
        wait_for(|| hooks.starts.load(Ordering::SeqCst) == 2).await;
        sup.stop();
        wait_for(|| hooks.events.lock().unwrap().iter().any(|e| e == "late 0.7")).await;
        assert!(!sup.has(Line::V07));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_secondary_whose_session_ended_before_it_began_is_not_started() {
        let sup = Arc::new(Supervisor::new("t"));
        let hooks = Arc::new(Fake::default());
        let session = sup.start_lines(Line::V06, None, hooks.clone()).await.unwrap();
        sup.stop();
        sup.attach_line(session, Line::V07, hooks.clone());
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(hooks.starts.load(Ordering::SeqCst), 1, "only the primary was started");
    }
}
