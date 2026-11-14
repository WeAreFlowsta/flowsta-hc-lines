//! The lines of one data root.
//!
//! [`start_line`] starts one line, key store through conductor: the app then
//! installs its DNAs on the admin port and attaches its app interface. Any
//! failure stops what the start had started, conductor first.

use crate::conductor::{self, NetworkTuning};
use crate::keystore::{self, SocketPlan};
use crate::process::{stop_gracefully, SidecarChild, StopOutcome, StopRequest};
use crate::rendezvous::Rendezvous;
use crate::{Error, Line, Result};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

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
    /// what this avoids. The conductor is asked with SIGINT, the one signal
    /// it shuts down on (with SIGTERM both lines' conductors ended about
    /// 0.1 s after the request, without their shutdown); lair in under 10 ms.
    ///
    /// A conductor with its network up often outlasts its grace whatever the
    /// grace: Holochain 0.6.1 and 0.7.1 stop every managed task (the
    /// workflows that write) within a millisecond of SIGINT, then leave
    /// their network running, so the process does not exit by itself
    /// (holochain#6010, fixed after 0.7.1). Traced on a 0.6.1 conductor: all
    /// 28 managed tasks done 1 ms after the signal, gossip still running
    /// 25 s later, killed at a 30 s grace. A longer grace only waits longer.
    pub fn stop(&mut self) -> StopReport {
        let (line, conductor_grace, lair_grace) = (self.line, self.timeouts.conductor_stop, self.timeouts.lair_stop);
        let report = StopReport {
            conductor: stop_gracefully(&mut self.conductor, StopRequest::Interrupt, conductor_grace),
            lair: stop_gracefully(&mut self.lair, StopRequest::Terminate, lair_grace),
        };
        for (what, outcome, grace) in [
            ("conductor", &report.conductor, conductor_grace),
            ("key store", &report.lair, lair_grace),
        ] {
            match outcome {
                Ok(StopOutcome::Killed) if what == "conductor" => log::info!(
                    "[{line}] the conductor was asked to stop and was ended after {grace:?}: this Holochain leaves its network running after it shuts down (holochain#6010), so it does not exit by itself"
                ),
                Ok(StopOutcome::Killed) => log::warn!("[{line}] the {what} did not stop within {grace:?} and was killed"),
                Ok(_) => log::info!("[{line}] the {what} stopped"),
                Err(e) => log::warn!("[{line}] stopping the {what}: {e}"),
            }
        }
        report
    }
}

fn stop_child(child: &mut SidecarChild, request: StopRequest, grace: Duration) {
    let _ = stop_gracefully(child, request, grace);
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

/// Connect to a running key store and ensure one agent, on the line's own
/// client crate.
macro_rules! ensure_one_agent {
    ($v:ident, $url:expr, $passphrase:expr, $source:expr) => {{
        let client = keystore::$v::connect($url, $passphrase, Duration::from_secs(30)).await?;
        match $source {
            KeySource::Seed { seed, tag } => keystore::$v::import_seed(&client, seed, tag).await,
            KeySource::NewSeed { tag } => keystore::$v::new_seed(&client, tag).await,
            KeySource::Existing { tag } => keystore::$v::existing(&client, tag).await,
        }
    }};
}

/// One agent on the key store at `url` (a running line's), by the same rules
/// as a start's ([`KeySource`]).
async fn agent_on(line: Line, url: &str, passphrase: &str, source: &KeySource) -> Result<[u8; 32]> {
    match line {
        #[cfg(feature = "line-06")]
        Line::V06 => ensure_one_agent!(v06, url, passphrase, source),
        #[cfg(feature = "line-07")]
        Line::V07 => ensure_one_agent!(v07, url, passphrase, source),
        #[allow(unreachable_patterns)]
        other => Err(Error::LineNotCompiled(other)),
    }
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
            stop_child(&mut lair, StopRequest::Terminate, s.timeouts.lair_stop);
            return Err(e);
        }
    };

    on_step(StartStep::Conductor);
    // Ports another process took as this conductor started (another app's
    // or account's conductor starting at the same moment): the next is tried.
    let mut taken: Vec<u16> = Vec::new();
    let (admin_port, conductor) = loop {
        let candidates: Vec<u16> = s.admin_ports.iter().copied().filter(|p| !taken.contains(p)).collect();
        if candidates.is_empty() {
            stop_child(&mut lair, StopRequest::Terminate, s.timeouts.lair_stop);
            return Err(conductor::ConductorError::PortsTaken { candidates: s.admin_ports.to_vec() }.into());
        }
        let conductor_up = async {
            let admin_port = conductor::pick_admin_port(&candidates)?;
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
                stop_child(&mut lair, StopRequest::Terminate, s.timeouts.lair_stop);
                return Err(e);
            }
        };

        on_step(StartStep::WaitAdmin);
        match conductor::wait_admin(admin_port, s.origin, s.timeouts.admin, &mut conductor, s.conductor_dir).await {
            Ok(()) => break (admin_port, conductor),
            Err(Error::Conductor(conductor::ConductorError::PortTakenAtStart { port, .. })) => {
                stop_child(&mut conductor, StopRequest::Interrupt, s.timeouts.conductor_stop);
                log::warn!("[{}] another process took admin port {port} as this conductor started; trying the next", s.line);
                taken.push(port);
            }
            Err(e) => {
                stop_child(&mut conductor, StopRequest::Interrupt, s.timeouts.conductor_stop);
                stop_child(&mut lair, StopRequest::Terminate, s.timeouts.lair_stop);
                return Err(e);
            }
        }
    };
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
    /// Line starts under way: from a start's first step until its line is in
    /// a session or stopped again ([`Supervisor::wait_for_starts`]).
    starting: std::sync::atomic::AtomicUsize,
    rendezvous: std::sync::Mutex<[Option<String>; 2]>,
    keeper_started: std::sync::atomic::AtomicBool,
    reachable: [std::sync::atomic::AtomicU64; 2],
    last_rounds: std::sync::Mutex<[Option<KeeperStatus>; 2]>,
}

/// A line's last keeper round ([`Supervisor::last_round`]).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct KeeperStatus {
    pub at: std::time::SystemTime,
    /// The servers the keeper asks.
    pub servers: usize,
    pub round: crate::keeper::Round,
    /// How long the keeper has been registering for the conductor, whose own
    /// registration did not reach its server; None while it registers itself.
    pub stalled_for: Option<Duration>,
    /// The rendezvous the conductor was configured with.
    pub conductor: Option<String>,
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

/// One line start under way ([`Supervisor::wait_for_starts`]).
pub struct StartGuard<'a>(&'a std::sync::atomic::AtomicUsize);

impl Drop for StartGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
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
            starting: std::sync::atomic::AtomicUsize::new(0),
            rendezvous: std::sync::Mutex::new([None, None]),
            keeper_started: std::sync::atomic::AtomicBool::new(false),
            reachable: [std::sync::atomic::AtomicU64::new(0), std::sync::atomic::AtomicU64::new(0)],
            last_rounds: std::sync::Mutex::new([None, None]),
        }
    }

    /// Keeper rounds on `line` in which a rendezvous answered, for this
    /// supervisor's life: the rounds a device was online on that line (what
    /// a listen window counts, [`crate::marker::ListenTally`]).
    pub fn reachable_rounds(&self, line: Line) -> u64 {
        self.reachable[slot(line)].load(std::sync::atomic::Ordering::SeqCst)
    }

    fn count_round(&self, line: Line, round: &crate::keeper::Round) {
        if round.reached > 0 {
            self.reachable[slot(line)].fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// `line`'s last keeper round, for an app's diagnostics; None before the
    /// first (about 70 s after the keeper starts).
    pub fn last_round(&self, line: Line) -> Option<KeeperStatus> {
        self.last_rounds.lock().unwrap()[slot(line)].clone()
    }

    fn record_round(&self, line: Line, status: KeeperStatus) {
        self.last_rounds.lock().unwrap()[slot(line)] = Some(status);
    }

    /// Record the rendezvous `line`'s conductor was configured with at its
    /// start (the main one, or the first fallback that answered when it was
    /// dark). The keeper calls a stall only against this one: a conductor
    /// never registers anywhere else.
    pub fn set_rendezvous(&self, line: Line, url: Option<&str>) {
        self.rendezvous.lock().unwrap()[slot(line)] = url.map(|u| u.trim_end_matches('/').to_string());
    }

    /// The rendezvous `line`'s conductor was configured with (None: not
    /// recorded; the keeper then takes the first server it was given).
    pub fn rendezvous(&self, line: Line) -> Option<String> {
        self.rendezvous.lock().unwrap()[slot(line)].clone()
    }

    /// Keep each running line's agents listed on its rendezvous: one
    /// [`crate::keeper::Keeper`] per line with servers, every 60 s after the
    /// first 70 s (the conductor's own first registration has had its
    /// chance), for as long as this supervisor lives. Each round asks which
    /// lines run, on which port and under which origin (a new start brings
    /// new conductors and a new origin) and skips a line that does not run.
    /// `servers`: the 0.6 line's `(bootstrap URL, auth material)` list, then
    /// the 0.7 line's, the conductor's own rendezvous first. Started once per
    /// supervisor; call it from within a tokio runtime.
    pub fn start_keeper(self: &std::sync::Arc<Self>, servers: [Vec<(String, Option<String>)>; 2]) {
        if servers.iter().all(|s| s.is_empty()) {
            log::info!("[rendezvous] no rendezvous configured - nothing to keep");
            return;
        }
        if self.keeper_started.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let weak = std::sync::Arc::downgrade(self);
        tokio::spawn(async move {
            // A gap this long between two rounds means the machine was asleep.
            const WOKE_AFTER: std::time::Duration = std::time::Duration::from_secs(150);
            let mut keepers = [
                crate::keeper::Keeper::new(crate::keeper::servers_from(&servers[0])),
                crate::keeper::Keeper::new(crate::keeper::servers_from(&servers[1])),
            ];
            let mut last_tick = std::time::SystemTime::now();
            let mut wait = std::time::Duration::from_secs(70);
            loop {
                tokio::time::sleep(wait).await;
                wait = std::time::Duration::from_secs(60);
                let now = std::time::SystemTime::now();
                if let Ok(gap) = now.duration_since(last_tick) {
                    if gap > wait + WOKE_AFTER {
                        log::info!("[rendezvous] back after {} min away - checking the rendezvous now", gap.as_secs() / 60);
                    }
                }
                last_tick = now;
                let Some(sup) = weak.upgrade() else { return };
                for line in LINES {
                    if servers[slot(line)].is_empty() {
                        continue;
                    }
                    let Some((admin_port, _)) = sup.ports(line) else { continue };
                    let label = if line == Line::V06 { "[rendezvous]" } else { "[rendezvous 0.7]" };
                    let admin = match crate::admin::AdminClient::connect(line, admin_port, &sup.origin()).await {
                        Ok(a) => a,
                        Err(e) => {
                            log::debug!("{label} round skipped: admin: {e}");
                            continue;
                        }
                    };
                    let conductor = sup.rendezvous(line);
                    let keeper = &mut keepers[slot(line)];
                    match keeper.run_once(&admin, conductor.as_deref()).await {
                        Ok(round) => {
                            sup.count_round(line, &round);
                            sup.record_round(
                                line,
                                KeeperStatus { at: std::time::SystemTime::now(), servers: keeper.server_count(), round, stalled_for: keeper.stalled_for(), conductor },
                            );
                        }
                        Err(e) => log::debug!("{label} round skipped: {e}"),
                    }
                }
            }
        });
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
    /// Ensure one more agent on a running line, for an app that makes agents
    /// while it runs (a new AI, a new member). The key comes from the line's
    /// own key store at its running address, by the same rules as a start
    /// ([`KeySource`]); `passphrase` is the one the line started with (the
    /// supervisor does not keep it). Installing the agent's app is the app's
    /// next step, through the admin client. Each line's store is separate:
    /// an agent needed on both lines is added on each (a [`KeySource::Seed`]
    /// gives the same key on both).
    pub async fn add_agent(&self, line: Line, passphrase: &str, source: &KeySource) -> Result<[u8; 32]> {
        let url = self.current.lock().unwrap().lines[slot(line)].as_ref().map(|r| r.process.lair_url.clone());
        let url = url.ok_or(Error::LineNotRunning(line))?;
        agent_on(line, &url, passphrase, source).await
    }

    /// The address of `line`'s key store while it runs, for
    /// [`crate::admin::Signing::KeyStore`]. It carries the connection key:
    /// never log it.
    pub fn key_store_url(&self, line: Line) -> Option<String> {
        self.current.lock().unwrap().lines[slot(line)].as_ref().map(|r| r.process.lair_url.clone())
    }

    pub fn agent_key(&self) -> Option<[u8; 32]> {
        self.current.lock().unwrap().agent_key
    }

    /// Begin a session on its primary line, which is up. A session still
    /// running is ended first; its lines are returned for the caller to stop.
    pub fn begin_session(&self, primary: RunningLine, agent_key: [u8; 32]) -> (u64, Vec<RunningLine>) {
        self.begin_session_if(primary, agent_key, || true).unwrap_or_else(|_| unreachable!())
    }

    /// [`Supervisor::begin_session`] when `wanted` still holds, asked under
    /// the session's lock: a stop the app makes after `wanted` turns false
    /// either comes first (the line is handed back, to be stopped) or finds
    /// the session to end.
    fn begin_session_if(&self, primary: RunningLine, agent_key: [u8; 32], wanted: impl Fn() -> bool) -> std::result::Result<(u64, Vec<RunningLine>), RunningLine> {
        let line = primary.line();
        let (id, old) = {
            let mut s = self.current.lock().unwrap();
            if !wanted() {
                return Err(primary);
            }
            let id = self.sessions.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            let old: Vec<RunningLine> = s.lines.iter_mut().filter_map(Option::take).collect();
            *s = Session { id, primary: Some(line), agent_key: Some(agent_key), lines: [None, None] };
            s.lines[slot(line)] = Some(primary);
            (id, old)
        };
        let mut states = self.states.lock().unwrap();
        *states = [LineState::Off; 2];
        states[slot(line)] = LineState::Serving;
        Ok((id, old))
    }

    /// Wait, blocking, until no line's start is under way, up to `within`;
    /// whether none is. A start the app no longer wants
    /// ([`LineHooks::wanted`]) ends at its next step, so after the app stops
    /// wanting its starts this is how long until nothing writes to their
    /// folders (before removing them, say).
    pub fn wait_for_starts(&self, within: Duration) -> bool {
        let until = Instant::now() + within;
        loop {
            if self.starting.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                return true;
            }
            if Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Count a start under way until the guard drops. The app holds one
    /// over its own steps before [`Supervisor::start_lines`] that write into
    /// the lines' folders, so [`Supervisor::wait_for_starts`] waits for
    /// those too; check [`LineHooks::wanted`]'s condition after taking it.
    pub fn start_under_way(&self) -> StartGuard<'_> {
        self.starting.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        StartGuard(&self.starting)
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

    /// The process id of `line`'s conductor; None without that line.
    pub fn conductor_pid(&self, line: Line) -> Option<u32> {
        self.current.lock().unwrap().lines[slot(line)].as_ref().map(|l| l.process.conductor.id())
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

    /// Retire `line` for this session: [`Supervisor::stop_line`], once the
    /// calls on it are done. Its ports go first, so no new call reaches it;
    /// the calls already on it ([`crate::client::calling`]) get up to `drain`
    /// to finish (seen in the field: a read in flight was cut by the stop);
    /// then it stops as any line does. Blocking: up to `drain` plus the
    /// line's stop graces.
    pub fn retire_line(&self, line: Line, drain: Duration) {
        let taken = self.current.lock().unwrap().lines[slot(line)].take();
        if let Some(mut l) = taken {
            let started = Instant::now();
            while crate::client::in_flight(line) > 0 && started.elapsed() < drain {
                std::thread::sleep(Duration::from_millis(100));
            }
            match crate::client::in_flight(line) {
                0 if started.elapsed() >= Duration::from_secs(1) => {
                    log::info!("[{line}] the calls in flight finished in {} s", started.elapsed().as_secs())
                }
                0 => {}
                n => log::warn!("[{line}] {n} call(s) still in flight after {} s: stopping the line anyway", drain.as_secs()),
            }
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

/// What a line's [`LineHooks::setup`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Setup {
    /// The app interface's port.
    pub app_port: u16,
    /// Restart the line once before it joins. Holochain 0.7.1 keeps the
    /// memory an install used until its conductor restarts: every module it
    /// drops from its cache (after each new cell's genesis, and after an
    /// hour idle) is reloaded into one runtime engine that keeps the old
    /// copy's machine code. A new identity's 0.7 conductor held ~2 GB after
    /// installing three apps, 419 MB after one restart (11-03).
    pub restart: bool,
}

impl From<u16> for Setup {
    fn from(app_port: u16) -> Self {
        Setup { app_port, restart: false }
    }
}

/// What an app supplies for its lines; the supervisor runs the order.
#[async_trait::async_trait]
pub trait LineHooks: Send + Sync + 'static {
    /// Start one line's key store and conductor, normally with [`start_line`]
    /// and the app's settings for that line.
    async fn start(&self, line: Line, role: Role) -> std::result::Result<LineProcess, String>;
    /// Install the app's DNAs on a line that just came up and attach its app
    /// interface; returns the app port (`port.into()`), or asks for one
    /// restart before the line joins ([`Setup::restart`]: the second setup
    /// is the one that counts). A failure stops the line.
    async fn setup(&self, line: Line, role: Role, process: &mut LineProcess) -> std::result::Result<Setup, String>;
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
    /// Whether the app still wants this start (by default, always): false
    /// once it locked, erased or quit since asking for it. Asked before each
    /// step of a line's start and again as the primary's session begins. A
    /// start no longer wanted stops what it started and ends with
    /// [`NOT_WANTED`]: a stop the app makes after this turns false never
    /// misses a line that was still starting.
    fn wanted(&self) -> bool {
        true
    }
}

/// The error of a start the app no longer wanted ([`LineHooks::wanted`]).
pub const NOT_WANTED: &str = "the start is no longer wanted";

async fn stop_process(mut process: LineProcess) {
    let _ = tokio::task::spawn_blocking(move || {
        process.stop();
    })
    .await;
}

/// Start and set up one line, restarted once when its setup asks
/// ([`Setup::restart`]); a setup failure, or a start no longer wanted,
/// stops what was started.
async fn start_and_setup(hooks: &dyn LineHooks, line: Line, role: Role) -> std::result::Result<RunningLine, String> {
    let mut restarted = false;
    loop {
        if !hooks.wanted() {
            return Err(NOT_WANTED.into());
        }
        let mut process = hooks.start(line, role).await?;
        if !hooks.wanted() {
            log::info!("[{line}] no longer wanted as it came up - stopped");
            stop_process(process).await;
            return Err(NOT_WANTED.into());
        }
        match hooks.setup(line, role, &mut process).await {
            Ok(_) if !hooks.wanted() => {
                log::info!("[{line}] no longer wanted as its setup ended - stopped");
                stop_process(process).await;
                return Err(NOT_WANTED.into());
            }
            Ok(setup) if setup.restart && !restarted => {
                log::info!("[{line}] apps installed this start: restarting the line once to give back the memory the install kept");
                stop_process(process).await;
                restarted = true;
            }
            Ok(setup) => return Ok(RunningLine { process, app_port: setup.app_port }),
            Err(e) => {
                stop_process(process).await;
                return Err(e);
            }
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
        let _starting = self.start_under_way();
        let running = match start_and_setup(hooks.as_ref(), primary, Role::Primary).await {
            Ok(r) => r,
            Err(e) if !hooks.wanted() => {
                match e.as_str() {
                    NOT_WANTED => log::info!("[{primary}] the start is no longer wanted"),
                    _ => log::info!("[{primary}] the start is no longer wanted (it had failed: {e})"),
                }
                return Err(NOT_WANTED.into());
            }
            Err(e) => {
                log::warn!("[{primary}] the primary line did not start ({e}) - one more try");
                hooks.before_retry(primary, &e).await;
                tokio::time::sleep(Duration::from_secs(2)).await;
                start_and_setup(hooks.as_ref(), primary, Role::Primary).await?
            }
        };
        let (admin_port, app_port) = (running.admin_port(), running.app_port);
        let key = running.process.agents.first().copied().unwrap_or([0u8; 32]);
        let (session, leftover) = match self.begin_session_if(running, key, || hooks.wanted()) {
            Ok(begun) => begun,
            Err(unwanted) => {
                log::info!("[{primary}] no longer wanted as its session would begin - stopped");
                stop_process(unwanted.process).await;
                return Err(NOT_WANTED.into());
            }
        };
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
            let _starting = sup.start_under_way();
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
                    if e != NOT_WANTED {
                        hooks.secondary_failed(line, &e).await;
                    }
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

    /// Calls signed with the agent's own key through the key store, on both
    /// lines with the real binaries: the conductor takes them, connecting
    /// any number of times writes nothing to the chain (a signing grant
    /// writes one action each time), and the no-write probe tells a running
    /// cell from a stopped one.
    ///
    /// `HC_LINES_LAIR_06= HC_LINES_LAIR_07= HC_LINES_CONDUCTOR_06= HC_LINES_CONDUCTOR_07= HC_LINES_HAPP_06= HC_LINES_HAPP_07= HC_LINES_HAPP_ROLE= cargo test --lib -- --ignored live_calls_signed`
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn live_calls_signed_by_the_key_store_write_nothing() {
        use crate::admin::{AdminClient, AppConnect, InstallRequest, Signing};
        use crate::client::ZomeErrorKind;
        let var = |v: &str| std::env::var(v).unwrap_or_else(|_| panic!("set {v}"));
        let role = var("HC_LINES_HAPP_ROLE");
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let sockets = SocketPlan::new("hcl-signed", "lair");
        let origin = conductor::fresh_origin("hcl");
        let rendezvous = Rendezvous::new("https://127.0.0.1:9");
        let agents = [KeySource::Seed { seed: [6u8; 32], tag: "device".into() }];
        for (line, lair, cond, happ, lair_dir, cond_dir, ports) in [
            (Line::V07, "HC_LINES_LAIR_07", "HC_LINES_CONDUCTOR_07", "HC_LINES_HAPP_07", "lair-07", "conductor-07", [47822u16, 47823]),
            (Line::V06, "HC_LINES_LAIR_06", "HC_LINES_CONDUCTOR_06", "HC_LINES_HAPP_06", "lair", "conductor", [47820, 47821]),
        ] {
            let (lair_bin, cond_bin, happ) = (PathBuf::from(var(lair)), PathBuf::from(var(cond)), PathBuf::from(var(happ)));
            let tuning = NetworkTuning::for_line(line);
            let mut p = start_line(
                &LineStart { line, lair_bin: &lair_bin, conductor_bin: &cond_bin, lair_dir: &root.join(lair_dir), conductor_dir: &root.join(cond_dir), passphrase: "live", sockets: &sockets, admin_ports: &ports, origin: &origin, rendezvous: &rendezvous, tuning: &tuning, agents: &agents, timeouts: Timeouts::default() },
                |_| {},
            )
            .await
            .unwrap_or_else(|e| panic!("{line}: {e}"));
            let admin = AdminClient::connect(line, p.admin_port, &origin).await.unwrap();
            // The 39-byte agent key: the 3-byte prefix, the key, its 4-byte location.
            let agent_key = crate::v07::holochain_types::prelude::AgentPubKey::from_raw_32(p.agents[0].to_vec()).get_raw_39().to_vec();
            admin.install(&InstallRequest { app_id: "signed", bundle: &happ, agent_key: &agent_key, network_seed: Some("signed") }).await.unwrap();
            admin.enable("signed").await.unwrap();
            let cell = admin.app_cell("signed", &role).await.unwrap();
            let app_port = admin.attach_app_interface(&origin).await.unwrap();
            let connect = || async {
                admin
                    .connect_app(AppConnect { app_port, origin: &origin, app_id: "signed", cell: &cell, signing: Signing::KeyStore { url: &p.lair_url, passphrase: "live" }, request_timeout: Duration::from_secs(120) })
                    .await
                    .unwrap_or_else(|e| panic!("{line}: {e:?}"))
            };
            assert_eq!(admin.chain_head(&cell).await.unwrap(), Some(2), "{line}: a new chain holds its three first actions");
            // The first call of any kind runs the cell's init: one action.
            let first = connect().await;
            first.cell_runs(&role).await.unwrap_or_else(|e| panic!("{line}: {e:?}"));
            let head = admin.chain_head(&cell).await.unwrap();
            assert_eq!(head, Some(3), "{line}: init, and nothing else");
            for _ in 0..3 {
                let again = connect().await;
                again.cell_runs(&role).await.unwrap();
                assert_eq!(admin.chain_head(&cell).await.unwrap(), head, "{line}: another connection wrote nothing");
            }
            admin.disable("signed").await.unwrap();
            let stopped = first.cell_runs(&role).await.expect_err("a stopped cell does not run");
            assert_eq!(stopped.kind, ZomeErrorKind::CellNotRunning, "{line}: {}", stopped.detail);
            admin.enable("signed").await.unwrap();
            first.cell_runs(&role).await.unwrap();
            assert_eq!(admin.chain_head(&cell).await.unwrap(), head, "{line}: the probe wrote nothing");
            // What it replaces: each grant is one write.
            let _grant = admin.authorize_signing(&cell).await.unwrap();
            assert_eq!(admin.chain_head(&cell).await.unwrap(), head.map(|h| h + 1), "{line}: a grant is one chain write");
            let report = p.stop();
            assert!(matches!(report.conductor, Ok(StopOutcome::Exited)), "{line}: {:?}", report.conductor);
        }
    }

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
            // An agent made while the line runs (a new AI): a new seed, the
            // same key for the same tag again, found as an existing tag.
            let made = agent_on(line, &p.lair_url, "live", &KeySource::NewSeed { tag: "ai-2".into() }).await.unwrap();
            assert_ne!(made, p.agents[0]);
            assert_eq!(agent_on(line, &p.lair_url, "live", &KeySource::NewSeed { tag: "ai-2".into() }).await.unwrap(), made);
            assert_eq!(agent_on(line, &p.lair_url, "live", &KeySource::Existing { tag: "ai-2".into() }).await.unwrap(), made);
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

        // Another process takes the picked port before the conductor binds it
        // (another conductor starting at the same moment, which refuses this
        // start's origin): the start goes on to the next port.
        let free = || std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port();
        let (first, second) = (free(), free());
        assert_ne!(first, second);
        let mut squatted = false;
        let mut steps = Vec::new();
        let mut p = start_line(
            &LineStart {
                line: Line::V07,
                lair_bin: &lair_bin,
                conductor_bin: &cond_bin,
                lair_dir: &lair_dir,
                conductor_dir: &root.join("conductor-07"),
                passphrase: "live",
                sockets: &sockets,
                admin_ports: &[first, second],
                origin: &origin,
                rendezvous: &rendezvous,
                tuning: &tuning,
                agents: &agents,
                timeouts: Timeouts::default(),
            },
            |step| {
                steps.push(step);
                if step == StartStep::WaitAdmin && !squatted {
                    squatted = true;
                    let other = std::net::TcpListener::bind(("127.0.0.1", first)).expect("the port is still free right after the spawn");
                    std::thread::spawn(move || {
                        use std::io::{Read, Write};
                        for mut stream in other.incoming().flatten() {
                            let mut request = [0u8; 1024];
                            let _ = stream.read(&mut request);
                            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
                        }
                    });
                }
            },
        )
        .await
        .unwrap_or_else(|e| panic!("the start after a taken port: {e}"));
        assert_eq!(p.admin_port, second);
        assert_eq!(steps.iter().filter(|s| **s == StartStep::WaitAdmin).count(), 2, "{steps:?}");
        let report = p.stop();
        assert!(matches!(report.conductor, Ok(StopOutcome::Exited)), "{:?}", report.conductor);
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
    fn a_retirement_waits_for_the_calls_in_flight_then_stops_the_line() {
        let sup = Supervisor::new("t");
        // (A stop takes up to its grace, a short one here: all of it where
        // /bin/sh waits on its sleep child and SIGINT ends neither (dash),
        // almost none where the shell execs sleep (macOS). So the checks
        // below count the call and the drain, not the stop.)
        let quick = |line: Line, port: u16| {
            let mut r = running(line, port);
            r.process.timeouts.conductor_stop = Duration::from_millis(200);
            r
        };
        let (_, _) = sup.begin_session(running(Line::V07, 11), [1u8; 32]);
        let session = sup.session().unwrap();
        assert!(sup.attach(session, quick(Line::V06, 12)).is_ok());

        // A call on the line finishes 300 ms in: the retirement waits for it.
        // (The clock starts before the call's thread, so the call ends at
        // least 300 ms after it.)
        let t = Instant::now();
        let call = crate::client::calling(Line::V06);
        let ending = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            drop(call);
        });
        sup.retire_line(Line::V06, Duration::from_secs(5));
        ending.join().unwrap();
        assert!(t.elapsed() >= Duration::from_millis(300), "{:?}", t.elapsed());
        assert!(t.elapsed() < Duration::from_secs(3), "waited for the call, not the drain: {:?}", t.elapsed());
        assert_eq!((sup.ports(Line::V06), sup.state(Line::V06)), (None, LineState::Off));
        assert_eq!(sup.ports(Line::V07), Some((11, 111)), "the session goes on");

        // A call that never ends holds it no longer than the drain.
        assert!(sup.attach(session, quick(Line::V06, 13)).is_ok());
        let stuck = crate::client::calling(Line::V06);
        let t = Instant::now();
        sup.retire_line(Line::V06, Duration::from_millis(400));
        assert!((Duration::from_millis(400)..Duration::from_secs(3)).contains(&t.elapsed()), "{:?}", t.elapsed());
        assert_eq!(sup.ports(Line::V06), None);
        drop(stuck);
        assert_eq!(crate::client::in_flight(Line::V06), 0);
        sup.stop();
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
    fn a_round_counts_as_reachable_only_when_a_rendezvous_answered() {
        let sup = Supervisor::new("t");
        sup.count_round(Line::V06, &crate::keeper::Round::default());
        sup.count_round(Line::V06, &crate::keeper::Round { reached: 1, ..Default::default() });
        sup.count_round(Line::V07, &crate::keeper::Round { reached: 2, ..Default::default() });
        sup.count_round(Line::V06, &crate::keeper::Round { reached: 1, ..Default::default() });
        assert_eq!((sup.reachable_rounds(Line::V06), sup.reachable_rounds(Line::V07)), (2, 1));
    }

    #[test]
    fn each_lines_last_round_is_kept_for_the_app() {
        let sup = Supervisor::new("t");
        assert!(sup.last_round(Line::V06).is_none(), "nothing before the first round");
        let status = |reached| KeeperStatus {
            at: std::time::SystemTime::now(),
            servers: 2,
            round: crate::keeper::Round { reached, ..Default::default() },
            stalled_for: None,
            conductor: Some("https://b.example.com".into()),
        };
        sup.record_round(Line::V06, status(1));
        sup.record_round(Line::V06, status(2));
        sup.record_round(Line::V07, status(0));
        assert_eq!(sup.last_round(Line::V06).unwrap().round.reached, 2, "the latest round");
        assert_eq!(sup.last_round(Line::V07).unwrap().round.reached, 0);
    }

    #[test]
    fn the_apps_own_steps_before_a_start_are_waited_for() {
        let sup = Supervisor::new("t");
        assert!(sup.wait_for_starts(Duration::ZERO));
        let first = sup.start_under_way();
        let second = sup.start_under_way();
        assert!(!sup.wait_for_starts(Duration::from_millis(60)));
        drop(first);
        assert!(!sup.wait_for_starts(Duration::from_millis(60)), "one is still under way");
        std::thread::scope(|s| {
            s.spawn(move || {
                std::thread::sleep(Duration::from_millis(150));
                drop(second);
            });
            assert!(sup.wait_for_starts(Duration::from_secs(5)));
        });
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
        /// Setups that ask for a restart (every time).
        restart_setup: Mutex<Vec<Line>>,
        secondary_delay_ms: u64,
        primary_delay_ms: u64,
        /// The app stopped wanting its starts (it locked, say).
        unwanted: std::sync::atomic::AtomicBool,
        /// Its setups stop wanting them, as a lock during an install would.
        unwant_in_setup: bool,
        /// The conductor pid of each line started.
        pids: Mutex<Vec<u32>>,
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
            if role == Role::Primary && self.primary_delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(self.primary_delay_ms)).await;
            }
            {
                let mut f = self.fail_starts.lock().unwrap();
                if let Some(entry) = f.iter_mut().find(|(l, n)| *l == line && *n > 0) {
                    entry.1 -= 1;
                    return Err(format!("{line} would not start"));
                }
            }
            let conductor = sleeper();
            self.pids.lock().unwrap().push(conductor.id());
            Ok(LineProcess {
                line,
                lair: sleeper(),
                conductor,
                admin_port: if line == Line::V06 { 1 } else { 2 },
                lair_url: String::new(),
                agents: vec![[9u8; 32]],
                conductor_dir: PathBuf::new(),
                // (The sleepers ignore SIGINT: each stop takes its grace.)
                timeouts: Timeouts { conductor_stop: Duration::from_millis(200), lair_stop: Duration::from_millis(200), ..Timeouts::default() },
            })
        }
        async fn setup(&self, line: Line, _role: Role, process: &mut LineProcess) -> std::result::Result<Setup, String> {
            if self.unwant_in_setup {
                self.unwanted.store(true, Ordering::SeqCst);
            }
            if self.fail_setup.lock().unwrap().contains(&line) {
                return Err("setup failed".into());
            }
            let restart = self.restart_setup.lock().unwrap().contains(&line);
            Ok(Setup { app_port: process.admin_port + 100, restart })
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
        fn wanted(&self) -> bool {
            !self.unwanted.load(Ordering::SeqCst)
        }
    }

    impl Fake {
        fn none_running(&self) -> bool {
            self.pids.lock().unwrap().iter().all(|p| !crate::process::pid_alive(*p))
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

    /// A setup that installed apps asks for a restart: the line starts
    /// twice, joins once with the second setup's port, and is never
    /// restarted a second time, even when that setup asks again.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_setup_that_asks_restarts_the_line_once() {
        let sup = Arc::new(Supervisor::new("t"));
        let hooks = Arc::new(Fake { restart_setup: Mutex::new(vec![Line::V07]), ..Fake::default() });
        sup.start_lines(Line::V07, Some(Line::V06), hooks.clone()).await.unwrap();
        wait_for(|| sup.has(Line::V06)).await;
        assert_eq!(hooks.starts.load(Ordering::SeqCst), 3, "0.7 twice, 0.6 once");
        assert_eq!(*hooks.events.lock().unwrap(), ["joined 0.7 Primary 2/102", "joined 0.6 Secondary 1/101"]);
        assert_eq!(sup.state(Line::V07), LineState::Serving);
        sup.stop();
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

    /// A start the app no longer wants (it locked or erased since asking)
    /// starts nothing, or stops what it started, and is never retried.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_start_no_longer_wanted_stops_what_it_started() {
        let sup = Arc::new(Supervisor::new("t"));
        let before = Arc::new(Fake::default());
        before.unwanted.store(true, Ordering::SeqCst);
        assert_eq!(sup.start_lines(Line::V07, Some(Line::V06), before.clone()).await.unwrap_err(), NOT_WANTED);
        assert_eq!(before.starts.load(Ordering::SeqCst), 0, "nothing started");

        let during = Arc::new(Fake { unwant_in_setup: true, ..Fake::default() });
        assert_eq!(sup.start_lines(Line::V07, Some(Line::V06), during.clone()).await.unwrap_err(), NOT_WANTED);
        assert_eq!((during.starts.load(Ordering::SeqCst), during.retries.load(Ordering::SeqCst)), (1, 0), "not retried");
        assert!(during.none_running(), "the line it started was stopped");
        assert_eq!((sup.session(), sup.state(Line::V07)), (None, LineState::Off));
        assert!(sup.wait_for_starts(Duration::ZERO));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(during.starts.load(Ordering::SeqCst), 1, "no secondary either");
    }

    /// The app locks while its primary line is still starting, before there
    /// is a session to stop: the start ends at its next step with nothing
    /// left running, and `wait_for_starts` holds until it has.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_stop_while_the_primary_starts_leaves_nothing_running() {
        let sup = Arc::new(Supervisor::new("t"));
        let hooks = Arc::new(Fake { primary_delay_ms: 600, ..Fake::default() });
        let starting = tokio::spawn({
            let (sup, hooks) = (sup.clone(), hooks.clone());
            async move { sup.start_lines(Line::V07, Some(Line::V06), hooks).await }
        });
        wait_for(|| hooks.starts.load(Ordering::SeqCst) == 1).await;
        assert!(!sup.wait_for_starts(Duration::from_millis(50)), "the primary is still starting");
        // The app's lock: it stops wanting the start, then stops the lines.
        hooks.unwanted.store(true, Ordering::SeqCst);
        assert!(!sup.stop(), "no session yet to stop");
        let s = sup.clone();
        assert!(tokio::task::spawn_blocking(move || s.wait_for_starts(Duration::from_secs(10))).await.unwrap());
        assert_eq!(starting.await.unwrap().unwrap_err(), NOT_WANTED);
        assert!(hooks.none_running());
        assert_eq!((sup.session(), hooks.starts.load(Ordering::SeqCst)), (None, 1));
    }
}

#[cfg(test)]
mod rendezvous_tests {
    use super::*;

    #[test]
    fn the_conductors_rendezvous_is_kept_per_line() {
        let s = Supervisor::new("t");
        assert_eq!(s.rendezvous(Line::V06), None, "not recorded: the keeper takes the first server");
        s.set_rendezvous(Line::V06, Some("https://node1.flowsta.com/"));
        assert_eq!(s.rendezvous(Line::V06).as_deref(), Some("https://node1.flowsta.com"));
        assert_eq!(s.rendezvous(Line::V07), None, "each line its own");
        s.set_rendezvous(Line::V06, None);
        assert_eq!(s.rendezvous(Line::V06), None);
    }
}

#[cfg(test)]
mod add_agent_tests {
    use super::*;

    #[tokio::test]
    async fn an_agent_is_added_only_to_a_running_line() {
        let s = Supervisor::new("t");
        let err = s.add_agent(Line::V07, "p", &KeySource::NewSeed { tag: "ai-1".into() }).await.unwrap_err();
        assert!(matches!(err, Error::LineNotRunning(Line::V07)), "{err}");
        assert_eq!(err.to_string(), "Holochain line 0.7 is not running");
    }
}
