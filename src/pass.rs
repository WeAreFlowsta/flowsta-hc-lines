//! The copy pass: what an identity holds on its previous line is written to
//! the current one, checked by reading it back, and once every kind that
//! blocks the flip is complete, the marker moves the identity's writes.
//!
//! An app gives its kinds of data as hooks. The runner owns the order, what
//! counts as complete, the flip and one pass at a time. A pass never fails
//! its caller: the outcome carries what happened.
//!
//! **Order:** the app's own kinds (written by the runner, verified by a
//! fresh read), then the carried kinds (records the app carries itself,
//! such as public records another key signed), then the flip.
//!
//! - A failure in an own kind, or in a carried kind that blocks the flip,
//!   stops the pass.
//! - A carried kind that does not block the flip is carried again each pass
//!   until complete; its failure is noted and the pass goes on.
//! - Passes keep running after the flip while the previous line runs, so
//!   what reaches it later (from another device still on it) is copied too.
//! - A pass complete for every kind that began with no other device on the
//!   previous generation records that nothing is left there to carry
//!   (`Marker::carried_all_ms`, which the retirement policy reads).

use crate::marker::{Marker, MarkerRead, MarkerSpec};
use crate::policy::Siblings;
use crate::versions::{latest_versions, missing_on, Versioned};
use crate::Line;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// An app hook's error: anything that displays (`String` converts with `?`).
pub type HookError = Box<dyn std::error::Error + Send + Sync>;

/// The app a pass runs for.
#[async_trait::async_trait]
pub trait PassApp: Send + Sync + 'static {
    /// Whether this line's conductor is running.
    fn line_up(&self, line: Line) -> bool;
    /// Why no pass can run now (the app is locked), or `None`.
    fn blocked(&self) -> Option<String> {
        None
    }
    /// The identity's other devices as this device knows them now (this
    /// one left out), or `None` when that cannot be read. The default,
    /// `None`, never records that nothing is left to carry.
    async fn siblings(_app: &Arc<Self>, _root: &Path) -> Option<Siblings> {
        None
    }
}

/// What every hook is handed.
pub struct PassCx<'a, C> {
    pub app: &'a Arc<C>,
    /// The identity's data root (where its marker is).
    pub root: &'a Path,
    pub reason: &'a str,
    pub spec: &'a MarkerSpec,
    /// The marker as the pass found it.
    pub marker: &'a MarkerRead,
    /// The identity's writes had moved to the current line when the pass began.
    pub moved: bool,
}

/// One set of the app's own data that moves together (the Vault: its
/// private records; an app with several agents: one per agent). The hooks
/// know what the id names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CopyUnit {
    pub id: String,
}

#[async_trait::async_trait]
pub trait CopyUnits<C>: Send + Sync {
    /// What this pass copies. None: nothing of the app's own to copy, and
    /// the own kinds count as complete.
    async fn units(&self, cx: &PassCx<'_, C>) -> Result<Vec<CopyUnit>, HookError>;
}

/// One stored version of a record with a logical id and a version time.
#[derive(Clone, Debug, PartialEq)]
pub struct Version {
    pub logical_id: String,
    pub version_time: u64,
    pub created_at: u64,
    pub deleted: bool,
    /// The raw 39-byte action hash of this version.
    pub action_hash: Vec<u8>,
    /// The app's own encoding of the version, handed back to `write`.
    pub body: Vec<u8>,
}

impl Versioned for Version {
    fn logical_id(&self) -> String {
        self.logical_id.clone()
    }
    fn version_time(&self) -> u64 {
        self.version_time
    }
    fn created_at(&self) -> u64 {
        self.created_at
    }
    fn deleted(&self) -> bool {
        self.deleted
    }
    fn action_hash(&self) -> &[u8] {
        &self.action_hash
    }
}

/// Own data with a logical id and a version time: the newest version of
/// each id on the previous line that the current one lacks is written.
#[async_trait::async_trait]
pub trait VersionedKind<C>: Send + Sync {
    /// How the outcome and its errors name the kind.
    fn name(&self) -> &'static str;
    /// Every stored version on `line` (the runner picks the newest per id).
    async fn versions(&self, cx: &PassCx<'_, C>, line: Line, unit: &CopyUnit) -> Result<Vec<Version>, HookError>;
    /// Write `v` to `line` as it was (the same logical id, times and body),
    /// superseding the version `line` holds, if any. Returns the new
    /// version's action hash.
    async fn write(&self, cx: &PassCx<'_, C>, line: Line, unit: &CopyUnit, v: &Version, supersedes: Option<&[u8]>) -> Result<Vec<u8>, HookError>;
    /// Called before the read that checks the writes: a cache of earlier
    /// reads must not answer it.
    fn forget_cache(&self, _cx: &PassCx<'_, C>) {}
}

/// The app's own kinds. Hash-keyed kinds (immutable records with parents)
/// join with the first app that needs them.
pub enum OwnKind<C> {
    Versioned(Arc<dyn VersionedKind<C>>),
}

/// What a carried kind did this pass. The hook fills it as it goes, so a
/// failure part way keeps the counts so far.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize)]
pub struct CarryReport {
    /// What the previous line holds of this kind.
    pub total: usize,
    /// How many of `total` are on the current line after this pass.
    pub carried: usize,
    /// Related records carried with them, by name (the Vault: revocations,
    /// thumbnails).
    pub details: Vec<(&'static str, usize)>,
}

impl CarryReport {
    /// Add `n` to a detail count.
    pub fn add(&mut self, name: &'static str, n: usize) {
        match self.details.iter_mut().find(|(k, _)| *k == name) {
            Some((_, count)) => *count += n,
            None => self.details.push((name, n)),
        }
    }
}

/// Whether a carried kind had anything to carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carried {
    /// Nothing to carry here: complete.
    Nothing,
    /// Carried; the report says how much.
    Ran,
}

/// Records the app carries itself (public records, carried with this device
/// as witness).
#[async_trait::async_trait]
pub trait CarriedRecords<C>: Send + Sync {
    fn name(&self) -> &'static str;
    /// The flip waits for it, and its failure stops the pass.
    fn blocks_flip(&self) -> bool;
    /// Carried only while writes still go to the previous line (nothing
    /// new lands there after the flip). After the flip it counts as complete.
    fn only_before_flip(&self) -> bool {
        false
    }
    async fn carry(&self, cx: &PassCx<'_, C>, report: &mut CarryReport) -> Result<Carried, HookError>;
    /// Once complete on a pass after the flip: record it in the marker, so
    /// later passes and the retirement policy know. Returns whether the
    /// marker changed (and is written).
    fn mark_complete(&self, _marker: &mut Marker, _report: &CarryReport) -> bool {
        false
    }
}

/// The flip's app side.
#[async_trait::async_trait]
pub trait FlipHook<C>: Send + Sync {
    /// The app's own keys in the new marker (an older version of the app
    /// may require them).
    fn marker_fields(&self, _outcome: &PassOutcome) -> Map<String, Value> {
        Map::new()
    }
    /// After the marker is written: what the app does now that its writes
    /// go to the current line.
    async fn flipped(&self, _cx: &PassCx<'_, C>, _marker: &Marker, _outcome: &PassOutcome) {}
}

/// A flip with nothing of the app's own.
pub struct NoFlipHook;
impl<C: Sync> FlipHook<C> for NoFlipHook {}

/// What one kind did in a pass.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize)]
pub struct KindOutcome {
    pub name: &'static str,
    /// On the previous line (own kinds: the newest version per logical id).
    pub total: usize,
    /// Own kinds: already on the current line at that version or newer.
    pub present: usize,
    /// Written (own kinds) or on the current line after the pass (carried).
    pub written: usize,
    pub details: Vec<(&'static str, usize)>,
    pub complete: bool,
    /// A failure of a kind that does not block the flip (the pass went on).
    pub error: Option<String>,
}

impl KindOutcome {
    pub fn detail(&self, name: &str) -> usize {
        self.details.iter().find(|(k, _)| *k == name).map(|(_, n)| *n).unwrap_or(0)
    }
}

/// What one pass did.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize)]
pub struct PassOutcome {
    pub reason: String,
    pub started_ms: u64,
    pub took_ms: u64,
    /// The own kinds, then the carried kinds, as far as the pass got.
    pub kinds: Vec<KindOutcome>,
    /// This pass wrote the marker.
    pub flipped: bool,
    pub error: Option<String>,
    /// The pass did not run, and why.
    pub skipped: Option<String>,
}

impl PassOutcome {
    pub fn kind(&self, name: &str) -> Option<&KindOutcome> {
        self.kinds.iter().find(|k| k.name == name)
    }
}

/// Whether a pass is running for an identity, and the last one's outcome.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PassStatus {
    pub running: bool,
    pub last: Option<PassOutcome>,
}

type Slot<T> = Arc<Mutex<Option<T>>>;

/// The right to run the one pass, from [`PassRunner::claim`]. Dropping it
/// lets the next one run; [`PassClaim::finished`] also keeps the outcome
/// for [`PassRunner::status`].
pub struct PassClaim {
    root: PathBuf,
    running: Slot<PathBuf>,
    last: Slot<(PathBuf, PassOutcome)>,
}

impl PassClaim {
    pub fn finished(self, outcome: PassOutcome) {
        *self.last.lock().unwrap() = Some((self.root.clone(), outcome));
    }
}

impl Drop for PassClaim {
    fn drop(&mut self) {
        *self.running.lock().unwrap() = None;
    }
}

pub struct PassRunner<C> {
    spec: MarkerSpec,
    units: Arc<dyn CopyUnits<C>>,
    own: Vec<OwnKind<C>>,
    carried: Vec<Arc<dyn CarriedRecords<C>>>,
    flip: Arc<dyn FlipHook<C>>,
    running: Slot<PathBuf>,
    last: Slot<(PathBuf, PassOutcome)>,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

impl<C: PassApp> PassRunner<C> {
    pub fn new(
        spec: MarkerSpec,
        units: Arc<dyn CopyUnits<C>>,
        own: Vec<OwnKind<C>>,
        carried: Vec<Arc<dyn CarriedRecords<C>>>,
        flip: Arc<dyn FlipHook<C>>,
    ) -> Self {
        Self { spec, units, own, carried, flip, running: Arc::default(), last: Arc::default() }
    }

    /// Claim the one pass for `root`, unless a pass is running (for any
    /// identity) or a line is down. The app spawns the pass on its own
    /// runtime: `run`, then `finished`.
    pub fn claim(&self, app: &C, root: &Path) -> Option<PassClaim> {
        if !app.line_up(self.spec.previous) || !app.line_up(self.spec.current) {
            return None;
        }
        let mut running = self.running.lock().unwrap();
        if running.is_some() {
            return None;
        }
        *running = Some(root.to_path_buf());
        Some(PassClaim { root: root.to_path_buf(), running: self.running.clone(), last: self.last.clone() })
    }

    pub fn status(&self, root: &Path) -> PassStatus {
        PassStatus {
            running: self.running.lock().unwrap().as_deref() == Some(root),
            last: self.last.lock().unwrap().as_ref().filter(|(r, _)| r == root).map(|(_, o)| o.clone()),
        }
    }

    /// One pass. Never fails the caller: the outcome carries the error.
    pub async fn run(&self, app: &Arc<C>, root: &Path, reason: &str) -> PassOutcome {
        let started = std::time::Instant::now();
        let mut out = PassOutcome { reason: reason.to_string(), started_ms: now_ms(), ..Default::default() };
        if let Some(why) = app.blocked() {
            out.skipped = Some(why);
            return out;
        }
        if !app.line_up(self.spec.current) {
            out.skipped = Some(format!("the {} line is not running", self.spec.current));
            return out;
        }
        if !app.line_up(self.spec.previous) {
            out.skipped = Some(format!("the {} line is not running (nothing to carry from)", self.spec.previous));
            return out;
        }
        let marker = Marker::load(root, &self.spec);
        let moved = Marker::writes_to(&marker, &self.spec) == self.spec.current;
        let siblings = C::siblings(app, root).await;
        let cx = PassCx { app, root, reason, spec: &self.spec, marker: &marker, moved };
        self.steps(&cx, &mut out).await;
        self.record_carried_all(root, siblings.as_ref(), &mut out);
        out.took_ms = started.elapsed().as_millis() as u64;
        out
    }

    /// Whether nothing is left on the previous line, from this pass:
    /// recorded when it was complete for every kind and began with no other
    /// device on the previous generation; cleared when a device is on it,
    /// or the pass left something (wrote and did not finish, or finished
    /// incomplete). A pass that failed before writing anything says nothing
    /// new. Only an existing marker is changed (none before the flip).
    fn record_carried_all(&self, root: &Path, siblings: Option<&Siblings>, out: &mut PassOutcome) {
        let previous = self.spec.previous.generation();
        let left = siblings.map(|s| match s {
            Siblings::Heard(list) => !list.iter().any(|s| !s.removed && s.generation == previous),
            Siblings::NoneHeardYet | Siblings::NeverShared => true,
        });
        let complete = out.error.is_none() && out.kinds.iter().all(|k| k.complete);
        let wrote = out.kinds.iter().take(self.own.len()).any(|k| k.written > 0);
        let carried_all = match left {
            Some(false) => None,
            _ if !complete && (wrote || out.error.is_none()) => None,
            Some(true) if complete => Some(now_ms()),
            _ => return,
        };
        let MarkerRead::Present(mut m) = Marker::load(root, &self.spec) else { return };
        if m.carried_all_ms.is_some() == carried_all.is_some() {
            return;
        }
        m.carried_all_ms = carried_all;
        if let Err(e) = m.save(root, &self.spec) {
            out.error.get_or_insert(format!("the marker was not updated: {e}"));
        }
    }

    async fn steps(&self, cx: &PassCx<'_, C>, out: &mut PassOutcome) {
        let units = match self.units.units(cx).await {
            Ok(u) => u,
            Err(e) => {
                out.error = Some(format!("what to copy: {e}"));
                return;
            }
        };
        // Whether every kind the flip waits for is complete.
        let mut flip_ready = true;
        for kind in &self.own {
            let OwnKind::Versioned(k) = kind;
            out.kinds.push(KindOutcome { name: k.name(), complete: true, ..Default::default() });
            let at = out.kinds.len() - 1;
            for unit in &units {
                if let Err(e) = copy_versions(k.as_ref(), cx, unit, &mut out.kinds[at]).await {
                    out.kinds[at].complete = false;
                    out.error = Some(format!("{}: {e}", k.name()));
                    return;
                }
            }
            flip_ready &= out.kinds[at].complete;
        }
        for k in &self.carried {
            let mut kind = KindOutcome { name: k.name(), ..Default::default() };
            if k.only_before_flip() && cx.moved {
                kind.complete = true;
                out.kinds.push(kind);
                continue;
            }
            let mut report = CarryReport::default();
            let result = k.carry(cx, &mut report).await;
            kind.total = report.total;
            kind.written = report.carried;
            kind.details = report.details.clone();
            match result {
                Ok(Carried::Nothing) => kind.complete = true,
                Ok(Carried::Ran) => {
                    kind.complete = report.carried == report.total;
                    if kind.complete && cx.moved {
                        if let Err(e) = self.mark_complete(cx.root, k.as_ref(), &report) {
                            out.error = Some(format!("the marker was not updated: {e}"));
                        }
                    }
                }
                Err(e) if k.blocks_flip() => {
                    out.kinds.push(kind);
                    out.error = Some(format!("{}: {e}", k.name()));
                    return;
                }
                Err(e) => kind.error = Some(e.to_string()),
            }
            if k.blocks_flip() {
                flip_ready &= kind.complete;
            }
            out.kinds.push(kind);
        }
        if !cx.moved && flip_ready {
            // Read again: a marker written meanwhile keeps the keys it has.
            let mut m = match Marker::load(cx.root, &self.spec) {
                MarkerRead::Present(found) => found,
                _ => Marker::new(&self.spec, 0),
            };
            m.v = 1;
            m.writes_to = Some(self.spec.current);
            m.moved_at_ms = now_ms();
            m.born = false;
            m.restored = false;
            m.old_line_needed = Some(true);
            m.app.extend(self.flip.marker_fields(out));
            match m.save(cx.root, &self.spec) {
                Ok(()) => {
                    out.flipped = true;
                    self.flip.flipped(cx, &m, out).await;
                }
                Err(e) => out.error = Some(format!("the marker was not written: {e}")),
            }
        }
    }
}

impl<C> PassRunner<C> {
    fn mark_complete(&self, root: &Path, k: &dyn CarriedRecords<C>, report: &CarryReport) -> Result<(), String> {
        match Marker::load(root, &self.spec) {
            MarkerRead::Present(mut m) => {
                if k.mark_complete(&mut m, report) {
                    m.save(root, &self.spec).map_err(|e| e.to_string())?;
                }
                Ok(())
            }
            MarkerRead::Absent => Err("no marker".into()),
            MarkerRead::Unreadable(e) => Err(format!("the marker does not read: {e}")),
        }
    }
}

/// The newest version of each id on the previous line that the current one
/// lacks (no version, or an older one), written oldest first, then checked
/// by reading the current line again.
async fn copy_versions<C>(k: &dyn VersionedKind<C>, cx: &PassCx<'_, C>, unit: &CopyUnit, kind: &mut KindOutcome) -> Result<(), HookError> {
    let held = |versions: Vec<Version>| -> HashMap<String, Version> {
        latest_versions(versions).0.into_iter().map(|v| (v.logical_id.clone(), v)).collect()
    };
    let (winners, _) = latest_versions(k.versions(cx, cx.spec.previous, unit).await?);
    let on_current = held(k.versions(cx, cx.spec.current, unit).await?);
    kind.total += winners.len();
    let missing = missing_on(&winners, &on_current);
    kind.present += winners.len() - missing.len();
    for (v, supersedes) in missing {
        k.write(cx, cx.spec.current, unit, v, supersedes.as_deref()).await?;
        kind.written += 1;
    }
    k.forget_cache(cx);
    let after = held(k.versions(cx, cx.spec.current, unit).await?);
    if !missing_on(&winners, &after).is_empty() {
        kind.complete = false;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    const SPEC: MarkerSpec = MarkerSpec { file_name: "moved-07", old_line_key: "line_06_needed", previous: Line::V06, current: Line::V07 };

    #[derive(Default)]
    struct App {
        down: Mutex<Vec<Line>>,
        locked: AtomicBool,
        /// Versions per line.
        lines: Mutex<HashMap<Line, Vec<Version>>>,
        /// Writes that do not land (the check must catch them).
        lose_writes: AtomicBool,
        fail_write: AtomicBool,
        written: Mutex<Vec<(String, Option<Vec<u8>>)>>,
        forgot: AtomicUsize,
        carry_fails: Mutex<Vec<&'static str>>,
        carry_calls: Mutex<Vec<&'static str>>,
        flipped: AtomicUsize,
        siblings: Mutex<Option<Siblings>>,
    }

    #[async_trait::async_trait]
    impl PassApp for App {
        fn line_up(&self, line: Line) -> bool {
            !self.down.lock().unwrap().contains(&line)
        }
        fn blocked(&self) -> Option<String> {
            self.locked.load(Ordering::SeqCst).then(|| "locked".to_string())
        }
        async fn siblings(app: &Arc<Self>, _root: &Path) -> Option<Siblings> {
            app.siblings.lock().unwrap().clone()
        }
    }

    fn v(id: &str, time: u64, hash: u8) -> Version {
        Version { logical_id: id.into(), version_time: time, created_at: time, deleted: false, action_hash: vec![hash; 39], body: vec![hash] }
    }

    struct OneUnit(bool);
    #[async_trait::async_trait]
    impl CopyUnits<App> for OneUnit {
        async fn units(&self, _cx: &PassCx<'_, App>) -> Result<Vec<CopyUnit>, HookError> {
            Ok(if self.0 { vec![CopyUnit { id: "private".into() }] } else { vec![] })
        }
    }

    struct Notes;
    #[async_trait::async_trait]
    impl VersionedKind<App> for Notes {
        fn name(&self) -> &'static str {
            "notes"
        }
        async fn versions(&self, cx: &PassCx<'_, App>, line: Line, _u: &CopyUnit) -> Result<Vec<Version>, HookError> {
            Ok(cx.app.lines.lock().unwrap().get(&line).cloned().unwrap_or_default())
        }
        async fn write(&self, cx: &PassCx<'_, App>, line: Line, _u: &CopyUnit, v: &Version, supersedes: Option<&[u8]>) -> Result<Vec<u8>, HookError> {
            if cx.app.fail_write.load(Ordering::SeqCst) {
                return Err("the conductor said no".to_string().into());
            }
            cx.app.written.lock().unwrap().push((v.logical_id.clone(), supersedes.map(|s| s.to_vec())));
            let mut copy = v.clone();
            copy.action_hash = vec![200; 39];
            if !cx.app.lose_writes.load(Ordering::SeqCst) {
                cx.app.lines.lock().unwrap().entry(line).or_default().push(copy);
            }
            Ok(vec![200; 39])
        }
        fn forget_cache(&self, cx: &PassCx<'_, App>) {
            cx.app.forgot.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct Signed { name: &'static str, blocks: bool, before_flip: bool, total: usize, nothing: bool }
    #[async_trait::async_trait]
    impl CarriedRecords<App> for Signed {
        fn name(&self) -> &'static str {
            self.name
        }
        fn blocks_flip(&self) -> bool {
            self.blocks
        }
        fn only_before_flip(&self) -> bool {
            self.before_flip
        }
        async fn carry(&self, cx: &PassCx<'_, App>, report: &mut CarryReport) -> Result<Carried, HookError> {
            cx.app.carry_calls.lock().unwrap().push(self.name);
            if self.nothing {
                return Ok(Carried::Nothing);
            }
            report.total = self.total;
            report.carried = 1;
            report.add("revocations", 1);
            if cx.app.carry_fails.lock().unwrap().contains(&self.name) {
                return Err(format!("{} failed part way", self.name).into());
            }
            report.carried = self.total;
            Ok(Carried::Ran)
        }
        fn mark_complete(&self, m: &mut Marker, report: &CarryReport) -> bool {
            m.app.insert(format!("{}_done", self.name), Value::from(report.carried));
            true
        }
    }

    struct Flip;
    #[async_trait::async_trait]
    impl FlipHook<App> for Flip {
        fn marker_fields(&self, o: &PassOutcome) -> Map<String, Value> {
            let mut m = Map::new();
            m.insert("notes".into(), Value::from(o.kind("notes").map(|k| k.total).unwrap_or(0)));
            m.insert("born".into(), Value::from(true)); // a line field: the runner's value wins
            m
        }
        async fn flipped(&self, cx: &PassCx<'_, App>, m: &Marker, o: &PassOutcome) {
            assert!(o.flipped && m.writes_to == Some(Line::V07));
            cx.app.flipped.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn signatures() -> Signed {
        Signed { name: "signatures", blocks: true, before_flip: true, total: 3, nothing: false }
    }
    fn web_era() -> Signed {
        Signed { name: "web era", blocks: false, before_flip: false, total: 2, nothing: false }
    }
    fn runner(units: bool, carried: Vec<Signed>) -> PassRunner<App> {
        PassRunner::new(
            SPEC,
            Arc::new(OneUnit(units)),
            vec![OwnKind::Versioned(Arc::new(Notes))],
            carried.into_iter().map(|c| Arc::new(c) as Arc<dyn CarriedRecords<App>>).collect(),
            Arc::new(Flip),
        )
    }
    fn app(old: Vec<Version>, new: Vec<Version>) -> Arc<App> {
        let app = App::default();
        app.lines.lock().unwrap().insert(Line::V06, old);
        app.lines.lock().unwrap().insert(Line::V07, new);
        Arc::new(app)
    }
    fn marker_map(root: &Path) -> Map<String, Value> {
        match Marker::load(root, &SPEC) {
            MarkerRead::Present(m) => m.to_map(&SPEC),
            other => panic!("no marker: {other:?}"),
        }
    }

    #[tokio::test]
    async fn skips_in_order_locked_then_the_current_line_then_the_previous() {
        let dir = tempfile::tempdir().unwrap();
        let app = app(vec![], vec![]);
        let r = runner(true, vec![]);
        app.locked.store(true, Ordering::SeqCst);
        *app.down.lock().unwrap() = vec![Line::V06, Line::V07];
        assert_eq!(r.run(&app, dir.path(), "t").await.skipped.as_deref(), Some("locked"));
        app.locked.store(false, Ordering::SeqCst);
        assert_eq!(r.run(&app, dir.path(), "t").await.skipped.as_deref(), Some("the 0.7 line is not running"));
        *app.down.lock().unwrap() = vec![Line::V06];
        assert_eq!(r.run(&app, dir.path(), "t").await.skipped.as_deref(), Some("the 0.6 line is not running (nothing to carry from)"));
        assert!(Marker::load(dir.path(), &SPEC) == MarkerRead::Absent);
    }

    #[tokio::test]
    async fn copies_what_the_current_line_lacks_then_flips_with_the_apps_fields() {
        let dir = tempfile::tempdir().unwrap();
        // a: missing; b: the same version there; c: an older one there.
        let app = app(vec![v("c", 3000, 3), v("a", 1000, 1), v("a", 900, 9), v("b", 2000, 2)], vec![v("b", 2000, 2), v("c", 2500, 33)]);
        let r = runner(true, vec![signatures(), web_era()]);
        let o = r.run(&app, dir.path(), "start").await;
        assert_eq!(o.error, None);
        let notes = o.kind("notes").unwrap();
        assert_eq!((notes.total, notes.present, notes.written, notes.complete), (3, 1, 2, true));
        assert_eq!(*app.written.lock().unwrap(), vec![("a".to_string(), None), ("c".to_string(), Some(vec![33; 39]))]);
        assert_eq!(app.forgot.load(Ordering::SeqCst), 1);
        let sig = o.kind("signatures").unwrap();
        assert_eq!((sig.total, sig.written, sig.detail("revocations"), sig.complete), (3, 3, 1, true));
        assert!(o.flipped);
        assert_eq!(app.flipped.load(Ordering::SeqCst), 1);
        let m = marker_map(dir.path());
        assert_eq!(m["writes_to"], "holochain-0.7");
        assert_eq!(m["line_06_needed"], true);
        assert_eq!(m["notes"], 3);
        assert_eq!(m["born"], false, "the line fields are the runner's");
        // Complete before the flip: the flip records it, not mark_complete.
        assert!(!m.contains_key("web era_done"));
    }

    #[tokio::test]
    async fn after_the_flip_signatures_are_not_carried_and_a_late_carry_marks_the_marker() {
        let dir = tempfile::tempdir().unwrap();
        Marker::new(&SPEC, 1).save(dir.path(), &SPEC).unwrap();
        let app = app(vec![v("a", 1000, 1)], vec![]);
        let r = runner(true, vec![signatures(), web_era()]);
        let o = r.run(&app, dir.path(), "round").await;
        assert!(!o.flipped && o.error.is_none());
        assert_eq!(o.kind("notes").unwrap().written, 1, "passes keep copying after the flip");
        assert_eq!(*app.carry_calls.lock().unwrap(), vec!["web era"]);
        let sig = o.kind("signatures").unwrap();
        assert!(sig.complete && sig.total == 0);
        assert_eq!(marker_map(dir.path())["web era_done"], 2);
    }

    #[tokio::test]
    async fn a_blocking_failure_stops_the_pass_with_its_counts_so_far() {
        let dir = tempfile::tempdir().unwrap();
        let app = app(vec![v("a", 1000, 1)], vec![]);
        app.carry_fails.lock().unwrap().push("signatures");
        let r = runner(true, vec![signatures(), web_era()]);
        let o = r.run(&app, dir.path(), "t").await;
        assert_eq!(o.error.as_deref(), Some("signatures: signatures failed part way"));
        let sig = o.kind("signatures").unwrap();
        assert_eq!((sig.total, sig.written, sig.complete), (3, 1, false));
        assert!(o.kind("web era").is_none(), "nothing after a stopping failure runs");
        assert!(!o.flipped && Marker::load(dir.path(), &SPEC) == MarkerRead::Absent);

        // An own kind's write failure stops it before anything is carried.
        let app = app_with_failing_write();
        let o = r.run(&app, dir.path(), "t").await;
        assert_eq!(o.error.as_deref(), Some("notes: the conductor said no"));
        assert!(o.kind("signatures").is_none() && !o.flipped);
    }

    fn app_with_failing_write() -> Arc<App> {
        let app = app(vec![v("a", 1000, 1)], vec![]);
        app.fail_write.store(true, Ordering::SeqCst);
        app
    }

    #[tokio::test]
    async fn a_non_blocking_failure_is_noted_and_the_flip_still_happens() {
        let dir = tempfile::tempdir().unwrap();
        let app = app(vec![], vec![]);
        app.carry_fails.lock().unwrap().push("web era");
        let o = runner(true, vec![signatures(), web_era()]).run(&app, dir.path(), "t").await;
        assert_eq!(o.error, None);
        let web = o.kind("web era").unwrap();
        assert_eq!((web.complete, web.error.as_deref()), (false, Some("web era failed part way")));
        assert!(o.flipped);
    }

    #[tokio::test]
    async fn a_write_that_does_not_read_back_is_not_complete_and_does_not_flip() {
        let dir = tempfile::tempdir().unwrap();
        let app = app(vec![v("a", 1000, 1)], vec![]);
        app.lose_writes.store(true, Ordering::SeqCst);
        let o = runner(true, vec![]).run(&app, dir.path(), "t").await;
        let notes = o.kind("notes").unwrap();
        assert_eq!((notes.written, notes.complete, o.flipped), (1, false, false));
    }

    #[tokio::test]
    async fn no_units_and_nothing_to_carry_count_as_complete() {
        let dir = tempfile::tempdir().unwrap();
        let app = app(vec![v("a", 1000, 1)], vec![]);
        let none = Signed { name: "web era", blocks: false, before_flip: false, total: 0, nothing: true };
        let o = runner(false, vec![none]).run(&app, dir.path(), "t").await;
        assert!(o.kind("notes").unwrap().complete && o.kind("web era").unwrap().complete);
        assert!(app.written.lock().unwrap().is_empty() && o.flipped);
    }

    fn carried_all(root: &Path) -> Option<u64> {
        match Marker::load(root, &SPEC) {
            MarkerRead::Present(m) => m.carried_all_ms,
            _ => None,
        }
    }
    fn on(generation: &str) -> Siblings {
        Siblings::Heard(vec![crate::policy::Sibling { device_id: "laptop".into(), generation: generation.into(), removed: false }])
    }

    #[tokio::test]
    async fn a_complete_pass_with_no_device_on_the_previous_line_records_that_nothing_is_left() {
        let dir = tempfile::tempdir().unwrap();
        let app = app(vec![v("a", 1000, 1)], vec![]);
        let r = runner(true, vec![]);
        // Unknown siblings: the flip happens, nothing is recorded.
        assert!(r.run(&app, dir.path(), "t").await.flipped);
        assert_eq!(carried_all(dir.path()), None);
        // A device still on the previous generation: not recorded either.
        *app.siblings.lock().unwrap() = Some(on("holochain-0.6"));
        r.run(&app, dir.path(), "t").await;
        assert_eq!(carried_all(dir.path()), None);
        // It moved: the next complete pass records it, and it stays.
        *app.siblings.lock().unwrap() = Some(on("holochain-0.7"));
        r.run(&app, dir.path(), "t").await;
        let at = carried_all(dir.path()).expect("recorded");
        r.run(&app, dir.path(), "t").await;
        assert_eq!(carried_all(dir.path()), Some(at), "written only when it changes");
        // A device back on the previous generation clears it.
        *app.siblings.lock().unwrap() = Some(on("holochain-0.6"));
        r.run(&app, dir.path(), "t").await;
        assert_eq!(carried_all(dir.path()), None);
    }

    #[tokio::test]
    async fn a_pass_that_leaves_something_clears_it_and_a_failure_before_writing_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let app = app(vec![v("a", 1000, 1)], vec![]);
        *app.siblings.lock().unwrap() = Some(Siblings::NeverShared);
        let r = runner(true, vec![]);
        r.run(&app, dir.path(), "t").await;
        assert!(carried_all(dir.path()).is_some(), "the flip pass, complete, records it");
        // A failure before anything was written: nothing new is known.
        app.lines.lock().unwrap().get_mut(&Line::V06).unwrap().push(v("b", 2000, 2));
        app.fail_write.store(true, Ordering::SeqCst);
        assert!(r.run(&app, dir.path(), "t").await.error.is_some());
        assert!(carried_all(dir.path()).is_some());
        // A write that does not read back: something is left.
        app.fail_write.store(false, Ordering::SeqCst);
        app.lose_writes.store(true, Ordering::SeqCst);
        let o = r.run(&app, dir.path(), "t").await;
        assert!(o.error.is_none() && !o.kinds[0].complete);
        assert_eq!(carried_all(dir.path()), None);
        // Carried after all: recorded again.
        app.lose_writes.store(false, Ordering::SeqCst);
        r.run(&app, dir.path(), "t").await;
        assert!(carried_all(dir.path()).is_some());
    }

    /// Writes a marker with a key of its own while the pass runs.
    struct MarkerMeanwhile;
    #[async_trait::async_trait]
    impl CopyUnits<App> for MarkerMeanwhile {
        async fn units(&self, cx: &PassCx<'_, App>) -> Result<Vec<CopyUnit>, HookError> {
            let mut m = Marker::new(&SPEC, 5);
            m.app.insert("later_version_key".into(), Value::from("kept"));
            m.save(cx.root, &SPEC)?;
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn the_flip_keeps_the_keys_of_a_marker_written_meanwhile() {
        let dir = tempfile::tempdir().unwrap();
        let app = app(vec![], vec![]);
        let r = PassRunner::new(SPEC, Arc::new(MarkerMeanwhile), vec![], vec![], Arc::new(Flip));
        assert!(r.run(&app, dir.path(), "t").await.flipped);
        let m = marker_map(dir.path());
        assert_eq!((m["later_version_key"].as_str(), m["notes"].as_u64()), (Some("kept"), Some(0)));
    }

    #[test]
    fn one_pass_at_a_time_and_none_while_a_line_is_down() {
        let app = app(vec![], vec![]);
        let r = runner(true, vec![]);
        let (a, b) = (Path::new("/id/a"), Path::new("/id/b"));
        *app.down.lock().unwrap() = vec![Line::V06];
        assert!(r.claim(&app, a).is_none());
        app.down.lock().unwrap().clear();
        let claim = r.claim(&app, a).unwrap();
        assert!(r.claim(&app, b).is_none(), "one pass at a time, across identities");
        assert!(r.status(a).running && !r.status(b).running);
        claim.finished(PassOutcome { reason: "done".into(), ..Default::default() });
        assert!(!r.status(a).running);
        assert_eq!(r.status(a).last.map(|o| o.reason).as_deref(), Some("done"));
        assert_eq!(r.status(b).last, None);
        drop(r.claim(&app, b).unwrap());
        assert!(r.claim(&app, b).is_some(), "a dropped claim frees the runner");
    }
}
