//! The marker: one small JSON file per identity (or profile) saying which
//! line its writes go to and what the move knows.
//!
//! **The compatibility rule, for every app version that ever reads it:** a
//! marker file is created only when writes go to the current line (an
//! identity born on it, restored onto it, or moved to it). No file means
//! writes go to the previous line; any file, even one that does not parse,
//! means the current line. So an older app that knows only "the file
//! exists" still reads it correctly, and nothing here needs it to.
//!
//! The file is a JSON object. This module reads and writes the line fields
//! (`v`, `writes_to`, `moved_at_ms`, `born`, `restored`, the old-line
//! decision under the key the app names, `listening_since_ms`,
//! `reachable_rounds`, `carried_all_ms`) and keeps
//! every other key as it found it, so an app's own fields, and the fields
//! an older version of the app requires, survive every update.

use crate::Line;
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};

/// Where an app keeps its marker and how it names the line fields.
#[derive(Clone, Copy, Debug)]
pub struct MarkerSpec {
    /// The file under the identity's root (the Vault: `moved-07`).
    pub file_name: &'static str,
    /// The key of the old-line decision (the Vault: `line_06_needed`, its
    /// 1.7.0 name; an app starting fresh can use `old_line_needed`).
    pub old_line_key: &'static str,
    /// The line writes go to without a marker.
    pub previous: Line,
    /// The line writes go to with one.
    pub current: Line,
}

impl MarkerSpec {
    pub fn path(&self, root: &Path) -> PathBuf {
        root.join(self.file_name)
    }
}

/// The line fields of a marker, and everything else in it.
#[derive(Clone, Debug, PartialEq)]
pub struct Marker {
    pub v: u32,
    /// The generation name (`holochain-0.7`). Absent in files written before
    /// it existed: read as the current line.
    pub writes_to: Option<Line>,
    pub moved_at_ms: u64,
    /// Created on the current line: there never was a previous one.
    pub born: bool,
    /// Restored (or joined, or brought over) onto the current line: nothing
    /// of it was on this device's previous line.
    pub restored: bool,
    /// What the last start decided about the previous line.
    pub old_line_needed: Option<bool>,
    /// When a restored identity began listening for other devices.
    pub listening_since_ms: Option<u64>,
    /// Rounds since then in which a previous-line rendezvous answered and
    /// still nobody was heard (counted up to the policy's `alone_rounds`).
    pub reachable_rounds: u32,
    /// When a pass, complete for every kind, began with no other device on
    /// the previous generation: nothing is left there to carry. Cleared by
    /// a pass that finds something left or a device back on it.
    pub carried_all_ms: Option<u64>,
    /// Every other key, verbatim.
    pub app: Map<String, Value>,
}

/// What reading a marker found.
#[derive(Clone, Debug, PartialEq)]
pub enum MarkerRead {
    Absent,
    Present(Marker),
    /// The file is there but did not read: writes still go to the current line.
    Unreadable(String),
}

impl Marker {
    /// A marker for an identity whose writes go to `spec.current` from now.
    pub fn new(spec: &MarkerSpec, moved_at_ms: u64) -> Self {
        Self {
            v: 1,
            writes_to: Some(spec.current),
            moved_at_ms,
            born: false,
            restored: false,
            old_line_needed: None,
            listening_since_ms: None,
            reachable_rounds: 0,
            carried_all_ms: None,
            app: Map::new(),
        }
    }

    pub fn load(root: &Path, spec: &MarkerSpec) -> MarkerRead {
        let path = spec.path(root);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return MarkerRead::Absent,
            Err(e) => return MarkerRead::Unreadable(format!("{}: {e}", path.display())),
        };
        match serde_json::from_slice::<Value>(&bytes) {
            Ok(Value::Object(map)) => match Self::from_map(map, spec) {
                Ok(m) => MarkerRead::Present(m),
                Err(e) => MarkerRead::Unreadable(e),
            },
            Ok(_) => MarkerRead::Unreadable("not a JSON object".into()),
            Err(e) => MarkerRead::Unreadable(e.to_string()),
        }
    }

    /// Where writes go: `spec.previous` without a marker, `spec.current`
    /// with one (readable or not).
    pub fn writes_to(read: &MarkerRead, spec: &MarkerSpec) -> Line {
        match read {
            MarkerRead::Absent => spec.previous,
            MarkerRead::Present(m) => m.writes_to.unwrap_or(spec.current),
            MarkerRead::Unreadable(_) => spec.current,
        }
    }

    pub fn from_map(mut map: Map<String, Value>, spec: &MarkerSpec) -> Result<Self, String> {
        let mut take = |k: &str| map.remove(k);
        let v = take("v").and_then(|v| v.as_u64()).ok_or("no v")? as u32;
        let moved_at_ms = take("moved_at_ms").and_then(|v| v.as_u64()).ok_or("no moved_at_ms")?;
        let writes_to = match take("writes_to") {
            None | Some(Value::Null) => None,
            Some(Value::String(g)) => Some(Line::from_generation(&g).ok_or_else(|| format!("writes_to names no line ({g})"))?),
            Some(other) => return Err(format!("writes_to is not a line name ({other})")),
        };
        let flag = |v: Option<Value>| v.and_then(|v| v.as_bool()).unwrap_or(false);
        let born = flag(take("born"));
        let restored = flag(take("restored"));
        let old_line_needed = take(spec.old_line_key).and_then(|v| v.as_bool());
        let listening_since_ms = take("listening_since_ms").and_then(|v| v.as_u64());
        let reachable_rounds = take("reachable_rounds").and_then(|v| v.as_u64()).map(|n| n.min(u32::MAX as u64) as u32).unwrap_or(0);
        let carried_all_ms = take("carried_all_ms").and_then(|v| v.as_u64());
        Ok(Self { v, writes_to, moved_at_ms, born, restored, old_line_needed, listening_since_ms, reachable_rounds, carried_all_ms, app: map })
    }

    /// The JSON object: the app's keys as found, then the line fields. The
    /// old-line key is always written (null when undecided), as earlier
    /// versions wrote it; `writes_to`, `listening_since_ms`,
    /// `reachable_rounds` and `carried_all_ms` only when set.
    pub fn to_map(&self, spec: &MarkerSpec) -> Map<String, Value> {
        let mut map = self.app.clone();
        map.insert("v".into(), Value::from(self.v));
        map.insert("moved_at_ms".into(), Value::from(self.moved_at_ms));
        if let Some(l) = self.writes_to {
            map.insert("writes_to".into(), Value::from(l.generation()));
        }
        map.insert("born".into(), Value::from(self.born));
        map.insert("restored".into(), Value::from(self.restored));
        map.insert(spec.old_line_key.into(), self.old_line_needed.map(Value::from).unwrap_or(Value::Null));
        if let Some(t) = self.listening_since_ms {
            map.insert("listening_since_ms".into(), Value::from(t));
        }
        if self.reachable_rounds > 0 {
            map.insert("reachable_rounds".into(), Value::from(self.reachable_rounds));
        }
        if let Some(t) = self.carried_all_ms {
            map.insert("carried_all_ms".into(), Value::from(t));
        }
        map
    }

    /// One listening round: the window starts now if it has no start (an
    /// identity restored by a version without one), and `new_rounds`
    /// reachable rounds are added, up to `cap`. Whether anything changed.
    pub fn note_listening(&mut self, now_ms: u64, new_rounds: u32, cap: u32) -> bool {
        let mut changed = false;
        if self.listening_since_ms.is_none() {
            self.listening_since_ms = Some(now_ms);
            changed = true;
        }
        if self.reachable_rounds < cap && new_rounds > 0 {
            self.reachable_rounds = self.reachable_rounds.saturating_add(new_rounds).min(cap);
            changed = true;
        }
        changed
    }

    /// Write it (atomically: the file is never half there).
    pub fn save(&self, root: &Path, spec: &MarkerSpec) -> std::io::Result<()> {
        std::fs::create_dir_all(root)?;
        let bytes = serde_json::to_vec_pretty(&Value::Object(self.to_map(spec))).map_err(std::io::Error::other)?;
        crate::files::write_atomic(&spec.path(root), &bytes)
    }
}

/// Rewrite a present marker in place. An absent or unreadable one is left
/// alone (it is never created or replaced here: creating one moves the
/// identity's writes).
pub fn update_marker(root: &Path, spec: &MarkerSpec, change: impl FnOnce(&mut Marker)) -> Result<(), String> {
    match Marker::load(root, spec) {
        MarkerRead::Present(mut m) => {
            change(&mut m);
            m.save(root, spec).map_err(|e| e.to_string())
        }
        MarkerRead::Absent => Err("no marker".into()),
        MarkerRead::Unreadable(e) => Err(format!("the marker does not read: {e}")),
    }
}

/// Counts a listening identity's reachable rounds into its marker. The
/// supervisor counts rounds for its whole life
/// ([`crate::supervisor::Supervisor::reachable_rounds`]); this keeps the
/// count it last saw for one identity, so each call adds only the rounds
/// since. The first call for an identity starts from the count then.
pub struct ListenTally {
    seen: std::sync::Mutex<Option<(PathBuf, u64)>>,
}

impl ListenTally {
    pub const fn new() -> Self {
        Self { seen: std::sync::Mutex::new(None) }
    }

    /// Call each round the decision is `Wanted(Why::Listening)`, with the
    /// supervisor's count for the previous line and the policy's
    /// `alone_rounds`. The marker is written only when the round changes it
    /// (the window's start, or a round under the cap), so at most `cap`
    /// writes after the first.
    pub fn note(&self, root: &Path, spec: &MarkerSpec, rounds_now: u64, cap: u32, now_ms: u64) -> Result<(), String> {
        let new_rounds = {
            let mut seen = self.seen.lock().unwrap();
            let before = match seen.as_ref() {
                Some((r, n)) if r == root && *n <= rounds_now => *n,
                _ => rounds_now,
            };
            *seen = Some((root.to_path_buf(), rounds_now));
            (rounds_now - before).min(u32::MAX as u64) as u32
        };
        let MarkerRead::Present(mut m) = Marker::load(root, spec) else { return Ok(()) };
        if m.note_listening(now_ms, new_rounds, cap) {
            m.save(root, spec).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

impl Default for ListenTally {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: MarkerSpec = MarkerSpec { file_name: "moved-07", old_line_key: "line_06_needed", previous: Line::V06, current: Line::V07 };

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("hcl-marker-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The shape Flowsta Vault 1.7.0 writes and requires to read (its own
    /// fields have no defaults).
    #[derive(serde::Deserialize, Debug)]
    #[allow(dead_code)]
    struct Vault170 {
        v: u32,
        moved_at_ms: u64,
        vault_version: String,
        private_records: usize,
        signatures: usize,
        revocations: usize,
        thumbnails: usize,
        #[serde(default)]
        born: bool,
        #[serde(default)]
        web_era_carried: bool,
        #[serde(default)]
        web_era_signatures: usize,
        #[serde(default)]
        restored: bool,
        #[serde(default)]
        line_06_needed: Option<bool>,
    }

    const FILE_170: &str = r#"{
  "v": 1,
  "moved_at_ms": 1793400000000,
  "vault_version": "1.7.0",
  "private_records": 4,
  "signatures": 2,
  "revocations": 1,
  "thumbnails": 1,
  "born": false,
  "web_era_carried": true,
  "web_era_signatures": 0,
  "restored": false,
  "line_06_needed": null
}"#;

    #[test]
    fn no_file_is_the_previous_line_and_any_file_the_current() {
        let d = dir("rule");
        assert_eq!(Marker::load(&d, &SPEC), MarkerRead::Absent);
        assert_eq!(Marker::writes_to(&MarkerRead::Absent, &SPEC), Line::V06);
        std::fs::write(SPEC.path(&d), b"not json").unwrap();
        let read = Marker::load(&d, &SPEC);
        assert!(matches!(read, MarkerRead::Unreadable(_)));
        assert_eq!(Marker::writes_to(&read, &SPEC), Line::V07, "an unreadable marker still moved the writes");
        std::fs::write(SPEC.path(&d), FILE_170).unwrap();
        assert_eq!(Marker::writes_to(&Marker::load(&d, &SPEC), &SPEC), Line::V07, "a 1.7.0 file has no writes_to: the current line");
    }

    #[test]
    fn a_1_7_0_file_survives_an_update_and_1_7_0_still_reads_it() {
        let d = dir("compat");
        std::fs::write(SPEC.path(&d), FILE_170).unwrap();
        let MarkerRead::Present(m) = Marker::load(&d, &SPEC) else { panic!("reads") };
        assert_eq!((m.v, m.moved_at_ms, m.born, m.restored, m.old_line_needed, m.writes_to), (1, 1793400000000, false, false, None, None));
        assert_eq!(m.app.get("vault_version"), Some(&Value::from("1.7.0")), "the app's own fields are kept");
        update_marker(&d, &SPEC, |m| {
            m.old_line_needed = Some(false);
            m.app.insert("web_era_signatures".into(), Value::from(3));
        })
        .unwrap();
        let written = std::fs::read_to_string(SPEC.path(&d)).unwrap();
        let old: Vault170 = serde_json::from_str(&written).expect("Vault 1.7.0 reads what the library writes");
        assert_eq!((old.private_records, old.signatures, old.revocations, old.thumbnails), (4, 2, 1, 1));
        assert_eq!((old.web_era_signatures, old.line_06_needed, old.vault_version.as_str()), (3, Some(false), "1.7.0"));
        let v: Value = serde_json::from_str(&written).unwrap();
        assert!(v.get("writes_to").is_none(), "not added when the file had none");
        assert!(v.get("old_line_needed").is_none(), "the app's key, not the generic one");
    }

    #[test]
    fn new_fields_round_trip_and_are_left_out_when_unset() {
        let d = dir("new");
        let mut m = Marker::new(&SPEC, 5);
        m.born = true;
        m.old_line_needed = Some(false);
        m.listening_since_ms = Some(9);
        m.reachable_rounds = 4;
        m.carried_all_ms = Some(11);
        m.app.insert("vault_version".into(), Value::from("1.8.0"));
        m.save(&d, &SPEC).unwrap();
        assert_eq!(Marker::load(&d, &SPEC), MarkerRead::Present(m.clone()));
        let v: Value = serde_json::from_slice(&std::fs::read(SPEC.path(&d)).unwrap()).unwrap();
        assert_eq!(v["writes_to"], Value::from("holochain-0.7"), "the generation name device records use");
        assert_eq!(v["line_06_needed"], Value::from(false));
        let mut bare = Marker::new(&SPEC, 5);
        bare.writes_to = None;
        let map = bare.to_map(&SPEC);
        assert!(!map.contains_key("writes_to") && !map.contains_key("listening_since_ms") && !map.contains_key("reachable_rounds") && !map.contains_key("carried_all_ms"));
        assert_eq!(map.get("line_06_needed"), Some(&Value::Null), "always written, as 1.7.0 did");
    }

    #[test]
    fn listening_starts_the_window_once_and_counts_rounds_up_to_the_cap() {
        let mut m = Marker::new(&SPEC, 5);
        assert!(m.note_listening(100, 0, 3), "the window starts");
        assert!(!m.note_listening(200, 0, 3), "no round reached a rendezvous: nothing to write");
        assert!(m.note_listening(300, 2, 3));
        assert!(m.note_listening(400, 5, 3));
        assert_eq!((m.listening_since_ms, m.reachable_rounds), (Some(100), 3), "started at the first round, capped");
        assert!(!m.note_listening(500, 1, 3), "at the cap: no more writes");
    }

    #[test]
    fn the_tally_adds_only_the_rounds_since_its_last_look() {
        let d = dir("tally");
        let mut m = Marker::new(&SPEC, 5);
        m.restored = true;
        m.save(&d, &SPEC).unwrap();
        let tally = ListenTally::new();
        let read = || match Marker::load(&d, &SPEC) {
            MarkerRead::Present(m) => (m.listening_since_ms, m.reachable_rounds),
            other => panic!("{other:?}"),
        };
        tally.note(&d, &SPEC, 7, 30, 1_000).unwrap();
        assert_eq!(read(), (Some(1_000), 0), "the first look starts the window and counts from there");
        tally.note(&d, &SPEC, 9, 30, 2_000).unwrap();
        tally.note(&d, &SPEC, 9, 30, 3_000).unwrap();
        tally.note(&d, &SPEC, 10, 30, 4_000).unwrap();
        assert_eq!(read(), (Some(1_000), 3));
        tally.note(&d, &SPEC, 50, 30, 5_000).unwrap();
        assert_eq!(read().1, 30, "capped");
        let none = dir("tally-none");
        tally.note(&none, &SPEC, 60, 30, 6_000).unwrap();
        assert!(!SPEC.path(&none).exists(), "never creates a marker");
    }

    #[test]
    fn an_update_never_creates_or_replaces_a_marker() {
        let d = dir("update");
        assert!(update_marker(&d, &SPEC, |_| {}).is_err());
        assert!(!SPEC.path(&d).exists(), "creating one would move the writes");
        std::fs::write(SPEC.path(&d), b"{").unwrap();
        assert!(update_marker(&d, &SPEC, |m| m.born = true).is_err());
        assert_eq!(std::fs::read(SPEC.path(&d)).unwrap(), b"{", "an unreadable file is left as it is");
    }
}
