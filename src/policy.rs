//! Whether an identity still needs its previous line, and which line its
//! start leads with: pure functions of local facts, so every rule is tested
//! without a conductor and every app decides the same way.

use crate::marker::{Marker, MarkerRead, MarkerSpec};
use crate::Line;

/// What the other devices of an identity are, as far as this device knows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Siblings {
    /// Nothing this device holds can reach another device (no rendezvous,
    /// never shared): no sibling can need the previous line.
    NeverShared,
    /// It can share, and no other device has been heard from yet.
    NoneHeardYet,
    /// The other devices it knows of (this device excluded or not: the
    /// rules skip `own_device_id`).
    Heard(Vec<Sibling>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sibling {
    pub device_id: String,
    /// The generation the device last said it runs (`holochain-0.6`).
    pub generation: String,
    pub removed: bool,
}

/// The facts a decision reads.
#[derive(Clone, Debug)]
pub struct Facts {
    pub marker: MarkerRead,
    /// The previous line holds data for this identity on this device.
    pub old_line_data_present: bool,
    pub own_device_id: Option<String>,
    pub siblings: Siblings,
    /// Kinds of data still owed from the previous line (an app's carry not
    /// yet done; the Vault: the web-era signatures).
    pub owed: Vec<String>,
    pub now_ms: u64,
}

/// How long a restored identity that has heard from no other device keeps
/// its previous line before it calls itself alone: `alone_after` since the
/// window began (`Marker::listening_since_ms`) AND `alone_rounds` rounds in
/// which a previous-line rendezvous answered (`Marker::reachable_rounds`,
/// counted by [`crate::marker::ListenTally`]). `None`: forever, which is
/// what Flowsta Vault 1.7.0 does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetirementPolicy {
    pub alone_after: Option<std::time::Duration>,
    pub alone_rounds: u32,
}

impl RetirementPolicy {
    /// The listen window never closes (Vault 1.7.0).
    pub const NEVER_ALONE: RetirementPolicy = RetirementPolicy { alone_after: None, alone_rounds: 0 };
}

/// Why the previous line is or is not wanted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Why {
    /// No marker, with data on the previous line: it is still the primary.
    NotMoved,
    Born,
    Owed(String),
    /// A sibling still runs the previous generation.
    SiblingOnOld(String),
    /// Restored and still listening for other devices.
    Listening,
    /// The previous line holds data, and no complete pass has run since
    /// every other device left it: something may be left to carry.
    NotCarried,
    Alone,
    NeverShared,
    NothingLeft,
    /// No marker and nothing on the previous line: a new identity's first start.
    Fresh,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Wanted(Why),
    NotWanted(Why),
}

impl Decision {
    pub fn wanted(&self) -> bool {
        matches!(self, Decision::Wanted(_))
    }
}

/// Whether the previous line is wanted, in this order:
/// 1. no marker: wanted (and primary) when the previous line holds data;
/// 2. born on the current line: not wanted;
/// 3. a kind still owed from it: wanted;
/// 4. another, unremoved device on the previous generation: wanted;
/// 5. restored and no device heard yet: wanted while listening (the
///    policy's window);
/// 6. data on the previous line and no complete pass since every other
///    device left it (`Marker::carried_all_ms`): wanted;
/// 7. restored and alone (the window closed): not wanted;
/// 8. never shared: not wanted;
/// 9. otherwise: not wanted (nothing left on it).
pub fn old_line_wanted(f: &Facts, p: &RetirementPolicy, spec: &MarkerSpec) -> Decision {
    let marker = match &f.marker {
        MarkerRead::Absent => {
            return if f.old_line_data_present { Decision::Wanted(Why::NotMoved) } else { Decision::NotWanted(Why::Fresh) };
        }
        MarkerRead::Present(m) => Some(m),
        // An unreadable marker: writes go to the current line and the
        // previous one is wanted, as Vault 1.7.0 treats it.
        MarkerRead::Unreadable(_) => None,
    };
    let Some(m) = marker else { return Decision::Wanted(Why::NotMoved) };
    if m.born {
        return Decision::NotWanted(Why::Born);
    }
    if let Some(kind) = f.owed.first() {
        return Decision::Wanted(Why::Owed(kind.clone()));
    }
    if let Some(s) = sibling_on_previous(f, spec) {
        return Decision::Wanted(Why::SiblingOnOld(s.device_id.clone()));
    }
    let listening = matches!(f.siblings, Siblings::NoneHeardYet) && m.restored;
    if listening && !window_closed(f, p, m) {
        return Decision::Wanted(Why::Listening);
    }
    if f.old_line_data_present && m.carried_all_ms.is_none() {
        return Decision::Wanted(Why::NotCarried);
    }
    match &f.siblings {
        _ if listening => Decision::NotWanted(Why::Alone),
        Siblings::NeverShared => Decision::NotWanted(Why::NeverShared),
        _ => Decision::NotWanted(Why::NothingLeft),
    }
}

/// Another unremoved device (not this one) on the previous generation.
fn sibling_on_previous<'a>(f: &'a Facts, spec: &MarkerSpec) -> Option<&'a Sibling> {
    let Siblings::Heard(list) = &f.siblings else { return None };
    list.iter().find(|s| !s.removed && s.generation == spec.previous.generation() && Some(&s.device_id) != f.own_device_id.as_ref())
}

/// A restored identity's listen window has closed (its time and rounds).
fn window_closed(f: &Facts, p: &RetirementPolicy, m: &Marker) -> bool {
    match (p.alone_after, m.listening_since_ms) {
        (Some(after), Some(since)) => f.now_ms.saturating_sub(since) >= after.as_millis() as u64 && m.reachable_rounds >= p.alone_rounds,
        _ => false,
    }
}

/// Where a write goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteTargets {
    /// The line the marker says writes go to.
    pub primary: Line,
    /// The previous line too, for the devices that read it there.
    pub mirror: Option<Line>,
}

/// A write goes to the line the marker says. While that is the current
/// line, the same write goes to the previous one too only when it runs AND
/// someone reads it there: another device on the previous generation, or a
/// restored identity still listening for one. Running for any other reason
/// (a carry owed, a pass not yet complete), it gets no copies.
pub fn write_targets(f: &Facts, p: &RetirementPolicy, old_running: bool, spec: &MarkerSpec) -> WriteTargets {
    let primary = Marker::writes_to(&f.marker, spec);
    let readers = match &f.marker {
        MarkerRead::Present(m) => sibling_on_previous(f, spec).is_some() || (m.restored && matches!(f.siblings, Siblings::NoneHeardYet) && !window_closed(f, p, m)),
        // Unreadable: no listen window to read; a device on the previous generation still counts.
        _ => sibling_on_previous(f, spec).is_some(),
    };
    WriteTargets { primary, mirror: (primary == spec.current && old_running && readers).then_some(spec.previous) }
}

/// Which line a start leads with, and which it attaches after.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartPlan {
    pub primary: Line,
    pub secondary: Option<Line>,
}

/// The start: without a marker the previous line leads and the current one
/// attaches (the move runs between them); with one the current line leads
/// and the previous one attaches only when wanted.
pub fn plan_start(f: &Facts, p: &RetirementPolicy, spec: &MarkerSpec) -> (StartPlan, Decision) {
    let decision = old_line_wanted(f, p, spec);
    let plan = match crate::marker::Marker::writes_to(&f.marker, spec) {
        l if l == spec.previous => StartPlan { primary: spec.previous, secondary: Some(spec.current) },
        _ => StartPlan { primary: spec.current, secondary: decision.wanted().then_some(spec.previous) },
    };
    (plan, decision)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: MarkerSpec = MarkerSpec { file_name: "moved-07", old_line_key: "line_06_needed", previous: Line::V06, current: Line::V07 };

    fn facts(marker: MarkerRead, siblings: Siblings) -> Facts {
        Facts { marker, old_line_data_present: true, own_device_id: Some("me".into()), siblings, owed: vec![], now_ms: 1_000_000 }
    }
    /// A marker whose last pass carried everything (unless `edit` says otherwise).
    fn present(edit: impl FnOnce(&mut Marker)) -> MarkerRead {
        let mut m = Marker::new(&SPEC, 1);
        m.carried_all_ms = Some(2);
        edit(&mut m);
        MarkerRead::Present(m)
    }
    fn sib(id: &str, gen: &str, removed: bool) -> Sibling {
        Sibling { device_id: id.into(), generation: gen.into(), removed }
    }
    const NEVER: RetirementPolicy = RetirementPolicy::NEVER_ALONE;

    #[test]
    fn not_moved_leads_with_the_previous_line() {
        let (plan, d) = plan_start(&facts(MarkerRead::Absent, Siblings::NoneHeardYet), &NEVER, &SPEC);
        assert_eq!(plan, StartPlan { primary: Line::V06, secondary: Some(Line::V07) });
        assert_eq!(d, Decision::Wanted(Why::NotMoved));
    }

    #[test]
    fn born_never_wants_it_and_owed_always_does() {
        let (plan, d) = plan_start(&facts(present(|m| m.born = true), Siblings::NoneHeardYet), &NEVER, &SPEC);
        assert_eq!((plan.primary, plan.secondary, d), (Line::V07, None, Decision::NotWanted(Why::Born)));
        let mut f = facts(present(|_| {}), Siblings::Heard(vec![]));
        f.owed = vec!["web_era".into()];
        assert_eq!(old_line_wanted(&f, &NEVER, &SPEC), Decision::Wanted(Why::Owed("web_era".into())));
    }

    #[test]
    fn a_sibling_on_the_previous_generation_wants_it_but_not_this_device_or_a_removed_one() {
        let f = facts(present(|_| {}), Siblings::Heard(vec![sib("me", "holochain-0.6", false), sib("old", "holochain-0.6", true), sib("new", "holochain-0.7", false)]));
        assert_eq!(old_line_wanted(&f, &NEVER, &SPEC), Decision::NotWanted(Why::NothingLeft));
        let f = facts(present(|_| {}), Siblings::Heard(vec![sib("laptop", "holochain-0.6", false)]));
        assert_eq!(old_line_wanted(&f, &NEVER, &SPEC), Decision::Wanted(Why::SiblingOnOld("laptop".into())));
    }

    #[test]
    fn a_restored_identity_listens_forever_under_the_1_7_0_policy() {
        let f = facts(present(|m| { m.restored = true; m.listening_since_ms = Some(0); }), Siblings::NoneHeardYet);
        assert_eq!(old_line_wanted(&f, &NEVER, &SPEC), Decision::Wanted(Why::Listening));
        // Heard from nobody but holding what it heard (a start from disk): nothing left.
        let f = facts(present(|m| m.restored = true), Siblings::Heard(vec![]));
        assert_eq!(old_line_wanted(&f, &NEVER, &SPEC), Decision::NotWanted(Why::NothingLeft));
    }

    #[test]
    fn a_window_closes_after_its_time_and_rounds() {
        let p = RetirementPolicy { alone_after: Some(std::time::Duration::from_secs(600)), alone_rounds: 3 };
        let listening = |rounds: u32, now_ms| {
            let mut f = facts(present(|m| { m.restored = true; m.listening_since_ms = Some(0); m.reachable_rounds = rounds; }), Siblings::NoneHeardYet);
            f.now_ms = now_ms;
            f
        };
        assert_eq!(old_line_wanted(&listening(5, 599_000), &p, &SPEC), Decision::Wanted(Why::Listening), "not long enough yet");
        assert_eq!(old_line_wanted(&listening(2, 600_000), &p, &SPEC), Decision::Wanted(Why::Listening), "not enough rounds reached a rendezvous");
        assert_eq!(write_targets(&listening(2, 600_000), &p, true, &SPEC).mirror, Some(Line::V06), "copies while it listens");
        assert_eq!(old_line_wanted(&listening(3, 600_000), &p, &SPEC), Decision::NotWanted(Why::Alone));
        assert_eq!(write_targets(&listening(3, 600_000), &p, true, &SPEC).mirror, None, "alone: nobody reads copies there");
        // No start recorded (restored by a version without one): it listens until a round starts the window.
        let mut f = listening(30, 10_000_000);
        if let MarkerRead::Present(m) = &mut f.marker { m.listening_since_ms = None; }
        assert_eq!(old_line_wanted(&f, &p, &SPEC), Decision::Wanted(Why::Listening));
    }

    #[test]
    fn an_unreadable_marker_moves_the_writes_and_wants_the_old_line() {
        let (plan, d) = plan_start(&facts(MarkerRead::Unreadable("x".into()), Siblings::NoneHeardYet), &NEVER, &SPEC);
        assert_eq!((plan.primary, plan.secondary, d), (Line::V07, Some(Line::V06), Decision::Wanted(Why::NotMoved)));
    }

    #[test]
    fn data_on_the_previous_line_is_kept_until_a_pass_has_carried_all_of_it() {
        // A 1.7.0 marker (no carried_all_ms) and the 0.6 line's data on disk.
        let not_carried = |edit: fn(&mut Marker), siblings| facts(present(|m| { m.carried_all_ms = None; edit(m) }), siblings);
        let f = not_carried(|_| {}, Siblings::Heard(vec![sib("phone", "holochain-0.7", false)]));
        assert_eq!(old_line_wanted(&f, &NEVER, &SPEC), Decision::Wanted(Why::NotCarried));
        assert_eq!(old_line_wanted(&not_carried(|_| {}, Siblings::NeverShared), &NEVER, &SPEC), Decision::Wanted(Why::NotCarried));
        // Nothing of it on the previous line (restored, never attached): nothing to carry.
        let mut f = not_carried(|m| m.restored = true, Siblings::Heard(vec![]));
        f.old_line_data_present = false;
        assert_eq!(old_line_wanted(&f, &NEVER, &SPEC), Decision::NotWanted(Why::NothingLeft));
        // A sibling still on it, or a restored identity still listening, says so first.
        let f = not_carried(|_| {}, Siblings::Heard(vec![sib("laptop", "holochain-0.6", false)]));
        assert_eq!(old_line_wanted(&f, &NEVER, &SPEC), Decision::Wanted(Why::SiblingOnOld("laptop".into())));
        let f = not_carried(|m| { m.restored = true; m.listening_since_ms = Some(0); }, Siblings::NoneHeardYet);
        assert_eq!(old_line_wanted(&f, &NEVER, &SPEC), Decision::Wanted(Why::Listening));
        // Alone, the window closed: still kept until what it holds is carried.
        let p = RetirementPolicy { alone_after: Some(std::time::Duration::from_secs(1)), alone_rounds: 0 };
        let f = not_carried(|m| { m.restored = true; m.listening_since_ms = Some(0); }, Siblings::NoneHeardYet);
        assert_eq!(old_line_wanted(&f, &p, &SPEC), Decision::Wanted(Why::NotCarried));
    }

    #[test]
    fn writes_go_to_the_previous_line_too_only_for_someone_who_reads_it_there() {
        let targets = |f: &Facts, running| write_targets(f, &NEVER, running, &SPEC);
        // Not moved: writes go to the previous line, and the pass carries them.
        let f = facts(MarkerRead::Absent, Siblings::Heard(vec![sib("laptop", "holochain-0.6", false)]));
        assert_eq!(targets(&f, true), WriteTargets { primary: Line::V06, mirror: None });
        // Moved, a device on the previous generation: both, while that line runs.
        let f = facts(present(|_| {}), Siblings::Heard(vec![sib("laptop", "holochain-0.6", false)]));
        assert_eq!(targets(&f, true), WriteTargets { primary: Line::V07, mirror: Some(Line::V06) });
        assert_eq!(targets(&f, false).mirror, None, "not running: nowhere to write");
        // Restored and still listening: both.
        let f = facts(present(|m| { m.restored = true; m.listening_since_ms = Some(0); }), Siblings::NoneHeardYet);
        assert_eq!(targets(&f, true).mirror, Some(Line::V06));
        // Running for a carry owed or a pass not yet complete, nobody on it: no copies.
        let mut f = facts(present(|m| m.carried_all_ms = None), Siblings::Heard(vec![sib("phone", "holochain-0.7", false), sib("old", "holochain-0.6", true)]));
        f.owed = vec!["web_era".into()];
        assert!(old_line_wanted(&f, &NEVER, &SPEC).wanted());
        assert_eq!(targets(&f, true).mirror, None);
        // Owed AND a device on it: the device still gets them.
        let mut f = facts(present(|_| {}), Siblings::Heard(vec![sib("laptop", "holochain-0.6", false)]));
        f.owed = vec!["web_era".into()];
        assert_eq!(old_line_wanted(&f, &NEVER, &SPEC), Decision::Wanted(Why::Owed("web_era".into())));
        assert_eq!(targets(&f, true).mirror, Some(Line::V06));
        // An unreadable marker: writes to the current line; a device on the previous one still gets copies.
        let f = facts(MarkerRead::Unreadable("x".into()), Siblings::Heard(vec![sib("laptop", "holochain-0.6", false)]));
        assert_eq!(targets(&f, true), WriteTargets { primary: Line::V07, mirror: Some(Line::V06) });
    }

    #[test]
    fn never_shared_does_not_want_it() {
        let f = facts(present(|m| m.restored = true), Siblings::NeverShared);
        assert_eq!(old_line_wanted(&f, &NEVER, &SPEC), Decision::NotWanted(Why::NeverShared));
    }
}
