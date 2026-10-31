//! Whether an identity still needs its previous line, and which line its
//! start leads with: pure functions of local facts, so every rule is tested
//! without a conductor and every app decides the same way.

use crate::marker::{MarkerRead, MarkerSpec};
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
    /// Rounds that reached a rendezvous since listening began.
    pub reachable_rounds: u32,
    pub now_ms: u64,
}

/// How long a restored identity that has heard from no other device keeps
/// its previous line before it calls itself alone. `None`: forever, which
/// is what Flowsta Vault 1.7.0 does.
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
///    policy's window), then not (alone);
/// 6. never shared: not wanted;
/// 7. otherwise: not wanted (nothing left on it).
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
    let previous = spec.previous.generation();
    if let Siblings::Heard(list) = &f.siblings {
        if let Some(s) = list.iter().find(|s| !s.removed && s.generation == previous && Some(&s.device_id) != f.own_device_id.as_ref()) {
            return Decision::Wanted(Why::SiblingOnOld(s.device_id.clone()));
        }
    }
    match &f.siblings {
        Siblings::NoneHeardYet if m.restored => {
            let closed = match (p.alone_after, m.listening_since_ms) {
                (Some(after), Some(since)) => f.now_ms.saturating_sub(since) >= after.as_millis() as u64 && f.reachable_rounds >= p.alone_rounds,
                _ => false,
            };
            if closed { Decision::NotWanted(Why::Alone) } else { Decision::Wanted(Why::Listening) }
        }
        Siblings::NeverShared => Decision::NotWanted(Why::NeverShared),
        _ => Decision::NotWanted(Why::NothingLeft),
    }
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
    use crate::marker::Marker;

    const SPEC: MarkerSpec = MarkerSpec { file_name: "moved-07", old_line_key: "line_06_needed", previous: Line::V06, current: Line::V07 };

    fn facts(marker: MarkerRead, siblings: Siblings) -> Facts {
        Facts { marker, old_line_data_present: true, own_device_id: Some("me".into()), siblings, owed: vec![], reachable_rounds: 0, now_ms: 1_000_000 }
    }
    fn present(edit: impl FnOnce(&mut Marker)) -> MarkerRead {
        let mut m = Marker::new(&SPEC, 1);
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
        let mut f = facts(present(|m| { m.restored = true; m.listening_since_ms = Some(0); }), Siblings::NoneHeardYet);
        f.now_ms = 599_000;
        f.reachable_rounds = 5;
        assert_eq!(old_line_wanted(&f, &p, &SPEC), Decision::Wanted(Why::Listening), "not long enough yet");
        f.now_ms = 600_000;
        f.reachable_rounds = 2;
        assert_eq!(old_line_wanted(&f, &p, &SPEC), Decision::Wanted(Why::Listening), "not enough rounds reached a rendezvous");
        f.reachable_rounds = 3;
        assert_eq!(old_line_wanted(&f, &p, &SPEC), Decision::NotWanted(Why::Alone));
    }

    #[test]
    fn an_unreadable_marker_moves_the_writes_and_wants_the_old_line() {
        let (plan, d) = plan_start(&facts(MarkerRead::Unreadable("x".into()), Siblings::NoneHeardYet), &NEVER, &SPEC);
        assert_eq!((plan.primary, plan.secondary, d), (Line::V07, Some(Line::V06), Decision::Wanted(Why::NotMoved)));
    }

    #[test]
    fn never_shared_does_not_want_it() {
        let f = facts(present(|m| m.restored = true), Siblings::NeverShared);
        assert_eq!(old_line_wanted(&f, &NEVER, &SPEC), Decision::NotWanted(Why::NeverShared));
    }
}
