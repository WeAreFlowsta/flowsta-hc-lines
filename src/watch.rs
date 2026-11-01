//! The watchdog's decision: what to do about a line that stopped, the same
//! way in every app. The app does the work (where a start's secrets come
//! from, what it shows, what runs after a start) and runs one recovery at a
//! time; this says which recovery.

use crate::supervisor::Supervisor;
use crate::Line;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How an app recovers its lines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WatchPolicy {
    /// The line an identity's writes go to once it has moved
    /// (`MarkerSpec::current`): a dead secondary on it is attached again; a
    /// dead secondary on the other line is let go, and the app's line policy
    /// attaches it again if it is still wanted.
    pub current: Line,
    /// At most this many recoveries within the window, then hold; `None`:
    /// no limit (Flowsta Vault 1.7.0).
    pub limit: Option<(u32, Duration)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchAction {
    Nothing,
    /// The primary line's conductor is dead, or no session runs: start again.
    RestartSession,
    /// The secondary line is the current one and its conductor died: attach it again.
    Reattach(Line),
    /// The secondary line is the previous one and its conductor died: stop holding it.
    LetGo(Line),
    /// Recovered as often as the policy allows within its window: leave it and say so.
    Hold,
}

/// The lines as the supervisor sees them at one moment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinesNow {
    pub primary: Option<Line>,
    /// Whether each line's conductor runs; `None` without that line.
    pub v06: Option<bool>,
    pub v07: Option<bool>,
}

impl LinesNow {
    pub fn of(sup: &Supervisor) -> Self {
        Self { primary: sup.session().and(sup.primary()), v06: sup.alive(Line::V06), v07: sup.alive(Line::V07) }
    }

    fn alive(&self, line: Line) -> Option<bool> {
        match line {
            Line::V06 => self.v06,
            Line::V07 => self.v07,
        }
    }
}

/// The recovery the lines call for, without the limit.
pub fn decide(lines: &LinesNow, p: &WatchPolicy) -> WatchAction {
    let Some(primary) = lines.primary else { return WatchAction::RestartSession };
    if lines.alive(primary) != Some(true) {
        return WatchAction::RestartSession;
    }
    let other = match primary {
        Line::V06 => Line::V07,
        Line::V07 => Line::V06,
    };
    match lines.alive(other) {
        Some(false) if other == p.current => WatchAction::Reattach(other),
        Some(false) => WatchAction::LetGo(other),
        _ => WatchAction::Nothing,
    }
}

/// The decision with the policy's limit: each restart or re-attach it
/// hands out counts as one recovery (an attempt, so a start that fails
/// counts too); once `limit.0` fall within `limit.1`, it answers `Hold`
/// until the oldest leaves the window.
pub struct Watchdog {
    recoveries: Mutex<VecDeque<Instant>>,
}

impl Watchdog {
    pub const fn new() -> Self {
        Self { recoveries: Mutex::new(VecDeque::new()) }
    }

    pub fn action(&self, sup: &Supervisor, p: &WatchPolicy) -> WatchAction {
        self.action_at(&LinesNow::of(sup), p, Instant::now())
    }

    fn action_at(&self, lines: &LinesNow, p: &WatchPolicy, now: Instant) -> WatchAction {
        let action = decide(lines, p);
        if !matches!(action, WatchAction::RestartSession | WatchAction::Reattach(_)) {
            return action;
        }
        let mut recoveries = self.recoveries.lock().unwrap();
        if let Some((most, within)) = p.limit {
            while recoveries.front().is_some_and(|t| now.duration_since(*t) >= within) {
                recoveries.pop_front();
            }
            if recoveries.len() >= most as usize {
                return WatchAction::Hold;
            }
        }
        recoveries.push_back(now);
        action
    }
}

impl Default for Watchdog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VAULT: WatchPolicy = WatchPolicy { current: Line::V07, limit: None };

    fn lines(primary: Option<Line>, v06: Option<bool>, v07: Option<bool>) -> LinesNow {
        LinesNow { primary, v06, v07 }
    }

    #[test]
    fn a_dead_primary_or_no_session_restarts_the_session() {
        assert_eq!(decide(&lines(None, None, None), &VAULT), WatchAction::RestartSession);
        assert_eq!(decide(&lines(Some(Line::V06), Some(false), Some(true)), &VAULT), WatchAction::RestartSession);
        assert_eq!(decide(&lines(Some(Line::V07), Some(true), Some(false)), &VAULT), WatchAction::RestartSession);
        assert_eq!(decide(&lines(Some(Line::V07), None, None), &VAULT), WatchAction::RestartSession, "the primary's line gone from the session");
    }

    #[test]
    fn a_dead_secondary_comes_back_on_the_current_line_and_is_let_go_on_the_previous() {
        // Not moved yet: 0.6 leads, the 0.7 line beside it died.
        assert_eq!(decide(&lines(Some(Line::V06), Some(true), Some(false)), &VAULT), WatchAction::Reattach(Line::V07));
        // Moved: 0.7 leads, the 0.6 line beside it died.
        assert_eq!(decide(&lines(Some(Line::V07), Some(false), Some(true)), &VAULT), WatchAction::LetGo(Line::V06));
        // Alive, or not attached at all: nothing to do.
        assert_eq!(decide(&lines(Some(Line::V07), Some(true), Some(true)), &VAULT), WatchAction::Nothing);
        assert_eq!(decide(&lines(Some(Line::V07), None, Some(true)), &VAULT), WatchAction::Nothing);
    }

    #[test]
    fn the_limit_holds_after_too_many_recoveries_and_lets_go_as_they_age() {
        let p = WatchPolicy { current: Line::V07, limit: Some((3, Duration::from_secs(600))) };
        let dog = Watchdog::new();
        let dead = lines(Some(Line::V07), Some(true), Some(false));
        let t0 = Instant::now();
        for i in 0..3 {
            assert_eq!(dog.action_at(&dead, &p, t0 + Duration::from_secs(i * 60)), WatchAction::RestartSession);
        }
        assert_eq!(dog.action_at(&dead, &p, t0 + Duration::from_secs(300)), WatchAction::Hold);
        assert_eq!(dog.action_at(&lines(Some(Line::V07), Some(false), Some(true)), &p, t0 + Duration::from_secs(301)), WatchAction::LetGo(Line::V06), "letting go is never held");
        assert_eq!(dog.action_at(&dead, &p, t0 + Duration::from_secs(600)), WatchAction::RestartSession, "the first recovery left the window");
        assert_eq!(dog.action_at(&dead, &p, t0 + Duration::from_secs(601)), WatchAction::Hold);
        // No limit: never held.
        let free = Watchdog::new();
        for _ in 0..10 {
            assert_eq!(free.action_at(&dead, &VAULT, t0), WatchAction::RestartSession);
        }
    }
}
