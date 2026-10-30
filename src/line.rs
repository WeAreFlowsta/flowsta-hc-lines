//! Which Holochain line a conductor speaks.

/// A Holochain line: a series of releases that share a network and data
/// format. The serde names (`V06`, `V07`) are written inside on-disk records
/// (see [`crate::RecordView`]): they never change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum Line {
    /// Holochain 0.6: conductor 0.6.1, lair 0.6.3.
    V06,
    /// Holochain 0.7: conductor 0.7.1, lair 0.7.1.
    V07,
}

impl Line {
    /// The generation name a device announces to its siblings
    /// (`holochain-0.6`, `holochain-0.7`). It travels on the network, so it
    /// never changes for a line.
    pub const fn generation(self) -> &'static str {
        match self {
            Line::V06 => "holochain-0.6",
            Line::V07 => "holochain-0.7",
        }
    }

    /// The short name (`0.6`, `0.7`), as `Display` prints it.
    pub const fn short(self) -> &'static str {
        match self {
            Line::V06 => "0.6",
            Line::V07 => "0.7",
        }
    }

    /// The line whose generation name this is.
    pub fn from_generation(generation: &str) -> Option<Line> {
        [Line::V06, Line::V07].into_iter().find(|l| l.generation() == generation)
    }
}

impl std::fmt::Display for Line {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.short())
    }
}

/// Whether a sibling device on `sibling_generation` syncs with a device on
/// `viewer` only once it has updated: its records are on another network.
pub fn needs_update(sibling_generation: &str, viewer: Line) -> bool {
    sibling_generation != viewer.generation()
}

/// How many records a device holds, counted the way its siblings count:
/// the larger of its active line's view and its attached old line's, when
/// the old line is still attached. A sibling still on the old line counts
/// what it holds there (superseded versions included), and this device's
/// old cell holds that same set through the dual write, while its current
/// view is reduced to the newest version of each record. Counting only the
/// current view leaves the device reading as behind for good.
pub fn records_held(active: u64, attached_old: Option<u64>) -> u64 {
    attached_old.map_or(active, |old| active.max(old))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_names_its_generation() {
        assert_eq!(Line::V06.generation(), "holochain-0.6");
        assert_eq!(Line::V07.generation(), "holochain-0.7");
        assert_eq!(format!("{}", Line::V07), "0.7");
        assert_eq!(Line::from_generation("holochain-0.6"), Some(Line::V06));
        assert_eq!(Line::from_generation("holochain-0.8"), None);
    }

    #[test]
    fn a_sibling_on_the_other_generation_needs_the_update() {
        assert!(needs_update("holochain-0.6", Line::V07));
        assert!(!needs_update("holochain-0.7", Line::V07));
    }

    #[test]
    fn holds_are_the_larger_of_both_lines() {
        assert_eq!(records_held(10, None), 10);
        assert_eq!(records_held(10, Some(14)), 14);
        assert_eq!(records_held(10, Some(3)), 10);
    }

    #[test]
    fn the_serde_names_are_a_format() {
        assert_eq!(rmp_serde::to_vec_named(&Line::V06).unwrap(), rmp_serde::to_vec_named(&"V06").unwrap());
        assert_eq!(rmp_serde::to_vec_named(&Line::V07).unwrap(), rmp_serde::to_vec_named(&"V07").unwrap());
    }
}
