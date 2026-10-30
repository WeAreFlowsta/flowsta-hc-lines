//! Own data with a logical id and a version time: the rules that make a
//! copy between lines idempotent and the same on every device.

use std::collections::HashMap;

/// One stored version of a record that carries a logical id and a version
/// time. An app implements this for its own stored type.
pub trait Versioned {
    /// The id that stays the same across versions and lines.
    fn logical_id(&self) -> String;
    /// When this version was written (the newest wins).
    fn version_time(&self) -> u64;
    /// When the record was first created (the copy order).
    fn created_at(&self) -> u64;
    /// Whether this version is a deletion.
    fn deleted(&self) -> bool;
    /// The raw 39-byte action hash of this version.
    fn action_hash(&self) -> &[u8];
}

/// Reduce every stored version to the newest per logical id. Returns the
/// winners (deletions included) and the versions they supersede. The order
/// between two versions is the same on every device: newer time first, then
/// a deletion over a live version, then the larger action hash.
pub fn latest_versions<V: Versioned>(versions: Vec<V>) -> (Vec<V>, Vec<V>) {
    let mut winners: HashMap<String, V> = HashMap::new();
    let mut superseded = Vec::new();
    for version in versions {
        let id = version.logical_id();
        match winners.get(&id) {
            None => {
                winners.insert(id, version);
            }
            Some(current) => {
                let rank = |v: &V| (v.version_time(), v.deleted(), v.action_hash().to_vec());
                if rank(&version) > rank(current) {
                    let old = winners.insert(id, version).expect("present");
                    superseded.push(old);
                } else if version.action_hash() != current.action_hash() {
                    superseded.push(version);
                }
            }
        }
    }
    (winners.into_values().collect(), superseded)
}

/// Which winners from the old line the new line lacks (no version there, or
/// an older one), in creation order, each with the action hash of the
/// new-line version it supersedes.
pub fn missing_on<'a, V: Versioned>(winners_old: &'a [V], held_new: &HashMap<String, V>) -> Vec<(&'a V, Option<Vec<u8>>)> {
    let mut list: Vec<&V> = winners_old
        .iter()
        .filter(|v| held_new.get(&v.logical_id()).map(|c| c.version_time() < v.version_time()).unwrap_or(true))
        .collect();
    list.sort_by(|a, b| a.created_at().cmp(&b.created_at()).then_with(|| a.action_hash().cmp(b.action_hash())));
    list.into_iter().map(|v| (v, held_new.get(&v.logical_id()).map(|c| c.action_hash().to_vec()))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, PartialEq)]
    struct V {
        id: &'static str,
        t: u64,
        created: u64,
        del: bool,
        hash: u8,
    }
    impl Versioned for V {
        fn logical_id(&self) -> String {
            self.id.into()
        }
        fn version_time(&self) -> u64 {
            self.t
        }
        fn created_at(&self) -> u64 {
            self.created
        }
        fn deleted(&self) -> bool {
            self.del
        }
        fn action_hash(&self) -> &[u8] {
            std::slice::from_ref(&self.hash)
        }
    }
    fn v(id: &'static str, t: u64, del: bool, hash: u8) -> V {
        V { id, t, created: 1, del, hash }
    }

    #[test]
    fn newest_wins_then_deletion_then_larger_hash() {
        let (w, s) = latest_versions(vec![v("a", 1, false, 1), v("a", 2, false, 2), v("b", 5, false, 3), v("b", 5, true, 4), v("c", 7, false, 5), v("c", 7, false, 6)]);
        let mut w: Vec<_> = w.into_iter().map(|x| (x.id, x.hash)).collect();
        w.sort();
        assert_eq!(w, vec![("a", 2), ("b", 4), ("c", 6)]);
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn the_same_winner_whatever_the_arrival_order() {
        let set = vec![v("a", 3, false, 9), v("a", 3, true, 1), v("a", 2, false, 5)];
        let mut rev = set.clone();
        rev.reverse();
        assert_eq!(latest_versions(set).0, latest_versions(rev).0);
    }

    #[test]
    fn missing_on_lists_what_the_new_line_lacks_or_holds_older() {
        let old = vec![V { id: "a", t: 5, created: 2, del: false, hash: 1 }, V { id: "b", t: 5, created: 1, del: false, hash: 2 }, V { id: "c", t: 5, created: 3, del: false, hash: 3 }];
        let mut held = HashMap::new();
        held.insert("a".to_string(), V { id: "a", t: 4, created: 2, del: false, hash: 9 });
        held.insert("c".to_string(), V { id: "c", t: 5, created: 3, del: false, hash: 8 });
        let m: Vec<_> = missing_on(&old, &held).into_iter().map(|(x, sup)| (x.id, sup)).collect();
        assert_eq!(m, vec![("b", None), ("a", Some(vec![9]))], "creation order; c is already current");
    }
}
