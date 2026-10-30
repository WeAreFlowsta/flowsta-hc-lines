//! Orphaned sidecars from an earlier launch.
//!
//! When an app dies without its exit path (macOS kills a running app whose
//! bundle was replaced under it; a crash; a forced quit; an installer), its
//! conductor and key store live on. The next launch then starts a second
//! conductor on the same agent key: two conductors, one key, and gossip
//! quietly fails for both. Linux ties the children to the parent with a
//! parent-death signal and Windows with a kill-on-close job
//! ([`crate::process`]); macOS has neither.
//!
//! So every launch sweeps first: a sidecar whose parent is gone, or whose
//! parent is not a live copy of this app, belongs to nobody and is stopped.
//! A sidecar whose parent is a live copy of this app that is not us is left
//! alone (a staging build beside production, a second copy in another
//! account). Matching is by executable file name, never by port or folder,
//! and only the names the app passes in: two apps using this library on one
//! machine never touch each other's sidecars.

/// What is known about a candidate process's parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parent {
    /// The parent pid is not in the process table.
    Gone,
    /// The parent is this very process: our own child.
    Us,
    /// The parent is another live copy of this app (same executable path,
    /// or the same executable file name at another path).
    OtherCopy,
    /// The parent is some live process that is not this app.
    Foreign,
    /// The parent is itself one of our sidecars: a thread of a running
    /// sidecar (Linux lists every thread as a process) or its own child.
    Sidecar,
}

/// The file name without a Windows extension, lower-case.
pub fn stem_of(name: &str) -> String {
    let n = name.to_lowercase();
    n.strip_suffix(".exe").map(str::to_string).unwrap_or(n)
}

/// Whether `name` is one of `stems` (any case, with or without `.exe`).
pub fn is_sidecar_name(name: &str, stems: &[&str]) -> bool {
    let s = stem_of(name);
    stems.iter().any(|t| t.to_lowercase() == s)
}

/// The one decision: reaped when nothing of ours holds it. `Foreign` covers
/// a sidecar adopted by a subreaper (a systemd user session, a terminal
/// that ran the app): its app is gone all the same.
pub fn should_reap(name: &str, parent: Parent, stems: &[&str]) -> bool {
    is_sidecar_name(name, stems) && matches!(parent, Parent::Gone | Parent::Foreign)
}

/// Stop every orphaned sidecar named in `stems` (this app's sidecar file
/// names, every line). Returns how many were stopped. Call before the first
/// sidecar of this launch spawns.
pub fn reap_orphaned_sidecars(stems: &[&str]) -> u32 {
    use sysinfo::{ProcessRefreshKind, RefreshKind, System, UpdateKind};

    let me = sysinfo::Pid::from_u32(std::process::id());
    let my_exe = std::env::current_exe().ok();
    let my_name = my_exe.as_ref().and_then(|p| p.file_name().map(|n| stem_of(&n.to_string_lossy())));

    let sys = System::new_with_specifics(RefreshKind::nothing().with_processes(ProcessRefreshKind::nothing().with_exe(UpdateKind::Always)));
    let procs = sys.processes();
    let full_name = |p: &sysinfo::Process| -> String {
        match p.exe().and_then(|e| e.file_name()) {
            Some(n) => n.to_string_lossy().to_string(),
            None => p.name().to_string_lossy().to_string(),
        }
    };
    let is_this_app = |pid: &sysinfo::Pid| -> bool {
        procs
            .get(pid)
            .map(|p| {
                let same_path = matches!((p.exe(), my_exe.as_deref()), (Some(e), Some(mine)) if e == mine);
                same_path || Some(stem_of(&full_name(p))) == my_name
            })
            .unwrap_or(false)
    };

    let mut reaped = 0u32;
    for (pid, proc_) in procs {
        if *pid == me {
            continue;
        }
        let name = full_name(proc_);
        if !is_sidecar_name(&name, stems) {
            continue;
        }
        // Linux lists each thread as a process; stopping a thread's id stops
        // its whole process, which may be a live sidecar of another copy.
        if proc_.thread_kind().is_some() {
            continue;
        }
        let parent = match proc_.parent() {
            None => Parent::Gone,
            Some(pp) if pp == me => Parent::Us,
            Some(pp) if !procs.contains_key(&pp) => Parent::Gone,
            Some(pp) if procs.get(&pp).map(|q| is_sidecar_name(&full_name(q), stems)).unwrap_or(false) => Parent::Sidecar,
            Some(pp) if is_this_app(&pp) => Parent::OtherCopy,
            Some(_) => Parent::Foreign,
        };
        if should_reap(&name, parent, stems) {
            log::warn!("[instance] stopping orphaned sidecar {} (pid {}, parent {:?})", name, pid, parent);
            if proc_.kill() {
                reaped += 1;
            } else {
                log::warn!("[instance] could not stop pid {}", pid);
            }
        } else if parent == Parent::OtherCopy {
            log::info!("[instance] sidecar {} (pid {}) belongs to another running copy - left alone", name, pid);
        }
    }
    if reaped > 0 {
        // Give the kernel a beat to release the admin port.
        std::thread::sleep(std::time::Duration::from_millis(400));
    }
    reaped
}

#[cfg(test)]
mod tests {
    use super::*;

    const STEMS: &[&str] = &["app-holochain", "app-lair-keystore", "app-holochain-07", "app-lair-keystore-07"];

    #[test]
    fn only_the_given_names_match_with_or_without_exe() {
        assert!(is_sidecar_name("app-holochain", STEMS));
        assert!(is_sidecar_name("App-Lair-Keystore-07.EXE", STEMS));
        assert!(!is_sidecar_name("holochain", STEMS));
        assert!(!is_sidecar_name("other-holochain", STEMS), "another app's sidecar is never ours");
    }

    #[test]
    fn a_sidecar_is_reaped_only_when_nothing_of_ours_holds_it() {
        assert!(should_reap("app-holochain", Parent::Gone, STEMS));
        assert!(should_reap("app-lair-keystore", Parent::Foreign, STEMS));
        assert!(!should_reap("app-holochain", Parent::Us, STEMS));
        assert!(!should_reap("app-holochain", Parent::Sidecar, STEMS));
        assert!(!should_reap("app-holochain", Parent::OtherCopy, STEMS));
        assert!(!should_reap("holochain", Parent::Gone, STEMS));
    }

    /// A process named like a sidecar of a made-up app, double-forked so its
    /// parent is gone, is stopped; one we spawned is kept. Safe on any
    /// machine: only the made-up name is ever matched.
    #[test]
    #[cfg(unix)]
    fn live_sweep_stops_a_parentless_sidecar_and_keeps_our_own_child() {
        let name = format!("hclines-test-sidecar-{}", std::process::id());
        let dir = std::env::temp_dir().join(format!("hclines-reap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fake = dir.join(&name);
        std::fs::copy("/bin/sleep", &fake).unwrap();
        std::process::Command::new("sh").arg("-c").arg(format!("nohup '{}' 300 >/dev/null 2>&1 &", fake.display())).status().unwrap();
        let mut mine = std::process::Command::new(&fake).arg("300").spawn().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(400));

        let reaped = reap_orphaned_sidecars(&[name.as_str()]);
        assert!(reaped >= 1, "the parentless one is stopped ({} reaped)", reaped);
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(mine.try_wait().unwrap().is_none(), "our own child is kept");
        let _ = mine.kill();
        let _ = mine.wait();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
