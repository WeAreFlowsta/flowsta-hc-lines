//! macOS: a sidecar ends when the app does.
//!
//! Linux ends a sidecar when its parent dies (`PR_SET_PDEATHSIG`) and
//! Windows does it with a job object. macOS has neither, so after a crash
//! or a forced quit the conductor and the key store ran on, the key store
//! unlocked, until the next launch swept them.
//!
//! Here each sidecar gets a watcher: the app's own program, started a
//! second time in a watch mode,
//!
//! ```text
//! <app> --watch-sidecar <the app's pid> <the sidecar's pid>
//! ```
//!
//! which waits for either process to end (kqueue `NOTE_EXIT`). When the app
//! ends first, the watcher stops the sidecar (SIGTERM, then SIGKILL after
//! five seconds) and ends. When the sidecar ends first (a clean quit, a
//! restart), the watcher just ends. No new program to sign or notarize: it
//! is the app's own executable.
//!
//! The sidecar stays the app's own child, started exactly as before: its
//! pid, its pipes and the way it is stopped are unchanged. The watcher is a
//! process beside it, not around it.
//!
//! An app turns this on by calling [`run_as_sidecar_watcher_if_asked`] as
//! the first thing in `main`. A program that never calls it starts no
//! watcher (it would start a second copy of itself with arguments it does
//! not know). The sweep at launch stays as the second line.

use std::sync::atomic::{AtomicBool, Ordering};

/// The first argument of a program started as a watcher.
pub const WATCH_FLAG: &str = "--watch-sidecar";

/// How long a sidecar gets to end after SIGTERM before SIGKILL.
pub const STOP_GRACE_SECS: i64 = 5;

/// Set once the app has said, by calling the hook, that its `main` handles
/// the watch mode.
static ARMED: AtomicBool = AtomicBool::new(false);

/// What a program's arguments (without the program name) ask for: `None`
/// when it was not started as a watcher, else the app's pid and the
/// sidecar's, or why they could not be read.
pub fn watch_request(args: &[String]) -> Option<Result<(u32, u32), String>> {
    if args.first().map(String::as_str) != Some(WATCH_FLAG) {
        return None;
    }
    let pid = |i: usize, what: &str| -> Result<u32, String> {
        let text = args.get(i).ok_or_else(|| format!("{WATCH_FLAG}: {what} pid missing"))?;
        match text.parse::<u32>() {
            // 0 and 1 are never an app or a sidecar; kill(0) and kill(1) must never be sent.
            Ok(p) if p > 1 => Ok(p),
            _ => Err(format!("{WATCH_FLAG}: {what} pid {text:?} is not a process id")),
        }
    };
    Some(pid(1, "the app's").and_then(|app| pid(2, "the sidecar's").map(|sidecar| (app, sidecar))))
}

/// Call first in `main`. Started as a watcher, this watches and never
/// returns. Started as the app, it returns at once and, on macOS, turns the
/// watchers on for every sidecar this process spawns.
pub fn run_as_sidecar_watcher_if_asked() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match watch_request(&args) {
        None => ARMED.store(true, Ordering::SeqCst),
        Some(Ok((app, sidecar))) => std::process::exit(watch(app, sidecar)),
        Some(Err(why)) => {
            eprintln!("{why}");
            std::process::exit(2);
        }
    }
}

/// Whether this process starts a watcher beside each sidecar.
pub fn armed() -> bool {
    cfg!(target_os = "macos") && ARMED.load(Ordering::SeqCst)
}

/// Start a watcher for a sidecar this process just spawned. A no-op unless
/// [`armed`]. A watcher that cannot be started is logged and the sidecar
/// runs on as before: the launch sweep still covers it.
pub(crate) fn watch_over(sidecar_pid: u32) {
    if !armed() {
        return;
    }
    let program = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            log::warn!("[sidecar watcher] this program's own path could not be read ({e}); sidecar {sidecar_pid} has no watcher");
            return;
        }
    };
    let spawned = std::process::Command::new(&program)
        .arg(WATCH_FLAG)
        .arg(std::process::id().to_string())
        .arg(sidecar_pid.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    match spawned {
        Ok(mut watcher) => {
            log::info!("[sidecar watcher] pid {} watches sidecar {sidecar_pid}", watcher.id());
            // The watcher ends when the sidecar does: collect it, so a
            // sidecar restarted many times leaves no finished processes.
            std::thread::spawn(move || {
                let _ = watcher.wait();
            });
        }
        Err(e) => log::warn!("[sidecar watcher] not started for sidecar {sidecar_pid}: {e}"),
    }
}

/// Wait until the app or the sidecar ends; when the app ends first, stop
/// the sidecar. Returns the watcher's exit code: 0 when it did its work,
/// 3 when the system refused the watch.
#[cfg(target_os = "macos")]
pub fn watch(app: u32, sidecar: u32) -> i32 {
    use std::ptr;

    // SAFETY: kqueue and kevent on a descriptor this function owns, with
    // buffers of the sizes passed; kill on pids checked to be above 1.
    unsafe {
        let kq = libc::kqueue();
        if kq < 0 {
            return 3;
        }
        let on_exit = |pid: u32| libc::kevent {
            ident: pid as libc::uintptr_t,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT | libc::EV_RECEIPT,
            fflags: libc::NOTE_EXIT,
            data: 0,
            udata: ptr::null_mut(),
        };
        let changes = [on_exit(app), on_exit(sidecar)];
        let mut receipts: [libc::kevent; 2] = std::mem::zeroed();
        let n = libc::kevent(kq, changes.as_ptr(), 2, receipts.as_mut_ptr(), 2, ptr::null());
        if n < 0 {
            libc::close(kq);
            return 3;
        }
        // With EV_RECEIPT each change answers with its own result: `data`
        // is 0, or the error (ESRCH: that process is already gone).
        let gone = |pid: u32| {
            receipts[..n as usize]
                .iter()
                .any(|r| r.ident == pid as libc::uintptr_t && (r.flags & libc::EV_ERROR) != 0 && r.data as i32 == libc::ESRCH)
        };
        let code = if gone(sidecar) {
            // Nothing to watch over.
            0
        } else if gone(app) {
            stop(kq, sidecar);
            0
        } else {
            loop {
                let mut event: libc::kevent = std::mem::zeroed();
                let n = libc::kevent(kq, ptr::null(), 0, &mut event, 1, ptr::null());
                if n < 0 {
                    if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    break 3;
                }
                if n == 0 {
                    continue;
                }
                if event.ident == sidecar as libc::uintptr_t {
                    // The sidecar ended by itself or was stopped by the app.
                    break 0;
                }
                if event.ident == app as libc::uintptr_t {
                    stop(kq, sidecar);
                    break 0;
                }
            }
        };
        libc::close(kq);
        code
    }
}

/// SIGTERM, then SIGKILL if the sidecar is still there after the grace.
/// The watch on the sidecar was registered while it ran, so its end is
/// read from the same queue: the pid cannot have passed to another program
/// unnoticed.
///
/// # Safety
/// `kq` is an open kqueue with an exit watch on `sidecar`.
#[cfg(target_os = "macos")]
unsafe fn stop(kq: libc::c_int, sidecar: u32) {
    libc::kill(sidecar as libc::pid_t, libc::SIGTERM);
    let grace = libc::timespec { tv_sec: STOP_GRACE_SECS as libc::time_t, tv_nsec: 0 };
    let mut event: libc::kevent = std::mem::zeroed();
    loop {
        let n = libc::kevent(kq, std::ptr::null(), 0, &mut event, 1, &grace);
        if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if n > 0 && event.ident != sidecar as libc::uintptr_t {
            // The app's own exit event, read again: keep waiting for the sidecar's.
            continue;
        }
        if n <= 0 {
            // Still running after the grace (or the wait failed): end it.
            libc::kill(sidecar as libc::pid_t, libc::SIGKILL);
        }
        return;
    }
}

/// Other systems tie a sidecar to the app another way; a program started
/// as a watcher there has nothing to do.
#[cfg(not(target_os = "macos"))]
pub fn watch(_app: u32, _sidecar: u32) -> i32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn an_ordinary_start_is_not_a_watch_request() {
        assert_eq!(watch_request(&args(&[])), None);
        assert_eq!(watch_request(&args(&["--minimized"])), None);
        assert_eq!(watch_request(&args(&["flowsta://open", "--watch-sidecar", "10", "11"])), None, "the flag counts only as the first argument");
    }

    #[test]
    fn a_watch_request_names_two_real_pids() {
        assert_eq!(watch_request(&args(&["--watch-sidecar", "4321", "4322"])), Some(Ok((4321, 4322))));
        for bad in [&["--watch-sidecar"][..], &["--watch-sidecar", "4321"], &["--watch-sidecar", "x", "4322"], &["--watch-sidecar", "4321", "-5"]] {
            assert!(matches!(watch_request(&args(bad)), Some(Err(_))), "{bad:?}");
        }
        // Never the whole process group or launchd.
        assert!(matches!(watch_request(&args(&["--watch-sidecar", "0", "4322"])), Some(Err(_))));
        assert!(matches!(watch_request(&args(&["--watch-sidecar", "4321", "1"])), Some(Err(_))));
    }

    #[test]
    fn nothing_is_watched_until_the_app_says_its_main_handles_the_flag() {
        // The test program never calls the hook: spawning it again with the
        // flag would start the test runner a second time.
        assert!(!armed());
        watch_over(999_999);
    }

    #[cfg(target_os = "macos")]
    mod on_macos {
        use super::super::*;
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        fn alive(pid: u32) -> bool {
            // SAFETY: signal 0 only checks that the process exists.
            unsafe { libc::kill(pid as i32, 0) == 0 }
        }

        /// A stand-in app (a shell) with a stand-in sidecar as its child
        /// (`sleep`), as an app and its conductor are. Returns the shell
        /// and the sidecar's pid.
        fn app_with_sidecar(sidecar_secs: u32, app_secs: u32) -> (std::process::Child, u32) {
            let mut app = Command::new("/bin/sh")
                .arg("-c")
                .arg(format!("sleep {sidecar_secs} & echo $!; sleep {app_secs}"))
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let mut line = String::new();
            BufReader::new(app.stdout.take().unwrap()).read_line(&mut line).unwrap();
            (app, line.trim().parse().unwrap())
        }

        #[test]
        fn a_sidecar_ends_within_five_seconds_of_its_app_being_killed() {
            let (mut app, sidecar) = app_with_sidecar(120, 120);
            assert!(alive(sidecar));
            let app_pid = app.id();
            let watcher = std::thread::spawn(move || watch(app_pid, sidecar));
            std::thread::sleep(Duration::from_millis(300));
            // The app dies the hard way: no chance to stop its sidecar.
            app.kill().unwrap();
            app.wait().unwrap();
            let killed = Instant::now();
            while alive(sidecar) && killed.elapsed() < Duration::from_secs(5) {
                std::thread::sleep(Duration::from_millis(50));
            }
            assert!(!alive(sidecar), "the sidecar outlived its app by five seconds");
            assert_eq!(watcher.join().unwrap(), 0);
        }

        #[test]
        fn a_sidecar_that_ends_by_itself_ends_its_watcher_and_nothing_else() {
            let (mut app, sidecar) = app_with_sidecar(1, 120);
            let app_pid = app.id();
            let started = Instant::now();
            assert_eq!(watch(app_pid, sidecar), 0);
            assert!(started.elapsed() < Duration::from_secs(10), "the watcher did not end with its sidecar");
            assert!(alive(app_pid), "the app was touched");
            app.kill().unwrap();
            app.wait().unwrap();
        }

        #[test]
        fn a_watcher_started_after_the_app_is_gone_stops_the_sidecar_at_once() {
            let (mut app, sidecar) = app_with_sidecar(120, 120);
            let app_pid = app.id();
            app.kill().unwrap();
            app.wait().unwrap();
            assert!(alive(sidecar));
            assert_eq!(watch(app_pid, sidecar), 0);
            let stopped = Instant::now();
            while alive(sidecar) && stopped.elapsed() < Duration::from_secs(2) {
                std::thread::sleep(Duration::from_millis(50));
            }
            assert!(!alive(sidecar));
        }

        #[test]
        fn a_watcher_for_a_sidecar_already_gone_ends_at_once() {
            let (mut app, sidecar) = app_with_sidecar(0, 120);
            // The sidecar (sleep 0) has ended; the shell has not collected
            // it, so its pid is still held: wait for the shell to move on.
            std::thread::sleep(Duration::from_millis(500));
            let started = Instant::now();
            assert_eq!(watch(app.id(), sidecar), 0);
            assert!(started.elapsed() < Duration::from_secs(5));
            app.kill().unwrap();
            app.wait().unwrap();
        }
    }
}
