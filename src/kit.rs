//! The kit cache: each line's conductor, key store and files, kept
//! compressed in the app's data folder, so a later release that no longer
//! bundles a line can still run it from disk, offline, with no download.
//! An installer replaces the app's folder, its sidecars included, but keeps
//! the data folder; the app sets its own kits aside there at every start.
//!
//! A cached kit is untrusted until restored: `restore` checks every file
//! against the hashes compiled into the release doing the restore, never
//! against what the cache recorded. It writes fresh files (a copy can carry
//! macOS's quarantine flag; a decompressed file does not), sets the
//! executable bit and removes a quarantine flag if one is there.
//!
//! Blocking: run `put`, `restore` and `prune` on a blocking thread.

use crate::error::{Error, Result};
use crate::marker::{Marker, MarkerRead, MarkerSpec};
use crate::sidecar::{exe_suffix, resolve_sidecar, SidecarSource, TARGET_TRIPLE};
use crate::Line;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// The zstd level kits are written at. Measured on the Linux sidecars
/// (2026-11-01, zstd 1.5.7, one thread): a line's conductor and key store,
/// about 67 MiB, pack to 21.4 MiB in 2 s; level 19 saves 2.7 MiB more for
/// 30 s. Unpacking takes the same time at every level.
pub const LEVEL: i32 = 9;

const MANIFEST: &str = "kit.json";
const RUN_DIR: &str = "run";
const KNOWN_LINES: [Line; 2] = [Line::V06, Line::V07];

/// Everything one line needs to run, described once and compiled in.
#[derive(Clone, Copy, Debug)]
pub struct KitDescriptor {
    pub line: Line,
    pub conductor: KitBinary,
    pub lair: KitBinary,
    /// The files the line loads from the app's resources: hApp bundles,
    /// coordinator wasm.
    pub files: &'static [KitFile],
}

#[derive(Clone, Copy, Debug)]
pub struct KitBinary {
    /// The sidecar's name, as `resolve_sidecar` takes it. Cached and
    /// restored under it (with `.exe` on Windows), so the app's reaper and
    /// console hider, which go by file name, know the restored copy.
    pub sidecar: &'static str,
    pub version: &'static str,
    /// `(target triple, sha256 hex)` of every build of this binary the
    /// release accepts on restore: each release's post-signing hashes,
    /// compiled into the next. A release that bundles the binary may leave
    /// it empty: it caches the binary but cannot restore it.
    pub accepted: &'static [(&'static str, &'static str)],
}

#[derive(Clone, Copy, Debug)]
pub struct KitFile {
    /// The file's name in the app's resources folder.
    pub name: &'static str,
    pub sha256: &'static str,
}

#[derive(Debug, thiserror::Error)]
pub enum KitError {
    #[error("{name} is not in the {line} kit cache")]
    NotCached { line: Line, name: String },
    /// The release names no build of this binary for this platform.
    #[error("this release accepts no {name} build for {}", TARGET_TRIPLE)]
    NotAccepted { line: Line, name: String },
    /// The restored bytes are not a build this release accepts; the cached
    /// copy is deleted, so the next `put` writes it again.
    #[error("{name} in the {line} kit is not a build this release accepts (sha256 {sha256})")]
    HashMismatch { line: Line, name: String, sha256: String },
    /// The cached copy does not decompress; it is deleted.
    #[error("{name} in the {line} kit does not unpack: {reason}")]
    Unreadable { line: Line, name: String, reason: String },
    /// A bundled file is not the one the descriptor names: not cached.
    #[error("the bundled {name} is not the file the {line} kit names (sha256 {sha256})")]
    SourceChanged { line: Line, name: String, sha256: String },
}

/// What the cache records about one line's kit, for status only: a restore
/// never trusts it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KitManifest {
    pub v: u32,
    pub line: Line,
    /// The platform the binaries were cached on.
    pub target: String,
    pub entries: Vec<KitEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KitEntry {
    /// The sidecar's name, or the file's.
    pub name: String,
    /// Of the uncompressed bytes.
    pub sha256: String,
    pub size: u64,
    /// The compressed copy's size.
    pub packed: u64,
}

impl KitManifest {
    pub fn packed_bytes(&self) -> u64 {
        self.entries.iter().map(|e| e.packed).sum()
    }
}

/// What a `put` did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KitPut {
    pub line: Line,
    /// The entries compressed this time (missing or changed).
    pub written: Vec<String>,
    /// The entries already cached as they are.
    pub kept: usize,
    pub packed: u64,
}

/// A kit restored and verified, ready to run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoredKit {
    pub line: Line,
    /// Holds the two binaries and the files: the line's sidecar folder
    /// (`SidecarSource::kit_dirs`) and its resources folder.
    pub dir: PathBuf,
    pub conductor: PathBuf,
    pub lair: PathBuf,
}

/// One folder per line under a folder the app names (`<dir>/holochain-0.6/`).
pub struct KitCache {
    dir: PathBuf,
}

enum Source<'a> {
    Binary(&'a KitBinary),
    File(&'a KitFile),
}

impl Source<'_> {
    fn name(&self) -> &'static str {
        match self {
            Source::Binary(b) => b.sidecar,
            Source::File(f) => f.name,
        }
    }
}

fn sources(d: &KitDescriptor) -> Vec<Source<'_>> {
    let mut all = vec![Source::Binary(&d.conductor), Source::Binary(&d.lair)];
    all.extend(d.files.iter().map(Source::File));
    all
}

fn io<'a>(what: &'static str, path: &'a Path) -> impl FnOnce(std::io::Error) -> Error + 'a {
    move |source| Error::Io { what, path: path.to_path_buf(), source }
}

fn packed_name(name: &str) -> String {
    format!("{name}.zst")
}

impl KitCache {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn line_dir(&self, line: Line) -> PathBuf {
        self.dir.join(line.generation())
    }

    /// What the cache holds for this line, by its own record.
    pub fn manifest(&self, line: Line) -> Option<KitManifest> {
        let bytes = std::fs::read(self.line_dir(line).join(MANIFEST)).ok()?;
        serde_json::from_slice::<KitManifest>(&bytes).ok().filter(|m| m.line == line)
    }

    /// Cache this line's bundled kit: each binary (found as the app runs
    /// it, never on the PATH) and each file is compressed when it is
    /// missing or changed. A bundled file whose hash is not the
    /// descriptor's is refused. The binaries' hashes are recorded, not
    /// checked: their post-signing hashes reach only the next release.
    pub fn put(&self, d: &KitDescriptor, sidecars: &SidecarSource, resources: &Path) -> Result<KitPut> {
        let dir = self.line_dir(d.line);
        std::fs::create_dir_all(&dir).map_err(io("create the kit folder", &dir))?;
        let old = self.manifest(d.line).filter(|m| m.target == TARGET_TRIPLE);
        let bundled = SidecarSource { allow_path_lookup: false, ..sidecars.clone() };
        let (mut entries, mut written) = (Vec::new(), Vec::new());
        for source in sources(d) {
            let name = source.name();
            let src = match &source {
                Source::Binary(b) => resolve_sidecar(b.sidecar, &bundled)?,
                Source::File(f) => resources.join(f.name),
            };
            let (sha256, size) = hash_file(&src)?;
            if let Source::File(f) = &source {
                if !sha256.eq_ignore_ascii_case(f.sha256) {
                    return Err(KitError::SourceChanged { line: d.line, name: name.to_string(), sha256 }.into());
                }
            }
            let packed_path = dir.join(packed_name(name));
            let cached = old.as_ref().and_then(|m| m.entries.iter().find(|e| e.name == name)).filter(|e| e.sha256 == sha256 && std::fs::metadata(&packed_path).ok().map(|m| m.len()) == Some(e.packed));
            let entry = match cached {
                Some(e) => e.clone(),
                None => {
                    let packed = compress(&src, &packed_path)?;
                    written.push(name.to_string());
                    KitEntry { name: name.to_string(), sha256, size, packed }
                }
            };
            entries.push(entry);
        }
        // What an earlier descriptor named (a bundle since replaced), and
        // anything a stopped write left half done.
        let keep: Vec<String> = entries.iter().map(|e| packed_name(&e.name)).collect();
        if let Ok(read) = std::fs::read_dir(&dir) {
            for item in read.flatten() {
                let file_name = item.file_name().to_string_lossy().to_string();
                if item.path().is_file() && file_name != MANIFEST && !keep.contains(&file_name) {
                    let _ = std::fs::remove_file(item.path());
                }
            }
        }
        let manifest = KitManifest { v: 1, line: d.line, target: TARGET_TRIPLE.to_string(), entries };
        let path = dir.join(MANIFEST);
        let json = serde_json::to_vec_pretty(&manifest).expect("a manifest serializes");
        crate::files::write_atomic(&path, &json).map_err(io("write the kit manifest", &path))?;
        Ok(KitPut { line: d.line, kept: manifest.entries.len() - written.len(), packed: manifest.packed_bytes(), written })
    }

    /// Unpack this line's kit into `<line folder>/run/`, every file checked
    /// against `d` as it is written. The binaries need a hash in
    /// `accepted` for this platform, checked before anything is unpacked.
    pub fn restore(&self, d: &KitDescriptor) -> Result<RestoredKit> {
        let dir = self.line_dir(d.line);
        let run = dir.join(RUN_DIR);
        let mut plan = Vec::new();
        for source in sources(d) {
            let name = source.name();
            let (out_name, expected): (String, Vec<&str>) = match &source {
                Source::Binary(b) => (format!("{name}{}", exe_suffix()), b.accepted.iter().filter(|(t, _)| *t == TARGET_TRIPLE).map(|(_, h)| *h).collect()),
                Source::File(f) => (name.to_string(), vec![f.sha256]),
            };
            if expected.is_empty() {
                return Err(KitError::NotAccepted { line: d.line, name: name.to_string() }.into());
            }
            let packed = dir.join(packed_name(name));
            if !packed.is_file() {
                return Err(KitError::NotCached { line: d.line, name: name.to_string() }.into());
            }
            plan.push((name, matches!(source, Source::Binary(_)), out_name, expected, packed));
        }
        std::fs::create_dir_all(&run).map_err(io("create the kit's run folder", &run))?;
        for (name, executable, out_name, expected, packed) in plan {
            let out = run.join(&out_name);
            let part = run.join(format!("{out_name}.part"));
            let unpacked = unpack(&packed, &part);
            let sha256 = match unpacked {
                Ok(sha256) => sha256,
                Err(Unpack::Write(e)) => {
                    let _ = std::fs::remove_file(&part);
                    return Err(Error::Io { what: "write a restored kit file", path: part, source: e });
                }
                Err(Unpack::Read(reason)) => {
                    let _ = std::fs::remove_file(&part);
                    let _ = std::fs::remove_file(&packed);
                    return Err(KitError::Unreadable { line: d.line, name: name.to_string(), reason }.into());
                }
            };
            if !expected.iter().any(|h| h.eq_ignore_ascii_case(&sha256)) {
                let _ = std::fs::remove_file(&part);
                let _ = std::fs::remove_file(&packed);
                return Err(KitError::HashMismatch { line: d.line, name: name.to_string(), sha256 }.into());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = if executable { 0o755 } else { 0o644 };
                std::fs::set_permissions(&part, std::fs::Permissions::from_mode(mode)).map_err(io("set a restored file's mode", &part))?;
            }
            #[cfg(not(unix))]
            let _ = executable;
            remove_quarantine(&part);
            std::fs::rename(&part, &out).map_err(io("move a restored kit file into place", &out))?;
        }
        let exe = |b: &KitBinary| run.join(format!("{}{}", b.sidecar, exe_suffix()));
        Ok(RestoredKit { line: d.line, conductor: exe(&d.conductor), lair: exe(&d.lair), dir: run })
    }

    /// Delete the kits of every line not in `keep`; returns the bytes freed.
    /// Never prune a line a conductor runs from.
    pub fn prune(&self, keep: &[Line]) -> Result<u64> {
        let mut freed = 0;
        for line in KNOWN_LINES.into_iter().filter(|l| !keep.contains(l)) {
            let dir = self.line_dir(line);
            if dir.is_dir() {
                freed += folder_bytes(&dir);
                std::fs::remove_dir_all(&dir).map_err(io("remove a kit", &dir))?;
            }
        }
        Ok(freed)
    }
}

/// Whether any identity (or profile) root on the device may still need the
/// previous line, so its kit stays cached. Leans to keeping it: a root with
/// no marker that holds data on the previous line (`holds_previous` says
/// how the app tells), a marker that does not read, and a moved root with
/// no decision recorded all need it. A moved root is done with it once its
/// marker says the old line is no longer needed AND records that a pass
/// carried everything (`carried_all_ms`: an earlier rule decided the first
/// without the second). A root born on the current line never needs it.
pub fn previous_line_needed(roots: &[PathBuf], spec: &MarkerSpec, holds_previous: impl Fn(&Path) -> bool) -> bool {
    roots.iter().any(|root| match Marker::load(root, spec) {
        MarkerRead::Absent => holds_previous(root),
        MarkerRead::Unreadable(_) => true,
        MarkerRead::Present(m) => !m.born && (m.old_line_needed != Some(false) || m.carried_all_ms.is_none()),
    })
}

fn hash_file(path: &Path) -> Result<(String, u64)> {
    let mut file = std::fs::File::open(path).map_err(io("read a kit source", path))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut size = 0u64;
    loop {
        let n = file.read(&mut buf).map_err(io("read a kit source", path))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        size += n as u64;
    }
    Ok((hex::encode(hasher.finalize()), size))
}

/// Compress `src` to `dst` through `<dst>.part`, so `dst` is never half written.
fn compress(src: &Path, dst: &Path) -> Result<u64> {
    let mut part_name = dst.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    part_name.push(".part");
    let part = dst.with_file_name(part_name);
    let write = || -> std::io::Result<()> {
        let mut input = std::fs::File::open(src)?;
        let mut encoder = zstd::stream::Encoder::new(std::fs::File::create(&part)?, LEVEL)?;
        encoder.include_checksum(true)?;
        std::io::copy(&mut input, &mut encoder)?;
        encoder.finish()?.sync_all()
    };
    if let Err(e) = write() {
        let _ = std::fs::remove_file(&part);
        return Err(Error::Io { what: "compress a kit file", path: src.to_path_buf(), source: e });
    }
    std::fs::rename(&part, dst).map_err(io("move a kit file into place", dst))?;
    std::fs::metadata(dst).map(|m| m.len()).map_err(io("read a kit file's size", dst))
}

enum Unpack {
    /// The cached copy did not decompress.
    Read(String),
    /// Writing the restored file failed (the cache is not at fault).
    Write(std::io::Error),
}

/// Decompress `packed` into a fresh `out`, returning the sha256 of what was written.
fn unpack(packed: &Path, out: &Path) -> std::result::Result<String, Unpack> {
    let input = std::fs::File::open(packed).map_err(|e| Unpack::Read(e.to_string()))?;
    let mut decoder = zstd::stream::Decoder::new(input).map_err(|e| Unpack::Read(e.to_string()))?;
    let _ = std::fs::remove_file(out);
    let mut file = std::fs::File::create(out).map_err(Unpack::Write)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = decoder.read(&mut buf).map_err(|e| Unpack::Read(e.to_string()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        file.write_all(&buf[..n]).map_err(Unpack::Write)?;
    }
    file.sync_all().map_err(Unpack::Write)?;
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(target_os = "macos")]
fn remove_quarantine(path: &Path) {
    use std::os::unix::ffi::OsStrExt;
    let (Ok(p), Ok(name)) = (std::ffi::CString::new(path.as_os_str().as_bytes()), std::ffi::CString::new("com.apple.quarantine")) else { return };
    // A fresh file has no flag: ENOATTR is the usual answer.
    unsafe { libc::removexattr(p.as_ptr(), name.as_ptr(), 0) };
}

#[cfg(not(target_os = "macos"))]
fn remove_quarantine(_path: &Path) {}

fn folder_bytes(dir: &Path) -> u64 {
    std::fs::read_dir(dir)
        .map(|read| {
            read.flatten()
                .map(|e| match e.file_type() {
                    Ok(t) if t.is_dir() => folder_bytes(&e.path()),
                    Ok(_) => e.metadata().map(|m| m.len()).unwrap_or(0),
                    Err(_) => 0,
                })
                .sum()
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leak(s: String) -> &'static str {
        Box::leak(s.into_boxed_str())
    }

    fn sha(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    struct Fixture {
        root: PathBuf,
        bins: PathBuf,
        resources: PathBuf,
        cache: KitCache,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    const CONDUCTOR_BYTES: &[u8] = b"#!/bin/sh\necho conductor-from-the-kit\n";
    const LAIR_BYTES: &[u8] = b"#!/bin/sh\necho lair-from-the-kit\n";

    /// A dev binaries folder with two sidecars and a resources folder with
    /// two files, as an app bundles a line.
    fn fixture(name: &str) -> Fixture {
        let root = std::env::temp_dir().join(format!("hcl-kit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (bins, resources) = (root.join("binaries"), root.join("resources"));
        std::fs::create_dir_all(&bins).unwrap();
        std::fs::create_dir_all(&resources).unwrap();
        std::fs::write(bins.join(format!("test-holochain-{TARGET_TRIPLE}{}", exe_suffix())), CONDUCTOR_BYTES).unwrap();
        std::fs::write(bins.join(format!("test-lair-{TARGET_TRIPLE}{}", exe_suffix())), LAIR_BYTES).unwrap();
        std::fs::write(resources.join("app.happ"), vec![7u8; 300_000]).unwrap();
        std::fs::write(resources.join("coordinator.wasm"), b"\0asm coordinator").unwrap();
        let cache = KitCache::new(root.join("kits"));
        Fixture { root, bins, resources, cache }
    }

    fn sidecars(f: &Fixture) -> SidecarSource {
        SidecarSource { dev_dir: Some(f.bins.clone()), exe_dir: Some(f.root.join("no-exe-dir")), kit_dirs: Vec::new(), allow_path_lookup: true }
    }

    /// The descriptor a release compiles in; `accepted` says which binary builds it restores.
    fn descriptor(f: &Fixture, accepted: bool) -> KitDescriptor {
        let file = |name: &'static str| KitFile { name, sha256: leak(sha(&std::fs::read(f.resources.join(name)).unwrap())) };
        let accept = |bytes: &[u8]| -> &'static [(&'static str, &'static str)] {
            if accepted {
                Box::leak(vec![("some-other-triple", leak("00".repeat(32))), (TARGET_TRIPLE, leak(sha(bytes)))].into_boxed_slice())
            } else {
                &[]
            }
        };
        KitDescriptor {
            line: Line::V06,
            conductor: KitBinary { sidecar: "test-holochain", version: "0.6.1", accepted: accept(CONDUCTOR_BYTES) },
            lair: KitBinary { sidecar: "test-lair", version: "0.6.3", accepted: accept(LAIR_BYTES) },
            files: Box::leak(vec![file("app.happ"), file("coordinator.wasm")].into_boxed_slice()),
        }
    }

    #[test]
    fn a_kit_is_cached_once_and_restores_to_fresh_verified_files_that_run() {
        let f = fixture("roundtrip");
        let d = descriptor(&f, true);
        let first = f.cache.put(&d, &sidecars(&f), &f.resources).unwrap();
        assert_eq!(first.written, ["test-holochain", "test-lair", "app.happ", "coordinator.wasm"]);
        assert!(first.packed < 300_000, "compressed: {} bytes", first.packed);
        let manifest = f.cache.manifest(Line::V06).unwrap();
        assert_eq!((manifest.target.as_str(), manifest.entries.len()), (TARGET_TRIPLE, 4));
        assert_eq!(manifest.entries[0].sha256, sha(CONDUCTOR_BYTES));

        let again = f.cache.put(&d, &sidecars(&f), &f.resources).unwrap();
        assert_eq!((again.written.len(), again.kept), (0, 4), "nothing changed, nothing written");

        let restored = f.cache.restore(&d).unwrap();
        assert_eq!(restored.dir, f.cache.line_dir(Line::V06).join("run"));
        assert_eq!(std::fs::read(&restored.conductor).unwrap(), CONDUCTOR_BYTES);
        assert_eq!(std::fs::read(&restored.lair).unwrap(), LAIR_BYTES);
        assert_eq!(std::fs::read(restored.dir.join("app.happ")).unwrap(), vec![7u8; 300_000]);
        let found = resolve_sidecar("test-holochain", &SidecarSource { kit_dirs: vec![restored.dir.clone()], exe_dir: Some(f.root.join("no-exe-dir")), ..Default::default() }).unwrap();
        assert_eq!(found, restored.conductor, "the resolver finds the restored copy by its name");
        #[cfg(unix)]
        {
            let out = std::process::Command::new(&restored.conductor).output().unwrap();
            assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "conductor-from-the-kit");
        }

        // A changed binary (the next release's build) is written again, alone.
        std::fs::write(f.bins.join(format!("test-lair-{TARGET_TRIPLE}{}", exe_suffix())), b"#!/bin/sh\necho newer\n").unwrap();
        let changed = f.cache.put(&d, &sidecars(&f), &f.resources).unwrap();
        assert_eq!((changed.written.as_slice(), changed.kept), (&["test-lair".to_string()][..], 3));
    }

    #[test]
    fn a_restore_refuses_what_the_release_does_not_accept_and_drops_a_bad_copy() {
        let f = fixture("refuse");
        let d = descriptor(&f, true);
        assert!(matches!(f.cache.restore(&d), Err(Error::Kit(KitError::NotCached { .. }))), "nothing cached yet");
        f.cache.put(&d, &sidecars(&f), &f.resources).unwrap();

        // A release that bundles the binary accepts no build of it.
        assert!(matches!(f.cache.restore(&descriptor(&f, false)), Err(Error::Kit(KitError::NotAccepted { .. }))));

        // A cached copy replaced by other (well-formed) bytes: refused,
        // deleted, and the next put writes it again.
        let packed = f.cache.line_dir(Line::V06).join("test-lair.zst");
        std::fs::write(&packed, zstd::encode_all(&b"#!/bin/sh\necho not ours\n"[..], 3).unwrap()).unwrap();
        assert!(matches!(f.cache.restore(&d), Err(Error::Kit(KitError::HashMismatch { ref name, .. })) if name == "test-lair"));
        assert!(!packed.exists(), "the bad copy is gone");
        assert!(!f.cache.line_dir(Line::V06).join("run").join(format!("test-lair{}.part", exe_suffix())).exists());
        assert_eq!(f.cache.put(&d, &sidecars(&f), &f.resources).unwrap().written, ["test-lair"]);

        // A cached copy that does not decompress: unreadable, deleted.
        std::fs::write(&packed, b"not zstd").unwrap();
        assert!(matches!(f.cache.restore(&d), Err(Error::Kit(KitError::Unreadable { .. }))));
        assert!(!packed.exists());
    }

    #[test]
    fn a_bundled_file_that_is_not_the_descriptors_is_not_cached() {
        let f = fixture("source");
        let d = descriptor(&f, true);
        std::fs::write(f.resources.join("app.happ"), b"another bundle").unwrap();
        assert!(matches!(f.cache.put(&d, &sidecars(&f), &f.resources), Err(Error::Kit(KitError::SourceChanged { ref name, .. })) if name == "app.happ"));
        assert!(f.cache.manifest(Line::V06).is_none());
        // Never from the PATH: a missing bundled binary says where it looked.
        let missing = SidecarSource { dev_dir: Some(f.root.join("empty")), ..sidecars(&f) };
        assert!(matches!(f.cache.put(&descriptor(&f, true), &missing, &f.resources), Err(Error::SidecarMissing { .. })));
    }

    #[test]
    fn a_put_drops_what_an_earlier_descriptor_named_and_prune_drops_lines_not_kept() {
        let f = fixture("prune");
        let d = descriptor(&f, true);
        f.cache.put(&d, &sidecars(&f), &f.resources).unwrap();
        let line_dir = f.cache.line_dir(Line::V06);
        std::fs::write(line_dir.join("old_bundle.happ.zst"), b"x").unwrap();
        std::fs::write(line_dir.join("test-holochain.zst.part"), b"x").unwrap();
        f.cache.put(&d, &sidecars(&f), &f.resources).unwrap();
        assert!(!line_dir.join("old_bundle.happ.zst").exists() && !line_dir.join("test-holochain.zst.part").exists());

        let other = KitDescriptor { line: Line::V07, ..d };
        f.cache.put(&other, &sidecars(&f), &f.resources).unwrap();
        assert_eq!(f.cache.prune(&[Line::V06, Line::V07]).unwrap(), 0);
        let freed = f.cache.prune(&[Line::V07]).unwrap();
        assert!(freed > 0 && !line_dir.exists(), "freed {freed}");
        assert!(f.cache.manifest(Line::V07).is_some(), "the kept line stays");
    }

    #[test]
    fn the_previous_line_stays_needed_until_every_root_is_done_with_it() {
        const SPEC: MarkerSpec = MarkerSpec { file_name: "moved", old_line_key: "old_needed", previous: Line::V06, current: Line::V07 };
        let base = std::env::temp_dir().join(format!("hcl-kit-needed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = |name: &str, marker: Option<&str>| {
            let r = base.join(name);
            std::fs::create_dir_all(&r).unwrap();
            if let Some(m) = marker {
                std::fs::write(r.join("moved"), m).unwrap();
            }
            r
        };
        let unmoved_with_data = root("unmoved", None);
        let empty = root("empty", None);
        let born = root("born", Some(r#"{"v":1,"moved_at_ms":1,"born":true}"#));
        let done = root("done", Some(r#"{"v":1,"moved_at_ms":1,"old_needed":false,"carried_all_ms":5}"#));
        let not_carried = root("not-carried", Some(r#"{"v":1,"moved_at_ms":1,"old_needed":false}"#));
        let still = root("still", Some(r#"{"v":1,"moved_at_ms":1,"old_needed":true}"#));
        let undecided = root("undecided", Some(r#"{"v":1,"moved_at_ms":1}"#));
        let unreadable = root("unreadable", Some("not json"));
        let holds = |r: &Path| r.ends_with("unmoved");
        let needed = |roots: &[&PathBuf]| previous_line_needed(&roots.iter().map(|r| (*r).clone()).collect::<Vec<_>>(), &SPEC, holds);

        assert!(!needed(&[&empty, &born, &done]), "nothing left on the previous line");
        assert!(needed(&[&done, &unmoved_with_data]), "an identity that has not moved");
        assert!(needed(&[&done, &still]), "a marker that still needs it");
        assert!(needed(&[&undecided]), "no decision recorded yet");
        assert!(needed(&[&not_carried]), "decided by the earlier rule, nothing recorded as carried");
        assert!(needed(&[&unreadable]), "a marker that does not read");
        assert!(!needed(&[]));
        let _ = std::fs::remove_dir_all(&base);
    }
}
