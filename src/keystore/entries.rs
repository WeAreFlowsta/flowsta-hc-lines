//! A stopped key store's entries, read and rebuilt through lair's own store
//! code (the `lair_keystore` crate's SQLCipher store), never over a lair
//! connection.
//!
//! Holochain 0.7.1 checks an existing agent key at app install by listing
//! every key its lair holds (`Conductor::install_app_bundle` calls
//! `MetaLairClient::list_public_keys`, which calls lair's `list_entries`),
//! and a lair reply must fit one message of at most 8 KiB. Past about fifty
//! keys the listing cannot be sent, the connection is aborted, and every
//! install with an existing key fails with `ConnectionAborted`. Holochain
//! 0.6.1 makes no such check, so a store that grew on the 0.6 line works
//! there and fails on 0.7. A line's store therefore holds only the keys that
//! line uses:
//! - [`entries`] lists a stopped store, and says how large lair's reply to
//!   a listing would be;
//! - [`keep_only`] rebuilds a stopped store with the entries a caller keeps.
//!
//! A rebuild writes a new store file beside the old one, under the same
//! context key and database salt (lair's own code encrypts every entry
//! again), reads it back, and only then swaps the files. A swap cut short is
//! finished by the next call ([`finish_interrupted`]), before lair could
//! start on a missing store and make an empty one.

use super::KeyStoreError;
use crate::{Error, Line, Result};
use std::path::{Path, PathBuf};

/// The largest reply lair can send: one secretstream message of at most
/// 8 KiB (lair 0.6.3 and 0.7.1 `sodium_secretstream::MAX_FRAME`), less the
/// stream's own 17 bytes per message (`secretstream::ABYTES`).
pub const LAIR_REPLY_MAX: usize = 8 * 1024 - 17;

/// What an entry is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    /// A signing seed: an agent key.
    Seed,
    /// A seed locked under a second passphrase.
    DeepLockedSeed,
    /// A TLS certificate.
    TlsCert,
    /// A kind this crate does not name.
    Other,
}

/// One entry of a key store: its tag, its kind and, for a seed, its Ed25519
/// public key (an agent key's 32 core bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub tag: String,
    pub kind: EntryKind,
    pub ed25519: Option<[u8; 32]>,
}

/// A store's entries and the size of lair's reply to a listing of them.
#[derive(Clone, Debug)]
pub struct Listing {
    pub entries: Vec<Entry>,
    /// Bytes of the listing reply as lair encodes it.
    pub reply_bytes: usize,
}

impl Listing {
    /// Whether lair can send this listing (and so whether Holochain 0.7.1
    /// can install an app for a key in this store).
    pub fn fits(&self) -> bool {
        self.reply_bytes <= LAIR_REPLY_MAX
    }
}

/// What [`keep_only`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kept {
    /// Every entry was kept: the store is as it was.
    AllKept { entries: usize, reply_bytes: usize },
    /// The store was rebuilt with `kept` of its entries.
    Rebuilt { kept: usize, dropped: usize, reply_bytes: usize },
}

/// The new store file while it is written, beside `store_file`.
pub const KEEP_FILE: &str = "store_file.keep";
/// The old store file during the swap.
pub const OLD_FILE: &str = "store_file.old";
const SIDES: [&str; 3] = ["", "-wal", "-shm"];

fn file(dir: &Path, base: &str, side: &str) -> PathBuf {
    dir.join(format!("{base}{side}"))
}

fn io_err<'a>(what: &'static str, path: &'a Path) -> impl FnOnce(std::io::Error) -> Error + 'a {
    move |source| Error::Io { what, path: path.to_path_buf(), source }
}

/// Finish or undo a [`keep_only`] that stopped part way, so the store in
/// `store_dir` is whole: the rebuilt one if its swap had begun, else the
/// old one. A store with no rebuild under way is left as it is.
pub fn finish_interrupted(store_dir: &Path) -> Result<()> {
    let current = file(store_dir, "store_file", "");
    let keep = file(store_dir, KEEP_FILE, "");
    let old = file(store_dir, OLD_FILE, "");
    if !current.exists() {
        if keep.exists() {
            // The old store had been moved aside: the rebuilt one, already
            // read back, takes its place. A side file still under the
            // current name belongs to the old store and goes with it first.
            for side in &SIDES[1..] {
                let p = file(store_dir, "store_file", side);
                if p.exists() {
                    std::fs::rename(&p, file(store_dir, OLD_FILE, side)).map_err(io_err("move the old store aside", &p))?;
                }
            }
            for side in SIDES {
                let p = file(store_dir, KEEP_FILE, side);
                if p.exists() {
                    std::fs::rename(&p, file(store_dir, "store_file", side)).map_err(io_err("put the rebuilt store in place", &p))?;
                }
            }
            log::info!("[key store] finished a rebuild that stopped part way");
        } else if old.exists() {
            for side in SIDES {
                let p = file(store_dir, OLD_FILE, side);
                if p.exists() {
                    std::fs::rename(&p, file(store_dir, "store_file", side)).map_err(io_err("restore the old store", &p))?;
                }
            }
            log::warn!("[key store] a rebuild stopped before its new store was written; the old store is back");
        }
    }
    // A whole store is in place: what a rebuild left beside it goes.
    for base in [KEEP_FILE, OLD_FILE] {
        for side in SIDES {
            let p = file(store_dir, base, side);
            if p.exists() {
                std::fs::remove_file(&p).map_err(io_err("remove a rebuild's leftover", &p))?;
            }
        }
    }
    Ok(())
}

/// The entries of the stopped store in `store_dir`, written by `line`'s
/// lair, opened with `passphrase`.
pub async fn entries(store_dir: &Path, line: Line, passphrase: &str) -> Result<Listing> {
    if super::copy::source_running(store_dir) {
        return Err(KeyStoreError::SourceRunning(store_dir.to_path_buf()).into());
    }
    finish_interrupted(store_dir)?;
    match line {
        #[cfg(feature = "line-06")]
        Line::V06 => e06::entries(store_dir, passphrase).await,
        #[cfg(feature = "line-07")]
        Line::V07 => e07::entries(store_dir, passphrase).await,
        #[allow(unreachable_patterns)]
        other => Err(Error::LineNotCompiled(other)),
    }
}

/// Rebuild the stopped store in `store_dir` with only the entries `keep`
/// accepts. A store whose entries are all kept is left as it is. The store
/// must not be running.
pub async fn keep_only(store_dir: &Path, line: Line, passphrase: &str, keep: &(dyn Fn(&Entry) -> bool + Sync)) -> Result<Kept> {
    if super::copy::source_running(store_dir) {
        return Err(KeyStoreError::SourceRunning(store_dir.to_path_buf()).into());
    }
    finish_interrupted(store_dir)?;
    match line {
        #[cfg(feature = "line-06")]
        Line::V06 => e06::keep_only(store_dir, passphrase, keep).await,
        #[cfg(feature = "line-07")]
        Line::V07 => e07::keep_only(store_dir, passphrase, keep).await,
        #[allow(unreachable_patterns)]
        other => Err(Error::LineNotCompiled(other)),
    }
}

/// Move the old store aside and put the rebuilt one in its place; each step
/// can be finished by [`finish_interrupted`].
fn swap(store_dir: &Path) -> Result<()> {
    for side in SIDES {
        let p = file(store_dir, "store_file", side);
        if p.exists() {
            std::fs::rename(&p, file(store_dir, OLD_FILE, side)).map_err(io_err("move the old store aside", &p))?;
        }
    }
    finish_interrupted(store_dir)
}

macro_rules! entries_with {
    ($v:ident, $r:ident, $api:ident, $store:ident) => {
        mod $v {
            use super::{file, swap, Entry, EntryKind, Kept, Listing, KEEP_FILE};
            use crate::keystore::rewrap::$r;
            use crate::keystore::KeyStoreError;
            use crate::{Error, Result};
            use std::path::Path;
            use $api::lair_store::traits::AsLairStore;
            use $api::prelude::{LairApiEnum, LairApiResListEntries, LairEntryInfo, LairServerConfigInner, LairStore};

            fn lair_err(e: impl std::fmt::Display) -> Error {
                KeyStoreError::Lair(e.to_string()).into()
            }

            fn entry(info: &LairEntryInfo) -> Entry {
                match info {
                    LairEntryInfo::Seed { tag, seed_info } => {
                        Entry { tag: tag.to_string(), kind: EntryKind::Seed, ed25519: Some(*seed_info.ed25519_pub_key.0) }
                    }
                    LairEntryInfo::DeepLockedSeed { tag, seed_info } => {
                        Entry { tag: tag.to_string(), kind: EntryKind::DeepLockedSeed, ed25519: Some(*seed_info.ed25519_pub_key.0) }
                    }
                    LairEntryInfo::WkaTlsCert { tag, .. } => Entry { tag: tag.to_string(), kind: EntryKind::TlsCert, ed25519: None },
                    #[allow(unreachable_patterns)]
                    _ => Entry { tag: String::new(), kind: EntryKind::Other, ed25519: None },
                }
            }

            /// Lair's listing reply as it encodes it (msgpack, struct maps,
            /// a 21-character message id).
            fn reply_bytes(infos: Vec<LairEntryInfo>) -> Result<usize> {
                let reply = LairApiEnum::ResListEntries(LairApiResListEntries { msg_id: "x".repeat(21).into(), entry_list: infos });
                let mut se = rmp_serde::encode::Serializer::new(Vec::new()).with_struct_map();
                serde::Serialize::serialize(&reply, &mut se).map_err(lair_err)?;
                Ok(se.into_inner().len())
            }

            async fn open_store(path: &Path, config: &LairServerConfigInner, passphrase: &str) -> Result<LairStore> {
                let Some((context_key, _id_seed)) = $r::open(config, passphrase).await.map_err(lair_err)? else {
                    return Err(KeyStoreError::StoreWrongPassphrase(path.to_path_buf()).into());
                };
                $store::store_sqlite::create_sql_pool_factory(path, &config.database_salt)
                    .connect_to_store(context_key)
                    .await
                    .map_err(lair_err)
            }

            async fn listing(store: &LairStore) -> Result<(Vec<LairEntryInfo>, Listing)> {
                let infos = store.list_entries().await.map_err(lair_err)?;
                let entries = infos.iter().map(entry).collect();
                let reply_bytes = reply_bytes(infos.clone())?;
                Ok((infos, Listing { entries, reply_bytes }))
            }

            pub(super) async fn entries(store_dir: &Path, passphrase: &str) -> Result<Listing> {
                let config = $r::read(store_dir)?;
                let store = open_store(&file(store_dir, "store_file", ""), &config, passphrase).await?;
                Ok(listing(&store).await?.1)
            }

            pub(super) async fn keep_only(store_dir: &Path, passphrase: &str, keep: &(dyn Fn(&Entry) -> bool + Sync)) -> Result<Kept> {
                let config = $r::read(store_dir)?;
                let old = open_store(&file(store_dir, "store_file", ""), &config, passphrase).await?;
                let (infos, before) = listing(&old).await?;
                let kept_tags: Vec<String> = before.entries.iter().filter(|e| keep(e)).map(|e| e.tag.clone()).collect();
                if kept_tags.len() == before.entries.len() {
                    return Ok(Kept::AllKept { entries: before.entries.len(), reply_bytes: before.reply_bytes });
                }
                let new_path = file(store_dir, KEEP_FILE, "");
                {
                    let new = open_store(&new_path, &config, passphrase).await?;
                    for tag in &kept_tags {
                        let e = old.get_entry_by_tag(tag.as_str().into()).await.map_err(lair_err)?;
                        AsLairStore::write_entry(&*new.0, e).await.map_err(lair_err)?;
                    }
                }
                drop(old);
                // Read the rebuilt store back before anything is swapped: the
                // same entries, each with the same key.
                let wanted: Vec<LairEntryInfo> = infos.into_iter().filter(|i| kept_tags.contains(&entry(i).tag)).collect();
                let (_, after) = {
                    let check = open_store(&new_path, &config, passphrase).await?;
                    listing(&check).await?
                };
                let mut got = after.entries.clone();
                let mut want: Vec<Entry> = wanted.iter().map(entry).collect();
                got.sort_by(|a, b| a.tag.cmp(&b.tag));
                want.sort_by(|a, b| a.tag.cmp(&b.tag));
                if got != want {
                    return Err(KeyStoreError::Lair(format!("the rebuilt store holds {} entries, {} were kept", got.len(), want.len())).into());
                }
                swap(store_dir)?;
                let dropped = before.entries.len() - kept_tags.len();
                log::info!("[key store] rebuilt with {} of {} entries ({} left out); a listing is {} bytes", kept_tags.len(), before.entries.len(), dropped, after.reply_bytes);
                Ok(Kept::Rebuilt { kept: kept_tags.len(), dropped, reply_bytes: after.reply_bytes })
            }
        }
    };
}

#[cfg(feature = "line-06")]
entries_with!(e06, r06, lair_keystore_api_06, lair_keystore_06);
#[cfg(feature = "line-07")]
entries_with!(e07, r07, lair_keystore_api_07, lair_keystore_07);

#[cfg(all(test, feature = "line-07"))]
mod tests_07 {
    use super::*;
    use crate::keystore::rewrap::r07;
    use lair_keystore_api_07::dependencies::sodoken;
    use std::sync::{Arc, Mutex};

    fn pass(p: &str) -> lair_keystore_api_07::prelude::SharedLockedArray {
        Arc::new(Mutex::new(sodoken::LockedArray::from(p.as_bytes().to_vec())))
    }

    /// A store of `n` seeds written by lair's own store code, as lair's
    /// server writes them: (tag, Ed25519 key) each.
    async fn store_with_seeds(dir: &Path, passphrase: &str, n: usize) -> Vec<(String, [u8; 32])> {
        std::fs::create_dir_all(dir).unwrap();
        r07::test_store::init(dir, passphrase).await;
        let config = r07::read(dir).unwrap();
        let (ctx, _) = r07::open(&config, passphrase).await.unwrap().unwrap();
        let store = lair_keystore_07::store_sqlite::create_sql_pool_factory(dir.join("store_file"), &config.database_salt)
            .connect_to_store(ctx)
            .await
            .unwrap();
        let mut out = Vec::new();
        for i in 0..n {
            // Tags as long as an app's ("ai-<uuid>").
            let tag = format!("ai-{i:04}-6f1e3c2a-9b7d-4e21-a8f0-5c3d2b1a0e9f");
            let info = store.new_seed(tag.as_str().into(), false).await.unwrap();
            out.push((tag, *info.ed25519_pub_key.0));
        }
        out
    }

    /// Whether lair's own server code, on this store, signs with `key`.
    async fn lair_signs(dir: &Path, passphrase: &str, key: [u8; 32]) -> bool {
        let config = Arc::new(r07::read(dir).unwrap());
        let factory = lair_keystore_07::store_sqlite::create_sql_pool_factory(dir.join("store_file"), &config.database_salt);
        let ks = lair_keystore_api_07::in_proc_keystore::InProcKeystore::new(config, factory, pass(passphrase)).await.unwrap();
        let client = ks.new_client().await.unwrap();
        client.sign_by_pub_key(key.into(), None, Arc::from(&b"keep"[..])).await.is_ok()
    }

    fn leftovers(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with(KEEP_FILE) || n.starts_with(OLD_FILE))
            .collect()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_store_past_one_message_keeps_the_chosen_keys_and_lair_signs_with_them() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("lair");
        let seeds = store_with_seeds(&dir, "pw", 120).await;
        let before = entries(&dir, Line::V07, "pw").await.unwrap();
        assert_eq!(before.entries.len(), 120);
        assert!(!before.fits(), "120 keys list in {} bytes, more than one lair message", before.reply_bytes);
        let keep: Vec<[u8; 32]> = seeds[..5].iter().map(|(_, k)| *k).collect();
        let kept = keep_only(&dir, Line::V07, "pw", &|e| e.ed25519.is_some_and(|k| keep.contains(&k))).await.unwrap();
        let Kept::Rebuilt { kept, dropped, reply_bytes } = kept else { panic!("rebuilt: {kept:?}") };
        assert_eq!((kept, dropped), (5, 115));
        assert!(reply_bytes <= LAIR_REPLY_MAX);
        let after = entries(&dir, Line::V07, "pw").await.unwrap();
        let mut got: Vec<(String, [u8; 32])> = after.entries.iter().map(|e| (e.tag.clone(), e.ed25519.unwrap())).collect();
        got.sort();
        let mut want = seeds[..5].to_vec();
        want.sort();
        assert_eq!(got, want, "the same tags with the same keys");
        assert!(after.fits());
        assert!(lair_signs(&dir, "pw", seeds[0].1).await, "lair signs with a kept key");
        assert!(!lair_signs(&dir, "pw", seeds[100].1).await, "a key left out is gone");
        assert!(leftovers(&dir).is_empty(), "nothing left beside the store: {:?}", leftovers(&dir));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_store_whose_entries_are_all_kept_is_left_as_it_is() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("lair");
        store_with_seeds(&dir, "pw", 10).await;
        let before = std::fs::metadata(dir.join("store_file")).unwrap().modified().unwrap();
        let kept = keep_only(&dir, Line::V07, "pw", &|_| true).await.unwrap();
        assert!(matches!(kept, Kept::AllKept { entries: 10, .. }), "{kept:?}");
        assert_eq!(std::fs::metadata(dir.join("store_file")).unwrap().modified().unwrap(), before);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_wrong_passphrase_reads_nothing_and_changes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("lair");
        store_with_seeds(&dir, "pw", 3).await;
        assert!(entries(&dir, Line::V07, "not-it").await.is_err());
        assert!(keep_only(&dir, Line::V07, "not-it", &|_| false).await.is_err());
        assert_eq!(entries(&dir, Line::V07, "pw").await.unwrap().entries.len(), 3);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_swap_cut_short_is_finished_and_a_rebuild_never_swapped_is_dropped() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("lair");
        let seeds = store_with_seeds(&dir, "pw", 4).await;
        // Cut after the old store was moved aside: the rebuilt one (here a
        // copy of the same store) takes its place.
        for side in SIDES {
            let p = file(&dir, "store_file", side);
            if p.exists() {
                std::fs::copy(&p, file(&dir, KEEP_FILE, side)).unwrap();
            }
        }
        for side in SIDES {
            let p = file(&dir, "store_file", side);
            if p.exists() {
                std::fs::rename(&p, file(&dir, OLD_FILE, side)).unwrap();
            }
        }
        finish_interrupted(&dir).unwrap();
        assert!(dir.join("store_file").exists());
        assert!(leftovers(&dir).is_empty(), "{:?}", leftovers(&dir));
        assert!(lair_signs(&dir, "pw", seeds[3].1).await);
        // A rebuild cut before its swap: the old store stands, the rebuild goes.
        std::fs::write(dir.join(KEEP_FILE), b"half written").unwrap();
        finish_interrupted(&dir).unwrap();
        assert!(leftovers(&dir).is_empty());
        assert_eq!(entries(&dir, Line::V07, "pw").await.unwrap().entries.len(), 4);
    }
    /// The failure and its fix with the real binaries: a store of 120 keys
    /// written by the 0.6 key store, copied and rewrapped for 0.7, cannot
    /// install an app for one of its keys on a 0.7.1 conductor (Holochain
    /// lists every key, and the reply exceeds one lair message); kept to the
    /// keys in use, the same install succeeds.
    ///
    /// `HC_LINES_LAIR_06= HC_LINES_LAIR_07= HC_LINES_CONDUCTOR_07= HC_LINES_HAPP_07=<a 0.7 .happ>
    /// cargo test --lib -- --ignored live_a_large_copied_store --nocapture`
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn live_a_large_copied_store_installs_on_07_once_kept_to_the_keys_in_use() {
        use crate::conductor::{self as cond, NetworkTuning};
        use crate::keystore::{copy_store, rekey_store, start, v06, wait_ready, SocketPlan};
        use crate::process::{stop_gracefully, StopRequest};
        use crate::rendezvous::Rendezvous;
        use crate::supervisor::{start_line, KeySource, LineStart, Timeouts};
        use crate::{AdminClient, InstallRequest};
        use std::time::Duration;
        let var = |v: &str| PathBuf::from(std::env::var(v).unwrap_or_else(|_| panic!("set {v}")));
        let (lair_06, lair_07, cond_07, happ) = (var("HC_LINES_LAIR_06"), var("HC_LINES_LAIR_07"), var("HC_LINES_CONDUCTOR_07"), var("HC_LINES_HAPP_07"));
        let tmp = tempfile::tempdir().unwrap();
        let (dir_06, dir_07, cond_dir) = (tmp.path().join("lair"), tmp.path().join("lair-07"), tmp.path().join("conductor-07"));

        // 120 keys made by the 0.6 key store, as an app makes one per AI.
        let plan = SocketPlan::new("hcl-live-keep", "lair");
        let (mut child, url) = start(&dir_06, &lair_06, "the-constant", &plan).unwrap();
        wait_ready(&url, Duration::from_secs(15), &mut child, &dir_06).await.unwrap();
        let client = v06::connect(&url, "the-constant", Duration::from_secs(30)).await.unwrap();
        let mut seeds = Vec::new();
        for i in 0..120 {
            let tag = format!("ai-{i:04}-6f1e3c2a-9b7d-4e21-a8f0-5c3d2b1a0e9f");
            seeds.push((tag.clone(), v06::new_seed(&client, &tag).await.unwrap()));
        }
        drop(client);
        let _ = stop_gracefully(&mut child, StopRequest::Terminate, Duration::from_secs(2));

        copy_store(&dir_06, &dir_07, &plan).unwrap();
        rekey_store(&dir_07, Line::V07, "the-constant", "per-install").await.unwrap();
        let listing = entries(&dir_07, Line::V07, "per-install").await.unwrap();
        assert_eq!(listing.entries.len(), 120);
        assert!(!listing.fits(), "120 keys: {} bytes", listing.reply_bytes);

        let origin = cond::fresh_origin("hcl");
        let rendezvous = Rendezvous::new("https://127.0.0.1:9");
        let tuning = NetworkTuning::for_line(Line::V07);
        let agents = [KeySource::Existing { tag: seeds[0].0.clone() }];
        let raw39 = holochain_types_07::prelude::AgentPubKey::from_raw_32(seeds[0].1.to_vec()).get_raw_39().to_vec();
        struct Ctx<'a> {
            lair_07: &'a Path,
            cond_07: &'a Path,
            dir_07: &'a Path,
            cond_dir: &'a Path,
            plan: &'a SocketPlan,
            origin: &'a str,
            rendezvous: &'a Rendezvous,
            tuning: &'a NetworkTuning,
            agents: &'a [KeySource],
            happ: &'a Path,
            raw39: &'a [u8],
        }
        async fn install(c: &Ctx<'_>, n: u32) -> std::result::Result<(), String> {
            let mut p = start_line(
                &LineStart {
                    line: Line::V07,
                    lair_bin: c.lair_07,
                    conductor_bin: c.cond_07,
                    lair_dir: c.dir_07,
                    conductor_dir: c.cond_dir,
                    passphrase: "per-install",
                    sockets: c.plan,
                    admin_ports: &[47820, 47821],
                    origin: c.origin,
                    rendezvous: c.rendezvous,
                    tuning: c.tuning,
                    agents: c.agents,
                    timeouts: Timeouts::default(),
                },
                |_| {},
            )
            .await
            .map_err(|e| format!("start: {e}"))?;
            let admin = AdminClient::connect(Line::V07, p.admin_port, c.origin).await.map_err(|e| e.to_string())?;
            let app_id = format!("hcl-live-keep-{n}");
            let r = admin
                .install(&InstallRequest { app_id: &app_id, bundle: c.happ, agent_key: c.raw39, network_seed: Some("hcl-live-keep") })
                .await
                .map_err(|e| e.to_string());
            drop(admin);
            let _ = p.stop();
            r
        }
        let c = Ctx {
            lair_07: &lair_07,
            cond_07: &cond_07,
            dir_07: &dir_07,
            cond_dir: &cond_dir,
            plan: &plan,
            origin: &origin,
            rendezvous: &rendezvous,
            tuning: &tuning,
            agents: &agents,
            happ: &happ,
            raw39: &raw39,
        };
        let before = install(&c, 1).await;
        println!("KEEP install with 120 keys: {before:?}");
        assert!(before.is_err(), "the install lists every key and must fail: {before:?}");

        let after_start = entries(&dir_07, Line::V07, "per-install").await.unwrap();
        for e in after_start.entries.iter().filter(|e| !seeds.iter().any(|(t, _)| t == &e.tag)) {
            println!("KEEP the conductor added: {:?} tag {:?}", e.kind, e.tag);
        }
        let keep: Vec<[u8; 32]> = seeds[..3].iter().map(|(_, k)| *k).collect();
        let kept = keep_only(&dir_07, Line::V07, "per-install", &|e| e.ed25519.is_some_and(|k| keep.contains(&k))).await.unwrap();
        println!("KEEP {kept:?}");
        let after = install(&c, 2).await;
        println!("KEEP install with the 3 keys in use: {after:?}");
        assert!(after.is_ok(), "{after:?}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real store's make-up, read from a copy (run by hand):
    /// `HC_LINES_LIST_STORE=<dir with store_file and its config>
    /// HC_LINES_LIST_PASSPHRASE=… [HC_LINES_LIST_KEYS=<agent keys, hex, comma>]
    /// cargo test --lib -- --ignored live_a_stores_make_up --nocapture`.
    /// Prints counts, tag shapes and the listing's size, never a secret.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn live_a_stores_make_up() {
        let src = PathBuf::from(std::env::var("HC_LINES_LIST_STORE").expect("HC_LINES_LIST_STORE"));
        let pass = std::env::var("HC_LINES_LIST_PASSPHRASE").expect("HC_LINES_LIST_PASSPHRASE");
        let keys: Vec<[u8; 32]> = std::env::var("HC_LINES_LIST_KEYS")
            .unwrap_or_default()
            .split(',')
            .filter(|h| h.len() == 78)
            .map(|h| {
                let raw = hex::decode(h).unwrap();
                raw[3..35].try_into().unwrap()
            })
            .collect();
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("lair");
        std::fs::create_dir_all(&dir).unwrap();
        for f in ["store_file", "store_file-wal", "store_file-shm", super::super::CONFIG_FILE] {
            if src.join(f).exists() {
                std::fs::copy(src.join(f), dir.join(f)).unwrap();
            }
        }
        let plan = super::super::SocketPlan::new("hcl-makeup", "lair");
        super::super::repoint_config(&dir, &plan).unwrap();
        let l = entries(&dir, Line::V07, &pass).await.unwrap();
        let mut kinds = std::collections::BTreeMap::new();
        let mut shapes = std::collections::BTreeMap::new();
        for e in &l.entries {
            *kinds.entry(format!("{:?}", e.kind)).or_insert(0usize) += 1;
            let shape: String = e.tag.chars().map(|c| if c.is_ascii_alphanumeric() { if c.is_ascii_digit() { '9' } else { 'a' } } else { c }).collect();
            let shape = shape.split(|c: char| c == '9').filter(|s| !s.is_empty()).collect::<Vec<_>>().join("#");
            *shapes.entry(shape.chars().take(40).collect::<String>()).or_insert(0usize) += 1;
        }
        let live = l.entries.iter().filter(|e| e.ed25519.is_some_and(|k| keys.contains(&k))).count();
        println!("MAKEUP {} entries; kinds {kinds:?}; listing {} bytes (fits: {}); seeds of the {} named keys: {live}", l.entries.len(), l.reply_bytes, l.fits(), keys.len());
        for (s, n) in &shapes {
            println!("MAKEUP tag shape {n:>4} x {s}");
        }
        let kept = keep_only(&dir, Line::V07, &pass, &|e| e.kind != EntryKind::Seed || e.tag.starts_with('_') || e.ed25519.is_some_and(|k| keys.contains(&k))).await.unwrap();
        println!("MAKEUP keep the named keys, every non-seed and every '_' tag: {kept:?}");
        let after = entries(&dir, Line::V07, &pass).await.unwrap();
        println!("MAKEUP after: {} entries, listing {} bytes (fits: {})", after.entries.len(), after.reply_bytes, after.fits());
    }
}
