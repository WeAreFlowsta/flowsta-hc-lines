//! A key store's passphrase changed in place.
//!
//! Lair has no call to change its passphrase, and a store holding seeds that
//! cannot be exported cannot be rebuilt. But the passphrase only wraps two
//! secrets in the store's config (`lair-keystore-config.yaml`):
//! - the context key, which encrypts the store file;
//! - the server's id seed, whose public key is the connection URL's `k=`.
//!
//! Each is sealed under a key derived from argon2id(blake2b(passphrase),
//! `runtimeSecretsSalt`) at the limits the config records. A rewrap opens
//! both with the current passphrase and seals them again under the new one,
//! with a fresh salt. The store file, its database salt and the connection
//! URL are left as they are, so every key the store holds opens as before.
//!
//! The crypto is lair's own: its config type, its sealed-secret type, and
//! the derivation its server runs at every start.

use super::{config_path, KeyStoreError, Rekeyed};
use crate::{Error, Line, Result};
use std::path::Path;

/// Rewrap the key store in `store_dir`, written by `line`'s lair, from
/// passphrase `current` to `new`. The store must not be running. A store
/// that already opens with `new` is left as it is ([`Rekeyed::AlreadyNew`]),
/// so a rewrap interrupted after its write is finished by the next call. The
/// config is replaced atomically and readable by this OS account only.
pub async fn rekey_store(store_dir: &Path, line: Line, current: &str, new: &str) -> Result<Rekeyed> {
    if super::copy::source_running(store_dir) {
        return Err(KeyStoreError::SourceRunning(store_dir.to_path_buf()).into());
    }
    match line {
        #[cfg(feature = "line-06")]
        Line::V06 => r06::rekey(store_dir, current, new).await,
        #[cfg(feature = "line-07")]
        Line::V07 => r07::rekey(store_dir, current, new).await,
        #[allow(unreachable_patterns)]
        other => Err(Error::LineNotCompiled(other)),
    }
}

macro_rules! rewrap_with {
    ($v:ident, $lair:ident) => {
        mod $v {
            use super::{config_path, Error, KeyStoreError, Rekeyed, Result};
            use std::io;
            use std::path::Path;
            use std::sync::{Arc, Mutex};
            use $lair::config::LairServerConfigInner;
            use $lair::dependencies::sodoken;
            use $lair::encoding_types::SecretDataSized;

            type Key = sodoken::SizedLockedArray<32>;

            fn other(e: impl std::fmt::Display) -> io::Error {
                io::Error::other(e.to_string())
            }

            /// The two sealing keys lair derives from a passphrase and the
            /// config's salt and limits (its server's start, `priv_srv.rs`).
            async fn sealing_keys(passphrase: &str, salt: [u8; 16], ops_limit: u32, mem_limit: u32) -> io::Result<(Key, Key)> {
                let mut pw_hash = sodoken::SizedLockedArray::<64>::new()?;
                sodoken::blake2b::blake2b_hash(&mut *pw_hash.lock(), passphrase.as_bytes(), None)?;
                let mut pre_secret = tokio::task::spawn_blocking(move || -> io::Result<Key> {
                    let mut pre_secret = Key::new()?;
                    sodoken::argon2::blocking_argon2id(&mut *pre_secret.lock(), &*pw_hash.lock(), &salt, ops_limit, mem_limit)?;
                    Ok(pre_secret)
                })
                .await
                .map_err(other)??;
                let mut ctx_secret = Key::new()?;
                sodoken::kdf::derive_from_key(&mut *ctx_secret.lock(), 42, b"CtxSecKy", &pre_secret.lock())?;
                let mut id_secret = Key::new()?;
                sodoken::kdf::derive_from_key(&mut *id_secret.lock(), 142, b"IdnSecKy", &pre_secret.lock())?;
                Ok((ctx_secret, id_secret))
            }

            /// The context key and the id seed, opened with `passphrase`;
            /// None when it is not this store's.
            pub(super) async fn open(config: &LairServerConfigInner, passphrase: &str) -> io::Result<Option<(Key, Key)>> {
                let salt = *config.runtime_secrets_salt.cloned_inner();
                let (ctx_secret, id_secret) =
                    sealing_keys(passphrase, salt, config.runtime_secrets_ops_limit, config.runtime_secrets_mem_limit).await?;
                let Ok(context_key) = config.runtime_secrets_context_key.decrypt(Arc::new(Mutex::new(ctx_secret))).await else {
                    return Ok(None);
                };
                let id_seed = config.runtime_secrets_id_seed.decrypt(Arc::new(Mutex::new(id_secret))).await.map_err(other)?;
                Ok(Some((context_key, id_seed)))
            }

            pub(super) fn read(store_dir: &Path) -> Result<LairServerConfigInner> {
                let path = config_path(store_dir);
                let bytes = std::fs::read(&path).map_err(|source| Error::Io { what: "read the key store config", path: path.clone(), source })?;
                LairServerConfigInner::from_bytes(&bytes).map_err(|e| KeyStoreError::Config { path, what: e.to_string() }.into())
            }

            pub(super) async fn rekey(store_dir: &Path, current: &str, new: &str) -> Result<Rekeyed> {
                let path = config_path(store_dir);
                let crypto = |e: io::Error| Error::from(KeyStoreError::Lair(e.to_string()));
                let mut config = read(store_dir)?;

                if open(&config, new).await.map_err(crypto)?.is_some() {
                    log::warn!("[key store] already opens with the new passphrase; left as it is");
                    return Ok(Rekeyed::AlreadyNew);
                }
                let Some((context_key, id_seed)) = open(&config, current).await.map_err(crypto)? else {
                    return Err(KeyStoreError::StoreWrongPassphrase(store_dir.to_path_buf()).into());
                };

                let mut salt = [0u8; 16];
                sodoken::random::randombytes_buf(&mut salt).map_err(crypto)?;
                let (ctx_secret, id_secret) =
                    sealing_keys(new, salt, config.runtime_secrets_ops_limit, config.runtime_secrets_mem_limit).await.map_err(crypto)?;
                let context_key = SecretDataSized::encrypt(Arc::new(Mutex::new(ctx_secret)), Arc::new(Mutex::new(context_key)))
                    .await
                    .map_err(|e| crypto(other(e)))?;
                let id_seed = SecretDataSized::encrypt(Arc::new(Mutex::new(id_secret)), Arc::new(Mutex::new(id_seed)))
                    .await
                    .map_err(|e| crypto(other(e)))?;
                config.runtime_secrets_salt = salt.into();
                config.runtime_secrets_context_key = context_key;
                config.runtime_secrets_id_seed = id_seed;

                crate::files::write_atomic_private(&path, config.to_string().as_bytes())
                    .map_err(|source| Error::Io { what: "replace the key store config", path: path.clone(), source })?;
                log::info!("[key store] rewrapped under the new passphrase");
                Ok(Rekeyed::Rewrapped)
            }

            #[cfg(test)]
            pub(super) mod test_store {
                use super::*;
                use $lair::prelude::PwHashLimits;

                fn pass(p: &str) -> $lair::prelude::SharedLockedArray {
                    Arc::new(Mutex::new(sodoken::LockedArray::from(p.as_bytes().to_vec())))
                }

                /// A store config as `lair-keystore init` writes it, at the
                /// minimum argon2 limits (the limits travel in the config).
                pub async fn init(dir: &Path, passphrase: &str) {
                    let root = dir.to_path_buf();
                    let p = pass(passphrase);
                    let config = PwHashLimits::Minimum.with_exec(|| LairServerConfigInner::new(&root, p)).await.unwrap();
                    std::fs::write(config_path(dir), config.to_string()).unwrap();
                }

                /// Whether lair's own server code opens the store with
                /// `passphrase`: the in-process keystore unseals as
                /// `lair-keystore server` does at every start.
                pub async fn lair_opens(dir: &Path, passphrase: &str) -> bool {
                    $lair::in_proc_keystore::InProcKeystore::new(
                        Arc::new(read(dir).unwrap()),
                        $lair::mem_store::create_mem_store_factory(),
                        pass(passphrase),
                    )
                    .await
                    .is_ok()
                }

                /// The context key and id seed `passphrase` opens, as bytes.
                pub async fn secrets(dir: &Path, passphrase: &str) -> Vec<u8> {
                    let (mut context_key, mut id_seed) = open(&read(dir).unwrap(), passphrase).await.unwrap().unwrap();
                    let mut out = context_key.lock().to_vec();
                    out.extend_from_slice(&*id_seed.lock());
                    out
                }

                /// What must not move (the database salt, the connection URL,
                /// the files) and what must (the passphrase salt).
                pub fn fixed_and_moved(dir: &Path) -> (String, Vec<u8>) {
                    let c = read(dir).unwrap();
                    (
                        format!("{:?}|{}|{:?}|{:?}", c.database_salt, c.connection_url, c.store_file, c.pid_file),
                        c.runtime_secrets_salt.cloned_inner().to_vec(),
                    )
                }
            }
        }
    };
}

#[cfg(feature = "line-06")]
rewrap_with!(r06, lair_keystore_api_06);
#[cfg(feature = "line-07")]
rewrap_with!(r07, lair_keystore_api_07);

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! each_line {
        ($body:ident) => {{
            #[cfg(feature = "line-06")]
            $body!(Line::V06, r06::test_store);
            #[cfg(feature = "line-07")]
            $body!(Line::V07, r07::test_store);
        }};
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_rewrapped_store_opens_with_the_new_passphrase_only_and_keeps_its_secrets() {
        macro_rules! check {
            ($line:expr, $store:path) => {{
                use $store as store;
                let line = $line;
                let tmp = tempfile::tempdir().unwrap();
                let dir = tmp.path();
                store::init(dir, "the-constant").await;
                assert!(store::lair_opens(dir, "the-constant").await, "{line}");
                let secrets_before = store::secrets(dir, "the-constant").await;
                let (fixed_before, salt_before) = store::fixed_and_moved(dir);

                assert_eq!(rekey_store(dir, line, "the-constant", "per-install").await.unwrap(), Rekeyed::Rewrapped, "{line}");

                assert!(store::lair_opens(dir, "per-install").await, "{line}: lair opens it with the new passphrase");
                assert!(!store::lair_opens(dir, "the-constant").await, "{line}: and no longer with the old one");
                assert_eq!(store::secrets(dir, "per-install").await, secrets_before, "{line}: the same context key and id seed");
                let (fixed_after, salt_after) = store::fixed_and_moved(dir);
                assert_eq!(fixed_after, fixed_before, "{line}: database salt, connection URL and files untouched");
                assert_ne!(salt_after, salt_before, "{line}: a fresh passphrase salt");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = std::fs::metadata(config_path(dir)).unwrap().permissions().mode() & 0o777;
                    assert_eq!(mode, 0o600, "{line}: the config is private");
                }
            }};
        }
        each_line!(check);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_second_rewrap_is_a_no_op_and_a_wrong_passphrase_is_refused() {
        macro_rules! check {
            ($line:expr, $store:path) => {{
                use $store as store;
                let line = $line;
                let tmp = tempfile::tempdir().unwrap();
                let dir = tmp.path();
                store::init(dir, "a").await;
                assert_eq!(rekey_store(dir, line, "a", "b").await.unwrap(), Rekeyed::Rewrapped, "{line}");
                assert_eq!(rekey_store(dir, line, "a", "b").await.unwrap(), Rekeyed::AlreadyNew, "{line}: interrupted after the write, finished");
                let wrong = rekey_store(dir, line, "c", "d").await.unwrap_err();
                assert!(matches!(wrong, Error::KeyStore(KeyStoreError::StoreWrongPassphrase(_))), "{line}: {wrong}");
                assert!(store::lair_opens(dir, "b").await, "{line}: a refused rewrap changes nothing");
            }};
        }
        each_line!(check);
    }

    /// The real key stores: a store made under one passphrase and given a
    /// random seed, rewrapped, opens under the new one with the same key on
    /// disk, and no longer under the old.
    ///
    /// `HC_LINES_LAIR_06= HC_LINES_LAIR_07= cargo test --lib -- --ignored live_rewrap`
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn live_rewrap_keeps_every_key_on_the_real_key_store() {
        use crate::keystore::{start, wait_ready, SocketPlan};
        use crate::process::{stop_gracefully, StopRequest};
        use std::time::Duration;

        macro_rules! seed_on {
            ($v:ident, $url:expr, $pass:expr, $new:expr) => {{
                let client = crate::keystore::$v::connect($url, $pass, Duration::from_secs(30)).await?;
                if $new { crate::keystore::$v::new_seed(&client, "ai-x").await } else { crate::keystore::$v::existing(&client, "ai-x").await }
            }};
        }
        async fn seed(line: Line, dir: &Path, bin: &Path, passphrase: &str, new: bool) -> Result<[u8; 32]> {
            let plan = SocketPlan::new("hcl-live-rw", "lair");
            let (mut child, url) = start(dir, bin, passphrase, &plan)?;
            let out = async {
                wait_ready(&url, Duration::from_secs(15), &mut child, dir).await?;
                match line {
                    #[cfg(feature = "line-06")]
                    Line::V06 => seed_on!(v06, &url, passphrase, new),
                    #[cfg(feature = "line-07")]
                    Line::V07 => seed_on!(v07, &url, passphrase, new),
                    #[allow(unreachable_patterns)]
                    other => Err(Error::LineNotCompiled(other)),
                }
            }
            .await;
            let _ = stop_gracefully(&mut child, StopRequest::Terminate, Duration::from_secs(2));
            out
        }

        for (line, var) in [(Line::V06, "HC_LINES_LAIR_06"), (Line::V07, "HC_LINES_LAIR_07")] {
            let bin = std::path::PathBuf::from(std::env::var(var).unwrap_or_else(|_| panic!("set {var}")));
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join("lair");
            let key = seed(line, &dir, &bin, "the-constant", true).await.unwrap_or_else(|e| panic!("{line}: {e}"));
            assert_eq!(rekey_store(&dir, line, "the-constant", "per-install").await.unwrap(), Rekeyed::Rewrapped, "{line}");
            assert_eq!(seed(line, &dir, &bin, "per-install", false).await.unwrap_or_else(|e| panic!("{line}: {e}")), key, "{line}: the same key under its tag");
            assert!(seed(line, &dir, &bin, "the-constant", false).await.is_err(), "{line}: the old passphrase no longer opens it");
        }
    }
}
