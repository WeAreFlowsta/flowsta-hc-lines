//! Talking to a running lair, per line. The two lines' client crates have
//! the same calls, so one macro writes `v06` and `v07`.

macro_rules! line_client {
    ($module:ident, $lair:ident, $line:literal) => {
        #[doc = concat!("Lair calls for the ", $line, " line.")]
        pub mod $module {
            use super::super::{exited, KeyStoreError};
            use crate::process::SidecarChild;
            use crate::{Error, Result};
            use std::path::Path;
            use std::sync::Arc;
            use std::time::Duration;
            use $lair::dependencies::sodoken;
            use $lair::prelude::{BinDataSized, LairEntryInfo, SharedLockedArray};

            pub use $lair::prelude::LairClient;

            /// Tag of the helper seed lair needs to receive an imported seed.
            const IMPORT_HELPER: &str = "_import_helper";

            fn lair_err(e: impl std::fmt::Display) -> Error {
                KeyStoreError::Lair(e.to_string()).into()
            }

            /// Lair's answer for a tag it does not hold: "Query returned no
            /// rows" from its SQLite store, "tag not found" from its memory
            /// store.
            fn is_absent(e: &impl std::fmt::Display) -> bool {
                let t = e.to_string();
                t.contains("no rows") || t.contains("tag not found")
            }

            /// Lair's answer for a tag it already holds: "UNIQUE constraint"
            /// from its SQLite store, "tag already registered" from its
            /// memory store.
            fn is_duplicate(e: &impl std::fmt::Display) -> bool {
                let t = e.to_string();
                t.contains("UNIQUE constraint") || t.contains("tag already registered")
            }

            /// The Ed25519 public key of `seed`, as lair derives it.
            pub fn public_key_of_seed(seed: &[u8; 32]) -> Result<[u8; 32]> {
                let mut public = [0u8; sodoken::sign::PUBLICKEYBYTES];
                let mut secret = [0u8; sodoken::sign::SECRETKEYBYTES];
                sodoken::sign::seed_keypair(&mut public, &mut secret, seed).map_err(lair_err)?;
                secret.fill(0);
                Ok(public)
            }

            /// Connect to a running lair, giving up after `timeout`.
            pub async fn connect(connection_url: &str, passphrase: &str, timeout: Duration) -> Result<LairClient> {
                let url = $lair::dependencies::url::Url::parse(connection_url)
                    .map_err(|e| Error::from(KeyStoreError::Connect(format!("invalid connection URL: {e}"))))?;
                let pass: SharedLockedArray = Arc::new(std::sync::Mutex::new(
                    sodoken::LockedArray::from(passphrase.as_bytes().to_vec()),
                ));
                match tokio::time::timeout(timeout, $lair::ipc_keystore_connect(url, pass)).await {
                    Ok(Ok(client)) => Ok(client),
                    Ok(Err(e)) => Err(KeyStoreError::Connect(e.to_string()).into()),
                    Err(_) => Err(KeyStoreError::ConnectTimeout { secs: timeout.as_secs() }.into()),
                }
            }

            /// Connect to the lair just started as `child`: six tries 400 ms
            /// apart, 30 s each, stopping as soon as lair has exited. The
            /// socket appears before lair accepts connections, so the first
            /// try can meet a reset on a slow machine.
            pub async fn connect_with_retries(
                connection_url: &str,
                passphrase: &str,
                child: &mut SidecarChild,
                store_dir: &Path,
            ) -> Result<LairClient> {
                const ATTEMPTS: u32 = 6;
                let mut last = None;
                for attempt in 1..=ATTEMPTS {
                    if let Some(err) = exited(child, store_dir) {
                        return Err(err);
                    }
                    match connect(connection_url, passphrase, Duration::from_secs(30)).await {
                        Ok(client) => return Ok(client),
                        Err(e) => {
                            if let Some(err) = exited(child, store_dir) {
                                return Err(err);
                            }
                            if attempt < ATTEMPTS {
                                log::warn!("[lair:connect] attempt {attempt}/{ATTEMPTS} failed ({e}), retrying");
                                tokio::time::sleep(Duration::from_millis(400)).await;
                            }
                            last = Some(e);
                        }
                    }
                }
                Err(last.unwrap_or_else(|| KeyStoreError::Connect("no attempt made".into()).into()))
            }

            /// Import `seed` under `tag` and return its public key. A tag
            /// already present is reused only when it holds this seed: a tag
            /// standing for another key would start the conductor as that key.
            ///
            /// Lair takes an imported seed only encrypted to a key it holds,
            /// so the seed goes in a crypto_box to a helper seed's X25519 key.
            pub async fn import_seed(client: &LairClient, seed: &[u8; 32], tag: &str) -> Result<[u8; 32]> {
                let expected = public_key_of_seed(seed)?;
                if let Ok(LairEntryInfo::Seed { seed_info, .. }) = client.get_entry(tag.into()).await {
                    if *seed_info.ed25519_pub_key.0 != expected {
                        return Err(KeyStoreError::TagHoldsOtherKey { tag: tag.to_string() }.into());
                    }
                    log::info!("[lair] seed '{tag}' already present, reusing");
                    return Ok(expected);
                }
                let helper = match client.new_seed(IMPORT_HELPER.into(), None, false).await {
                    Ok(h) => h,
                    Err(_) => match client.get_entry(IMPORT_HELPER.into()).await {
                        Ok(LairEntryInfo::Seed { seed_info, .. }) => seed_info,
                        _ => return Err(KeyStoreError::Lair("could not create or fetch the import helper seed".into()).into()),
                    },
                };
                let mut sender_pub = [0u8; sodoken::crypto_box::XSALSA_PUBLICKEYBYTES];
                let mut sender_sec =
                    sodoken::SizedLockedArray::<{ sodoken::crypto_box::XSALSA_SECRETKEYBYTES }>::new().map_err(lair_err)?;
                sodoken::crypto_box::xsalsa_keypair(&mut sender_pub, &mut *sender_sec.lock()).map_err(lair_err)?;
                let mut nonce = [0u8; sodoken::crypto_box::XSALSA_NONCEBYTES];
                sodoken::random::randombytes_buf(&mut nonce).map_err(lair_err)?;
                let recipient: &[u8; 32] = &helper.x25519_pub_key.0;
                let mut cipher = vec![0u8; seed.len() + sodoken::crypto_box::XSALSA_MACBYTES];
                sodoken::crypto_box::xsalsa_easy(&mut cipher, seed, &nonce, recipient, &*sender_sec.lock())
                    .map_err(lair_err)?;
                let info = client
                    .import_seed(BinDataSized(Arc::new(sender_pub)), helper.x25519_pub_key, None, nonce, cipher.into(), tag.into(), false)
                    .await
                    .map_err(|e| Error::from(KeyStoreError::Lair(format!("seed import failed: {e}"))))?;
                if *info.ed25519_pub_key.0 != expected {
                    return Err(KeyStoreError::DerivedKeyMismatch.into());
                }
                Ok(expected)
            }

            /// A new random seed under `tag` that never leaves the store. A
            /// tag already present is that key, and is returned.
            pub async fn new_seed(client: &LairClient, tag: &str) -> Result<[u8; 32]> {
                match client.new_seed(tag.into(), None, false).await {
                    Ok(info) => Ok(*info.ed25519_pub_key.0),
                    Err(e) if is_duplicate(&e) => existing(client, tag).await,
                    Err(e) => Err(lair_err(e)),
                }
            }

            /// The public key under `tag`, which must be present.
            pub async fn existing(client: &LairClient, tag: &str) -> Result<[u8; 32]> {
                match client.get_entry(tag.into()).await {
                    Ok(LairEntryInfo::Seed { seed_info, .. }) => Ok(*seed_info.ed25519_pub_key.0),
                    Ok(_) => Err(KeyStoreError::Lair(format!("'{tag}' is not a seed")).into()),
                    Err(e) if is_absent(&e) => Err(KeyStoreError::KeyAbsent { tag: tag.to_string() }.into()),
                    Err(e) => Err(lair_err(e)),
                }
            }

            #[cfg(test)]
            mod tests {
                use super::*;
                use $lair::prelude::{LairServerConfigInner, PwHashLimits};

                async fn store() -> ($lair::in_proc_keystore::InProcKeystore, LairClient, tempfile::TempDir) {
                    let dir = tempfile::tempdir().unwrap();
                    let pass: SharedLockedArray =
                        Arc::new(std::sync::Mutex::new(sodoken::LockedArray::from(b"test-passphrase".to_vec())));
                    let root = dir.path().to_path_buf();
                    let p = pass.clone();
                    let config = Arc::new(
                        PwHashLimits::Minimum.with_exec(|| LairServerConfigInner::new(&root, p)).await.unwrap(),
                    );
                    let keystore = $lair::in_proc_keystore::InProcKeystore::new(
                        config,
                        $lair::mem_store::create_mem_store_factory(),
                        pass,
                    )
                    .await
                    .unwrap();
                    let client = keystore.new_client().await.unwrap();
                    (keystore, client, dir)
                }

                fn unhex(s: &str) -> [u8; 32] {
                    let mut out = [0u8; 32];
                    for i in 0..32 {
                        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
                    }
                    out
                }

                /// RFC 8032 section 7.1, test 1.
                #[test]
                fn the_public_key_of_a_seed_is_ed25519s() {
                    let seed = unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
                    let public = unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
                    assert_eq!(public_key_of_seed(&seed).unwrap(), public);
                }

                #[tokio::test]
                async fn an_imported_seed_has_the_seeds_own_key_and_signs_with_it() {
                    let (_ks, client, _dir) = store().await;
                    let seed = [7u8; 32];
                    let key = import_seed(&client, &seed, "device").await.unwrap();
                    assert_eq!(key, public_key_of_seed(&seed).unwrap());
                    let sig = client.sign_by_pub_key(BinDataSized::from(key), None, Arc::from(&b"m"[..])).await.unwrap();
                    assert_eq!(sig.0.len(), 64);
                }

                #[tokio::test]
                async fn a_tag_is_reused_only_for_its_own_seed() {
                    let (_ks, client, _dir) = store().await;
                    let first = import_seed(&client, &[3u8; 32], "device").await.unwrap();
                    assert_eq!(import_seed(&client, &[3u8; 32], "device").await.unwrap(), first);
                    let other = import_seed(&client, &[4u8; 32], "device").await.unwrap_err();
                    assert!(matches!(other, Error::KeyStore(KeyStoreError::TagHoldsOtherKey { .. })), "{other}");
                }

                #[tokio::test]
                async fn a_new_seed_under_a_tag_already_present_is_that_key() {
                    let (_ks, client, _dir) = store().await;
                    let made = new_seed(&client, "ai-1").await.unwrap();
                    assert_eq!(new_seed(&client, "ai-1").await.unwrap(), made);
                    assert_eq!(existing(&client, "ai-1").await.unwrap(), made);
                    assert_ne!(new_seed(&client, "ai-2").await.unwrap(), made);
                }

                #[tokio::test]
                async fn a_missing_tag_is_reported_as_absent() {
                    let (_ks, client, _dir) = store().await;
                    let err = existing(&client, "nobody").await.unwrap_err();
                    assert!(matches!(err, Error::KeyStore(KeyStoreError::KeyAbsent { .. })), "{err}");
                }
            }
        }
    };
}

#[cfg(feature = "line-06")]
line_client!(v06, lair_keystore_api_06, "0.6");
#[cfg(feature = "line-07")]
line_client!(v07, lair_keystore_api_07, "0.7");
