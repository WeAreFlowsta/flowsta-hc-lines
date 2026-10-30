//! The conductor's database key file (`databases/db.key`), rewrapped under
//! a new passphrase.
//!
//! The file is `base64url_no_pad(nonce[24] || secretbox(key[32])[48] ||
//! salt[16])`, where the secretbox secret is argon2id(passphrase, salt) at
//! the MODERATE limits. Holochain 0.6.1 (`holochain_sqlite::db::key`) and
//! 0.7.1 (`holochain_data::key`) write the same format. Each line's file is
//! still handled with that line's own crypto crate, so a later line that
//! changes the format changes only its own arm.
//!
//! Only the wrapping changes: the inner key stays, and so does the salt,
//! which the conductor also gives SQLCipher as `cipher_salt`. A new salt
//! would make every database unreadable.

use super::KeyStoreError;
use crate::{Error, Line, Result};
use std::path::Path;

/// What a rewrap did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rekeyed {
    /// Rewrapped under the new passphrase.
    Rewrapped,
    /// Already opened with the new passphrase (an earlier change stopped
    /// between files); left as it was.
    AlreadyNew,
}

/// Rewrap the database key at `path`, written by `line`'s conductor, from
/// `current` to `new`. Blocking (argon2id twice or three times): run it off
/// the async runtime. The file is replaced atomically.
pub fn rekey_db_key(path: &Path, line: Line, current: &str, new: &str) -> Result<Rekeyed> {
    match line {
        #[cfg(feature = "line-06")]
        Line::V06 => rekey_06(path, current, new),
        #[cfg(feature = "line-07")]
        Line::V07 => rekey_07(path, current, new),
        #[allow(unreachable_patterns)]
        other => Err(KeyStoreError::Lair(format!("line {other} is not compiled in")).into()),
    }
}

macro_rules! rekey_with {
    ($name:ident, $lair:ident) => {
        fn $name(path: &Path, current: &str, new: &str) -> Result<Rekeyed> {
            use base64::Engine as _;
            use $lair::dependencies::sodoken;
            const NONCE: usize = sodoken::secretbox::XSALSA_NONCEBYTES;
            const MAC: usize = sodoken::secretbox::XSALSA_MACBYTES;
            const SALT: usize = sodoken::argon2::ARGON2_ID_SALTBYTES;
            let b64 = &base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let malformed = |what: String| Error::from(KeyStoreError::DbKeyMalformed { path: path.to_path_buf(), what });
            let crypto = |e: std::io::Error| Error::from(KeyStoreError::Lair(e.to_string()));

            let text = std::fs::read_to_string(path)
                .map_err(|source| Error::Io { what: "read the database key", path: path.to_path_buf(), source })?;
            let buf = b64.decode(text.trim()).map_err(|e| malformed(format!("not base64: {e}")))?;
            if buf.len() != NONCE + 32 + MAC + SALT {
                return Err(malformed(format!("length {}", buf.len())));
            }
            let nonce: [u8; NONCE] = buf[..NONCE].try_into().unwrap();
            let cipher = &buf[NONCE..NONCE + 32 + MAC];
            let mut salt = [0u8; SALT];
            salt.copy_from_slice(&buf[NONCE + 32 + MAC..]);

            let derive = |passphrase: &str| -> Result<sodoken::SizedLockedArray<32>> {
                let mut secret = sodoken::SizedLockedArray::<32>::new().map_err(crypto)?;
                sodoken::argon2::blocking_argon2id(
                    &mut *secret.lock(),
                    passphrase.as_bytes(),
                    &salt,
                    sodoken::argon2::ARGON2_ID_OPSLIMIT_MODERATE,
                    sodoken::argon2::ARGON2_ID_MEMLIMIT_MODERATE,
                )
                .map_err(crypto)?;
                Ok(secret)
            };

            let mut key = sodoken::SizedLockedArray::<32>::new().map_err(crypto)?;
            let opens = |secret: &mut sodoken::SizedLockedArray<32>, key: &mut sodoken::SizedLockedArray<32>| {
                sodoken::secretbox::xsalsa_open_easy(&mut *key.lock(), cipher, &nonce, &secret.lock()).is_ok()
            };
            if !opens(&mut derive(current)?, &mut key) {
                if opens(&mut derive(new)?, &mut key) {
                    log::warn!("[db.key] already wrapped with the new password; left as it is");
                    return Ok(Rekeyed::AlreadyNew);
                }
                return Err(KeyStoreError::DbKeyWrongPassword(path.to_path_buf()).into());
            }

            let mut new_nonce = [0u8; NONCE];
            sodoken::random::randombytes_buf(&mut new_nonce).map_err(crypto)?;
            let mut new_cipher = vec![0u8; 32 + MAC];
            sodoken::secretbox::xsalsa_easy(&mut new_cipher, &new_nonce, &*key.lock(), &derive(new)?.lock())
                .map_err(crypto)?;
            let mut out = Vec::with_capacity(NONCE + 32 + MAC + SALT);
            out.extend_from_slice(&new_nonce);
            out.extend_from_slice(&new_cipher);
            out.extend_from_slice(&salt);
            crate::files::write_atomic(path, b64.encode(&out).as_bytes())
                .map_err(|source| Error::Io { what: "replace the database key", path: path.to_path_buf(), source })?;
            log::info!("[db.key] rewrapped under the new password");
            Ok(Rekeyed::Rewrapped)
        }
    };
}

#[cfg(feature = "line-06")]
rekey_with!(rekey_06, lair_keystore_api_06);
#[cfg(feature = "line-07")]
rekey_with!(rekey_07, lair_keystore_api_07);

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    #[cfg(feature = "line-06")]
    use lair_keystore_api_06::dependencies::sodoken;
    #[cfg(all(feature = "line-07", not(feature = "line-06")))]
    use lair_keystore_api_07::dependencies::sodoken;

    fn compiled() -> Vec<Line> {
        let mut lines = Vec::new();
        #[cfg(feature = "line-06")]
        lines.push(Line::V06);
        #[cfg(feature = "line-07")]
        lines.push(Line::V07);
        lines
    }

    fn secret(passphrase: &str, salt: &[u8; 16]) -> sodoken::SizedLockedArray<32> {
        let mut secret = sodoken::SizedLockedArray::<32>::new().unwrap();
        sodoken::argon2::blocking_argon2id(
            &mut *secret.lock(),
            passphrase.as_bytes(),
            salt,
            sodoken::argon2::ARGON2_ID_OPSLIMIT_MODERATE,
            sodoken::argon2::ARGON2_ID_MEMLIMIT_MODERATE,
        )
        .unwrap();
        secret
    }

    /// A db.key as the conductor writes it (the format in this module's
    /// header), with its inner key and salt, so a test can check they survive.
    fn make(passphrase: &str) -> (String, [u8; 32], [u8; 16]) {
        let key = [0x5au8; 32];
        let mut salt = [0u8; 16];
        sodoken::random::randombytes_buf(&mut salt).unwrap();
        let mut nonce = [0u8; 24];
        sodoken::random::randombytes_buf(&mut nonce).unwrap();
        let mut cipher = vec![0u8; 48];
        sodoken::secretbox::xsalsa_easy(&mut cipher, &nonce, &key, &secret(passphrase, &salt).lock()).unwrap();
        let mut buf = nonce.to_vec();
        buf.extend_from_slice(&cipher);
        buf.extend_from_slice(&salt);
        (base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf), key, salt)
    }

    fn open(text: &str, passphrase: &str) -> Option<([u8; 32], [u8; 16])> {
        let buf = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(text.trim()).unwrap();
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&buf[72..]);
        let nonce: [u8; 24] = buf[..24].try_into().unwrap();
        let mut key = [0u8; 32];
        sodoken::secretbox::xsalsa_open_easy(&mut key, &buf[24..72], &nonce, &secret(passphrase, &salt).lock()).ok()?;
        Some((key, salt))
    }

    /// Each line: rewrapped, the inner key and salt kept, the old password
    /// no longer opens it, a repeat is a no-op, a wrong password is refused.
    #[test]
    fn each_line_rewraps_its_key_and_keeps_the_salt() {
        for line in compiled() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("db.key");
            let (text, key, salt) = make("old pass");
            std::fs::write(&path, &text).unwrap();
            assert_eq!(rekey_db_key(&path, line, "old pass", "new pass").unwrap(), Rekeyed::Rewrapped);
            let after = std::fs::read_to_string(&path).unwrap();
            assert_ne!(after, text);
            assert_eq!(open(&after, "new pass"), Some((key, salt)), "line {line}");
            assert_eq!(open(&after, "old pass"), None);
            assert_eq!(rekey_db_key(&path, line, "old pass", "new pass").unwrap(), Rekeyed::AlreadyNew);
            let wrong = rekey_db_key(&path, line, "neither", "other").unwrap_err();
            assert!(matches!(wrong, Error::KeyStore(KeyStoreError::DbKeyWrongPassword(_))), "{wrong}");
            assert_eq!(std::fs::read_to_string(&path).unwrap(), after, "a refused rewrap leaves the file");
        }
    }

    #[test]
    fn a_malformed_file_is_refused_and_left_alone() {
        for line in compiled() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("db.key");
            std::fs::write(&path, "AAAA").unwrap();
            let err = rekey_db_key(&path, line, "a", "b").unwrap_err();
            assert!(matches!(err, Error::KeyStore(KeyStoreError::DbKeyMalformed { .. })), "{err}");
            assert_eq!(std::fs::read_to_string(&path).unwrap(), "AAAA");
        }
    }
}
