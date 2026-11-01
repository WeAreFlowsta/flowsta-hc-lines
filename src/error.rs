//! The library's error type. Its `Display` text is the text the code it was
//! extracted from returned as a `String`, so callers that still match on
//! that text keep working while they move to the typed variants.

use crate::Line;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A record or entry did not decode with the given line's types.
    #[error("{what}")]
    Decode { line: Option<Line>, what: String },
    /// A sidecar binary was not found in any of the places searched.
    #[error("Sidecar {name} not found (looked for {})", .searched.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", "))]
    SidecarMissing { name: String, searched: Vec<std::path::PathBuf> },
    #[error(transparent)]
    KeyStore(#[from] crate::keystore::KeyStoreError),
    #[error(transparent)]
    Conductor(#[from] crate::conductor::ConductorError),
    /// A zome call failed; its kind says what a caller can do about it.
    #[error(transparent)]
    ZomeCall(#[from] crate::client::ZomeCallError),
    #[error(transparent)]
    Kit(#[from] crate::kit::KitError),
    /// The call needs a line this build does not include (its feature is off).
    #[error("Holochain line {0} is not compiled into this build")]
    LineNotCompiled(Line),
    /// A file or process operation failed.
    #[error("could not {what} ({}): {source}", .path.display())]
    Io { what: &'static str, path: std::path::PathBuf, #[source] source: std::io::Error },
}

pub type Result<T> = std::result::Result<T, Error>;

/// For apps whose functions still return `Result<_, String>`: `?` keeps
/// working on this library's results while they move to the typed error.
impl From<Error> for String {
    fn from(e: Error) -> String {
        e.to_string()
    }
}
