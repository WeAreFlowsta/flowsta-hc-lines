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
}

pub type Result<T> = std::result::Result<T, Error>;
