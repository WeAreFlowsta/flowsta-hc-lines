//! Run two Holochain lines side by side in a desktop app, and move a
//! person's data from the old line to the new one.
//!
//! A Holochain "line" is a series of releases that share a network and data
//! format (0.6.x, 0.7.x). Moving between lines is a breaking change: an app
//! runs the old line's conductor beside the new one, copies the person's own
//! data across, keeps both in step while another of their devices is still
//! on the old version, and retires the old line once nothing needs it.
//!
//! **Status: early.** The machinery is being extracted from Flowsta Vault,
//! where it runs in production; the public interface is not stable yet.
//!
//! Each line is a Cargo feature (`line-06`, `line-07`) that pins the exact
//! client crate versions its conductor needs. Use those crates through the
//! re-exports below rather than declaring them yourself: two declarations
//! of one crate at different versions cannot resolve.

mod error;
pub mod process;
mod line;
mod record;
mod versions;

pub use error::{Error, Result};
pub use line::{needs_update, records_held, Line};
pub use record::{record, record_opt, records, RecordView};
#[cfg(feature = "line-06")]
pub use record::view_06;
#[cfg(feature = "line-07")]
pub use record::view_07;
pub use versions::{latest_versions, missing_on, Versioned};

/// The Holochain 0.6 line: conductor 0.6.1, lair 0.6.3.
#[cfg(feature = "line-06")]
pub mod v06 {
    pub use holochain_client_06 as holochain_client;
    pub use holochain_types_06 as holochain_types;
    pub use lair_keystore_api_06 as lair_keystore_api;
    pub use mr_bundle_06 as mr_bundle;
}

/// The Holochain 0.7 line: conductor 0.7.1, lair 0.7.1.
#[cfg(feature = "line-07")]
pub mod v07 {
    pub use holochain_client_07 as holochain_client;
    pub use holochain_types_07 as holochain_types;
    pub use lair_keystore_api_07 as lair_keystore_api;
    pub use mr_bundle_07 as mr_bundle;
}
