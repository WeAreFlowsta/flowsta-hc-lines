//! Talking to a line's app interface: one client over both lines, and a
//! zome call's failure as a kind a caller can decide on, instead of text it
//! has to search.
//!
//! The kind comes from the client crate's own error variants where it has
//! one (an unauthorized call, a websocket timeout, an I/O error), and from
//! the conductor's message only where the conductor sends nothing more
//! precise (a chain head that moved, a cell not running, a missing zome
//! function). Those messages are read here, in one place per line, with
//! tests; callers never search them.
//!
//! The error's text is the text callers matched on before this module
//! existed (`"<fn> failed: <client error Debug>"`), so a caller not yet
//! ported keeps working.

use crate::Line;

/// What went wrong with a zome call, as far as a caller decides on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ZomeErrorKind {
    /// Another write to the source chain landed first.
    ChainHeadMoved,
    /// The DNA has no such zome function (an older coordinator).
    MissingFunction,
    /// The call's capability or signature was refused.
    Unauthorized,
    /// The cell is disabled or not running yet (0.6 says `CellDisabled`,
    /// 0.7.1 `CellNotRunning`).
    CellNotRunning,
    /// The conductor reports that a network read inside the call ran out
    /// of time ("response timeout", "channel dropped"): the call failed, so
    /// nothing it would have written was written.
    Timeout,
    /// This side stopped waiting for the answer (the websocket request
    /// timed out). The call's outcome is unknown: a write may have landed.
    NoAnswer,
    /// The websocket closed or the connection was reset. As with
    /// [`ZomeErrorKind::NoAnswer`], a call in flight may have taken effect.
    ConnectionClosed,
    /// Nothing is listening on the port.
    ConnectionRefused,
    /// The coordinator's wasm did not compile: permanent for this build.
    ModuleBuild,
    /// The conductor reported an internal error that none of the kinds
    /// above names (often passing; whether to retry is the caller's call).
    Internal,
    /// Anything else; the text is in [`ZomeCallError::detail`].
    Other,
}

impl ZomeErrorKind {
    /// Worth another try after a short wait, and safe to retry even for a
    /// write: the call did not take effect.
    pub fn is_transient(self) -> bool {
        matches!(self, Self::ChainHeadMoved | Self::CellNotRunning | Self::Timeout | Self::ConnectionRefused)
    }

    /// The call may have taken effect even though it failed: retry a read,
    /// never blindly a write.
    pub fn outcome_unknown(self) -> bool {
        matches!(self, Self::NoAnswer | Self::ConnectionClosed)
    }
}

/// A failed zome call.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{fn_name} failed: {detail}")]
pub struct ZomeCallError {
    pub fn_name: String,
    pub kind: ZomeErrorKind,
    /// The client crate's error, as its `Debug` text.
    pub detail: String,
}

/// For apps whose functions still return `Result<_, String>`.
impl From<ZomeCallError> for String {
    fn from(e: ZomeCallError) -> String {
        e.to_string()
    }
}

/// An app websocket on one of the two lines.
pub enum AppClient {
    #[cfg(feature = "line-06")]
    V06(crate::v06::holochain_client::AppWebsocket),
    #[cfg(feature = "line-07")]
    V07(crate::v07::holochain_client::AppWebsocket),
}

impl AppClient {
    pub fn line(&self) -> Line {
        match self {
            #[cfg(feature = "line-06")]
            AppClient::V06(_) => Line::V06,
            #[cfg(feature = "line-07")]
            AppClient::V07(_) => Line::V07,
        }
    }

    /// Call a zome function. `payload` is the msgpack of the input; the
    /// result is the msgpack of the output.
    pub async fn call(&self, role: &str, zome: &str, fn_name: &str, payload: Vec<u8>) -> Result<Vec<u8>, ZomeCallError> {
        match self {
            #[cfg(feature = "line-06")]
            AppClient::V06(c) => {
                use crate::v06::holochain_client::ZomeCallTarget;
                use crate::v06::holochain_types::prelude::ExternIO;
                c.call_zome(ZomeCallTarget::RoleName(role.into()), zome.into(), fn_name.into(), ExternIO::from(payload))
                    .await
                    .map(|io| io.into_vec())
                    .map_err(|e| ZomeCallError { fn_name: fn_name.to_string(), kind: kind_06(&e), detail: format!("{e:?}") })
            }
            #[cfg(feature = "line-07")]
            AppClient::V07(c) => {
                use crate::v07::holochain_client::ZomeCallTarget;
                use crate::v07::holochain_types::prelude::ExternIO;
                c.call_zome(ZomeCallTarget::RoleName(role.into()), zome.into(), fn_name.into(), ExternIO::from(payload))
                    .await
                    .map(|io| io.into_vec())
                    .map_err(|e| ZomeCallError { fn_name: fn_name.to_string(), kind: kind_07(&e), detail: format!("{e:?}") })
            }
        }
    }
}

/// The 0.6 client's error as a kind.
#[cfg(feature = "line-06")]
pub fn kind_06(e: &crate::v06::holochain_client::ConductorApiError) -> ZomeErrorKind {
    use crate::v06::holochain_client::ConductorApiError as E;
    use holochain_conductor_api_06::ExternalApiWireError as W;
    match e {
        E::ExternalApiWireError(W::ZomeCallUnauthorized(_) | W::ZomeCallAuthenticationFailed(_)) => ZomeErrorKind::Unauthorized,
        E::ExternalApiWireError(W::InternalError(t)) => internal(t),
        E::IoError(io) => kind_of_io(io),
        E::WebsocketError(w) => kind_of_chain(w).unwrap_or_else(|| websocket(&format!("{w:?}"))),
        _ => kind_from_text(&format!("{e:?}")),
    }
}

/// The 0.7 client's error as a kind.
#[cfg(feature = "line-07")]
pub fn kind_07(e: &crate::v07::holochain_client::ConductorApiError) -> ZomeErrorKind {
    use crate::v07::holochain_client::ConductorApiError as E;
    use holochain_conductor_api_07::ExternalApiWireError as W;
    match e {
        E::ExternalApiWireError(W::ZomeCallUnauthorized(_) | W::ZomeCallAuthenticationFailed(_)) => ZomeErrorKind::Unauthorized,
        E::ExternalApiWireError(W::InternalError(t)) => internal(t),
        E::IoError(io) => kind_of_io(io),
        E::WebsocketError(w) => kind_of_chain(w).unwrap_or_else(|| websocket(&format!("{w:?}"))),
        _ => kind_from_text(&format!("{e:?}")),
    }
}

/// An I/O error anywhere under a websocket error, as a kind.
fn kind_of_chain(e: &(dyn std::error::Error + 'static)) -> Option<ZomeErrorKind> {
    let mut cur = Some(e);
    while let Some(err) = cur {
        if let Some(io) = err.downcast_ref::<std::io::Error>() {
            return Some(kind_of_io(io));
        }
        cur = err.source();
    }
    None
}

fn kind_of_io(io: &std::io::Error) -> ZomeErrorKind {
    use std::io::ErrorKind as K;
    match io.kind() {
        K::ConnectionRefused => ZomeErrorKind::ConnectionRefused,
        K::ConnectionReset | K::ConnectionAborted | K::BrokenPipe | K::NotConnected | K::UnexpectedEof => ZomeErrorKind::ConnectionClosed,
        K::TimedOut | K::WouldBlock => ZomeErrorKind::NoAnswer,
        _ => kind_from_text(&io.to_string()),
    }
}

/// A websocket failure: its timeout is [`ZomeErrorKind::NoAnswer`], anything
/// else leaves the connection unusable.
fn websocket(t: &str) -> ZomeErrorKind {
    match kind_from_text(t) {
        ZomeErrorKind::Other => ZomeErrorKind::ConnectionClosed,
        k => k,
    }
}

/// A conductor `InternalError`: a named kind when its message says one,
/// else [`ZomeErrorKind::Internal`].
fn internal(t: &str) -> ZomeErrorKind {
    use ZomeErrorKind as K;
    // The conductor answered: only the kinds it names apply, never one
    // about this side's connection.
    match kind_from_text(t) {
        k @ (K::ChainHeadMoved | K::MissingFunction | K::CellNotRunning | K::ModuleBuild | K::Unauthorized | K::Timeout) => k,
        _ => K::Internal,
    }
}

/// The conductor's message, read for what it sends only as text. First the
/// kinds the conductor names; then, once the message shows the conductor
/// answered (an `InternalError` or `RibosomeError`), nothing in it is about
/// this side's connection; last, this side's connection.
pub(crate) fn kind_from_text(t: &str) -> ZomeErrorKind {
    if t.contains("chain head has moved") || t.contains("HeadMoved") {
        ZomeErrorKind::ChainHeadMoved
    } else if t.contains("zome function that doesn't exist") {
        ZomeErrorKind::MissingFunction
    } else if t.contains("CellDisabled") || t.contains("CellNotRunning") {
        ZomeErrorKind::CellNotRunning
    } else if t.contains("ModuleBuild") {
        ZomeErrorKind::ModuleBuild
    } else if t.contains("nauthorized") {
        ZomeErrorKind::Unauthorized
    } else if t.contains("response timeout") || t.contains("channel dropped") {
        ZomeErrorKind::Timeout
    } else if t.contains("InternalError") {
        ZomeErrorKind::Internal
    } else if t.contains("RibosomeError") {
        ZomeErrorKind::Other
    } else if t.contains("ConnectionRefused") || t.contains("os error 10061") || t.contains("os error 111)") {
        ZomeErrorKind::ConnectionRefused
    } else if t.contains("ConnectionReset") || t.contains("ConnectionClosed") || t.contains("os error 10054") || t.contains("Close(") {
        ZomeErrorKind::ConnectionClosed
    } else if t.contains("Timeout") {
        ZomeErrorKind::NoAnswer
    } else if t.contains("Websocket error") || t.contains("WebsocketError") {
        ZomeErrorKind::ConnectionClosed
    } else {
        ZomeErrorKind::Other
    }
}

/// The kind of a failure an app holds only as text: a `Result<_, String>`
/// chain carrying a client error's `Display` or `Debug` (an admin call's
/// error, a zome call's [`ZomeCallError`] text). The same rules as the
/// typed classifiers' fallback, so callers never search the text
/// themselves.
pub fn kind_of_message(t: &str) -> ZomeErrorKind {
    kind_from_text(t)
}

/// What a failed `install_app` says about the app.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallFailure {
    /// An app with this id is installed already (a previous attempt went through).
    AppAlreadyInstalled,
    /// The DNA's cell exists already for this agent under another app id.
    CellAlreadyExists,
    /// Anything else, as a call kind.
    Other(ZomeErrorKind),
}

/// The 0.6 client's `install_app` error, read.
#[cfg(feature = "line-06")]
pub fn install_failure_06(e: &crate::v06::holochain_client::ConductorApiError) -> InstallFailure {
    install_failure(&format!("{e:?}"), || kind_06(e))
}

/// The 0.7 client's `install_app` error, read.
#[cfg(feature = "line-07")]
pub fn install_failure_07(e: &crate::v07::holochain_client::ConductorApiError) -> InstallFailure {
    install_failure(&format!("{e:?}"), || kind_07(e))
}

#[allow(dead_code)]
fn install_failure(debug: &str, kind: impl FnOnce() -> ZomeErrorKind) -> InstallFailure {
    if debug.contains("AppAlreadyInstalled") {
        InstallFailure::AppAlreadyInstalled
    } else if debug.contains("CellAlreadyExists") {
        InstallFailure::CellAlreadyExists
    } else {
        InstallFailure::Other(kind())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_messages_callers_matched_map_to_their_kinds() {
        // The texts the Vault searched for before this module (commands.rs,
        // sealed.rs, dna.rs), as the client's Debug carries them.
        for (t, k) in [
            ("RibosomeError(\"source chain head has moved\")", ZomeErrorKind::ChainHeadMoved),
            ("RibosomeError(\"Attempted to call a zome function that doesn't exist: Zome: x Fn: y\")", ZomeErrorKind::MissingFunction),
            ("InternalError(\"CellDisabled(...)\")", ZomeErrorKind::CellNotRunning),
            ("InternalError(\"CellNotRunning(...)\")", ZomeErrorKind::CellNotRunning),
            ("InternalError(\"ModuleBuild(...)\")", ZomeErrorKind::ModuleBuild),
            ("ZomeCallUnauthorized(\"...\")", ZomeErrorKind::Unauthorized),
            ("RibosomeError(\"... response timeout ...\")", ZomeErrorKind::Timeout),
            ("RibosomeError(\"get response channel dropped\")", ZomeErrorKind::Timeout),
            ("Io(Os { code: 10061, kind: ConnectionRefused })", ZomeErrorKind::ConnectionRefused),
            ("Io(Os { code: 10054, kind: ConnectionReset })", ZomeErrorKind::ConnectionClosed),
            ("RibosomeError(\"Wasm runtime error\")", ZomeErrorKind::Other),
        ] {
            assert_eq!(kind_from_text(t), k, "{t}");
        }
    }

    #[test]
    fn the_conductors_timeout_is_not_ours() {
        // A network read that timed out inside the call: nothing was written.
        assert_eq!(kind_from_text("RibosomeError(\"... response timeout ...\")"), ZomeErrorKind::Timeout);
        // This side stopped waiting: a write may have landed.
        assert_eq!(kind_from_text("WebsocketError(Timeout(Elapsed(())))"), ZomeErrorKind::NoAnswer);
        assert!(ZomeErrorKind::Timeout.is_transient() && !ZomeErrorKind::Timeout.outcome_unknown());
        assert!(!ZomeErrorKind::NoAnswer.is_transient() && ZomeErrorKind::NoAnswer.outcome_unknown());
        assert!(!ZomeErrorKind::ConnectionClosed.is_transient() && ZomeErrorKind::ConnectionClosed.outcome_unknown());
    }

    #[test]
    fn messages_held_as_text() {
        // An admin call's Display, wrapped in the app's own label.
        assert_eq!(kind_of_message("Admin WS: Websocket error: Io(Os { code: 10061, kind: ConnectionRefused })"), ZomeErrorKind::ConnectionRefused);
        assert_eq!(kind_of_message("list_apps: Websocket error: Close(\"x\")"), ZomeErrorKind::ConnectionClosed);
        assert_eq!(kind_of_message("Admin WS: Websocket error: Timeout(Elapsed(()))"), ZomeErrorKind::NoAnswer);
        assert_eq!(kind_of_message("auth creds: External API wire error: InternalError(\"busy\")"), ZomeErrorKind::Internal);
        assert_eq!(kind_of_message("revoke_signature zome call: External API wire error: InternalError(\"CellDisabled(..)\")"), ZomeErrorKind::CellNotRunning);
        // A caller's own timeout message is not the client's.
        assert_eq!(kind_of_message("get_all_sealed_at timed out after 20 s"), ZomeErrorKind::Other);
        assert_eq!(kind_of_message("deadline has elapsed"), ZomeErrorKind::Other);
        // The conductor answered: a timeout or a reset inside is its own business.
        assert_eq!(kind_of_message("External API wire error: InternalError(\"peer Timeout\")"), ZomeErrorKind::Internal);
        assert_eq!(kind_of_message("External API wire error: InternalError(\"ConnectionReset by peer\")"), ZomeErrorKind::Internal);
        assert_eq!(kind_of_message("External API wire error: RibosomeError(\"Timeout in wasm\")"), ZomeErrorKind::Other);
        assert_eq!(internal("peer Timeout"), ZomeErrorKind::Internal);
        assert_eq!(internal("source chain head has moved"), ZomeErrorKind::ChainHeadMoved);
    }

    #[test]
    fn install_failures() {
        assert_eq!(install_failure("InternalError(\"AppAlreadyInstalled(..)\")", || ZomeErrorKind::Other), InstallFailure::AppAlreadyInstalled);
        assert_eq!(install_failure("InternalError(\"CellAlreadyExists(..)\")", || ZomeErrorKind::Other), InstallFailure::CellAlreadyExists);
        assert_eq!(install_failure("InternalError(\"busy\")", || ZomeErrorKind::Internal), InstallFailure::Other(ZomeErrorKind::Internal));
    }

    #[test]
    fn a_moved_chain_head_wins_over_a_timeout() {
        assert_eq!(kind_from_text("chain head has moved after response timeout"), ZomeErrorKind::ChainHeadMoved);
    }

    #[test]
    fn io_errors_by_their_kind() {
        use std::io::{Error, ErrorKind};
        assert_eq!(kind_of_io(&Error::from(ErrorKind::ConnectionRefused)), ZomeErrorKind::ConnectionRefused);
        assert_eq!(kind_of_io(&Error::from(ErrorKind::ConnectionReset)), ZomeErrorKind::ConnectionClosed);
        assert_eq!(kind_of_io(&Error::from(ErrorKind::TimedOut)), ZomeErrorKind::NoAnswer);
    }

    #[test]
    fn the_text_is_the_old_text() {
        let e = ZomeCallError { fn_name: "get_x".into(), kind: ZomeErrorKind::Other, detail: "RibosomeError(\"y\")".into() };
        assert_eq!(e.to_string(), "get_x failed: RibosomeError(\"y\")");
    }

    #[cfg(feature = "line-06")]
    #[test]
    fn line_06_variants() {
        use crate::v06::holochain_client::ConductorApiError as E;
        use holochain_conductor_api_06::ExternalApiWireError as W;
        assert_eq!(kind_06(&E::ExternalApiWireError(W::ZomeCallUnauthorized("x".into()))), ZomeErrorKind::Unauthorized);
        assert_eq!(kind_06(&E::ExternalApiWireError(W::RibosomeError("source chain head has moved".into()))), ZomeErrorKind::ChainHeadMoved);
        assert_eq!(kind_06(&E::ExternalApiWireError(W::InternalError("CellDisabled".into()))), ZomeErrorKind::CellNotRunning);
        assert_eq!(kind_06(&E::IoError(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))), ZomeErrorKind::ConnectionRefused);
        assert_eq!(kind_06(&E::CellNotFound), ZomeErrorKind::Other);
        assert_eq!(kind_06(&E::ExternalApiWireError(W::InternalError("conductor busy".into()))), ZomeErrorKind::Internal);
    }

    #[cfg(feature = "line-07")]
    #[test]
    fn line_07_variants() {
        use crate::v07::holochain_client::ConductorApiError as E;
        use holochain_conductor_api_07::ExternalApiWireError as W;
        assert_eq!(kind_07(&E::ExternalApiWireError(W::ZomeCallAuthenticationFailed("x".into()))), ZomeErrorKind::Unauthorized);
        assert_eq!(kind_07(&E::ExternalApiWireError(W::InternalError("CellNotRunning".into()))), ZomeErrorKind::CellNotRunning);
        assert_eq!(kind_07(&E::ExternalApiWireError(W::RibosomeError("zome function that doesn't exist".into()))), ZomeErrorKind::MissingFunction);
        assert_eq!(kind_07(&E::IoError(std::io::Error::from(std::io::ErrorKind::ConnectionReset))), ZomeErrorKind::ConnectionClosed);
        assert_eq!(kind_07(&E::ExternalApiWireError(W::InternalError("conductor busy".into()))), ZomeErrorKind::Internal);
        assert_eq!(kind_07(&E::ExternalApiWireError(W::RibosomeError("anything else".into()))), ZomeErrorKind::Other);
    }
}
