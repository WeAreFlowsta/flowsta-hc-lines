//! Talking to a line's admin interface: one client over both lines, its
//! answers in line-free shapes, and a failed call as a kind.
//!
//! An [`AdminError`]'s text is the client error's `Display`, the text apps
//! wrapped in their own messages before this module existed, so those
//! messages read the same.

use crate::client::ZomeErrorKind;
use crate::Line;

/// A provisioned cell, as 39-byte DNA hash and agent key (the same bytes on
/// both lines).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellRef {
    pub role: String,
    pub dna_hash: Vec<u8>,
    pub agent_key: Vec<u8>,
}

/// An installed app, line-free.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppSummary {
    pub app_id: String,
    pub enabled: bool,
    /// 39 bytes.
    pub agent_key: Vec<u8>,
    /// Provisioned cells only (cloned and stem cells are left out).
    pub cells: Vec<CellRef>,
}

impl AppSummary {
    /// The app's first provisioned cell.
    pub fn first_cell(&self) -> Option<&CellRef> {
        self.cells.first()
    }
}

/// A failed admin call.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{detail}")]
pub struct AdminError {
    /// What was asked (`"connect"`, `"list_apps"`, `"enable_app"`, ...).
    pub op: &'static str,
    pub kind: ZomeErrorKind,
    /// The client error's `Display`.
    pub detail: String,
}

/// For apps whose functions still return `Result<_, String>`.
impl From<AdminError> for String {
    fn from(e: AdminError) -> String {
        e.to_string()
    }
}

/// A coordinator zome to hot-swap: `name`, depending on `name` + `_integrity`.
pub struct CoordinatorZome<'a> {
    pub name: &'a str,
    pub wasm: Vec<u8>,
}

/// An admin websocket on one of the two lines.
pub enum AdminClient {
    #[cfg(feature = "line-06")]
    V06(crate::v06::holochain_client::AdminWebsocket),
    #[cfg(feature = "line-07")]
    V07(crate::v07::holochain_client::AdminWebsocket),
}

#[cfg(feature = "line-06")]
fn err_06(op: &'static str, e: crate::v06::holochain_client::ConductorApiError) -> AdminError {
    AdminError { op, kind: crate::client::kind_06(&e), detail: e.to_string() }
}

#[cfg(feature = "line-07")]
fn err_07(op: &'static str, e: crate::v07::holochain_client::ConductorApiError) -> AdminError {
    AdminError { op, kind: crate::client::kind_07(&e), detail: e.to_string() }
}

impl AdminClient {
    /// Connect to `localhost:<port>` as `origin` (the conductor accepts only
    /// the origins its config names).
    pub async fn connect(line: Line, port: u16, origin: &str) -> Result<Self, AdminError> {
        let addr = format!("localhost:{port}");
        match line {
            #[cfg(feature = "line-06")]
            Line::V06 => crate::v06::holochain_client::AdminWebsocket::connect(addr, Some(origin.to_string()))
                .await
                .map(AdminClient::V06)
                .map_err(|e| err_06("connect", e)),
            #[cfg(feature = "line-07")]
            Line::V07 => crate::v07::holochain_client::AdminWebsocket::connect(addr, Some(origin.to_string()))
                .await
                .map(AdminClient::V07)
                .map_err(|e| err_07("connect", e)),
            #[allow(unreachable_patterns)]
            other => Err(AdminError { op: "connect", kind: ZomeErrorKind::Other, detail: crate::Error::LineNotCompiled(other).to_string() }),
        }
    }

    pub fn line(&self) -> Line {
        match self {
            #[cfg(feature = "line-06")]
            AdminClient::V06(_) => Line::V06,
            #[cfg(feature = "line-07")]
            AdminClient::V07(_) => Line::V07,
        }
    }

    /// Every installed app.
    pub async fn list_apps(&self) -> Result<Vec<AppSummary>, AdminError> {
        match self {
            #[cfg(feature = "line-06")]
            AdminClient::V06(ws) => {
                use crate::v06::holochain_client::CellInfo;
                use crate::v06::holochain_types::app::AppStatus;
                let apps = ws.list_apps(None).await.map_err(|e| err_06("list_apps", e))?;
                Ok(apps
                    .into_iter()
                    .map(|a| AppSummary {
                        enabled: matches!(a.status, AppStatus::Enabled),
                        agent_key: a.agent_pub_key.get_raw_39().to_vec(),
                        cells: a
                            .cell_info
                            .iter()
                            .flat_map(|(role, cells)| {
                                cells.iter().filter_map(move |c| match c {
                                    CellInfo::Provisioned(p) => Some(CellRef {
                                        role: role.to_string(),
                                        dna_hash: p.cell_id.dna_hash().get_raw_39().to_vec(),
                                        agent_key: p.cell_id.agent_pubkey().get_raw_39().to_vec(),
                                    }),
                                    _ => None,
                                })
                            })
                            .collect(),
                        app_id: a.installed_app_id,
                    })
                    .collect())
            }
            #[cfg(feature = "line-07")]
            AdminClient::V07(ws) => {
                use crate::v07::holochain_client::CellInfo;
                use crate::v07::holochain_types::app::AppStatus;
                let apps = ws.list_apps(None).await.map_err(|e| err_07("list_apps", e))?;
                Ok(apps
                    .into_iter()
                    .map(|a| AppSummary {
                        enabled: matches!(a.status, AppStatus::Enabled),
                        agent_key: a.agent_pub_key.get_raw_39().to_vec(),
                        cells: a
                            .cell_info
                            .iter()
                            .flat_map(|(role, cells)| {
                                cells.iter().filter_map(move |c| match c {
                                    CellInfo::Provisioned(p) => Some(CellRef {
                                        role: role.to_string(),
                                        dna_hash: p.cell_id.dna_hash().get_raw_39().to_vec(),
                                        agent_key: p.cell_id.agent_pubkey().get_raw_39().to_vec(),
                                    }),
                                    _ => None,
                                })
                            })
                            .collect(),
                        app_id: a.installed_app_id,
                    })
                    .collect())
            }
        }
    }

    pub async fn enable(&self, app_id: &str) -> Result<(), AdminError> {
        match self {
            #[cfg(feature = "line-06")]
            AdminClient::V06(ws) => ws.enable_app(app_id.to_string()).await.map(|_| ()).map_err(|e| err_06("enable_app", e)),
            #[cfg(feature = "line-07")]
            AdminClient::V07(ws) => ws.enable_app(app_id.to_string()).await.map(|_| ()).map_err(|e| err_07("enable_app", e)),
        }
    }

    /// Attach an app interface on a free port, answering `origin` only.
    pub async fn attach_app_interface(&self, origin: &str) -> Result<u16, AdminError> {
        match self {
            #[cfg(feature = "line-06")]
            AdminClient::V06(ws) => {
                use crate::v06::holochain_client::AllowedOrigins;
                ws.attach_app_interface(0, None, AllowedOrigins::Origins([origin.to_string()].into_iter().collect()), None)
                    .await
                    .map_err(|e| err_06("attach_app_interface", e))
            }
            #[cfg(feature = "line-07")]
            AdminClient::V07(ws) => {
                use crate::v07::holochain_client::AllowedOrigins;
                ws.attach_app_interface(0, None, AllowedOrigins::Origins([origin.to_string()].into_iter().collect()), None)
                    .await
                    .map_err(|e| err_07("attach_app_interface", e))
            }
        }
    }

    /// Hot-swap a cell's coordinator zome. The bundle holds one zome, `name`,
    /// at `<name>_coordinator.wasm`, depending on `<name>_integrity`. Cheap
    /// and idempotent: apps apply it on every start rather than trusting a
    /// marker.
    pub async fn update_coordinators(&self, cell: &CellRef, zome: CoordinatorZome<'_>) -> Result<(), AdminError> {
        let bad = |what: String| AdminError { op: "update_coordinators", kind: ZomeErrorKind::Other, detail: what };
        let path = format!("{}_coordinator.wasm", zome.name);
        let integrity = format!("{}_integrity", zome.name);
        match self {
            #[cfg(feature = "line-06")]
            AdminClient::V06(ws) => {
                use crate::v06::holochain_types::prelude::{
                    AgentPubKey, CellId, CoordinatorBundle, CoordinatorManifest, CoordinatorSource, DnaHash, UpdateCoordinatorsPayload, ZomeDependency, ZomeManifest,
                };
                let manifest_zome = ZomeManifest { name: zome.name.into(), hash: None, path, dependencies: Some(vec![ZomeDependency { name: integrity.as_str().into() }]) };
                let resource_id = manifest_zome.resource_id();
                let bundle = crate::v06::mr_bundle::Bundle::new(CoordinatorManifest { zomes: vec![manifest_zome] }, [(resource_id, zome.wasm.into())])
                    .map_err(|e| bad(format!("coordinator bundle: {e}")))?;
                let cell_id = CellId::new(DnaHash::from_raw_39(cell.dna_hash.clone()), AgentPubKey::from_raw_39(cell.agent_key.clone()));
                ws.update_coordinators(UpdateCoordinatorsPayload { cell_id, source: CoordinatorSource::Bundle(Box::new(CoordinatorBundle::from(bundle))) })
                    .await
                    .map_err(|e| err_06("update_coordinators", e))
            }
            #[cfg(feature = "line-07")]
            AdminClient::V07(ws) => {
                use crate::v07::holochain_types::prelude::{
                    AgentPubKey, CellId, CoordinatorBundle, CoordinatorManifest, CoordinatorSource, DnaHash, UpdateCoordinatorsPayload, ZomeDependency, ZomeManifest,
                };
                let manifest_zome = ZomeManifest { name: zome.name.into(), hash: None, path, dependencies: Some(vec![ZomeDependency { name: integrity.as_str().into() }]) };
                let resource_id = manifest_zome.resource_id();
                let bundle = crate::v07::mr_bundle::Bundle::new(CoordinatorManifest { zomes: vec![manifest_zome] }, [(resource_id, zome.wasm.into())])
                    .map_err(|e| bad(format!("coordinator bundle (0.7): {e}")))?;
                let cell_id = CellId::new(DnaHash::from_raw_39(cell.dna_hash.clone()), AgentPubKey::from_raw_39(cell.agent_key.clone()));
                ws.update_coordinators(UpdateCoordinatorsPayload { cell_id, source: CoordinatorSource::Bundle(Box::new(CoordinatorBundle::from(bundle))) })
                    .await
                    .map_err(|e| err_07("update_coordinators", e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_text_is_the_clients_display() {
        let e = AdminError { op: "list_apps", kind: ZomeErrorKind::ConnectionClosed, detail: "Websocket error: Close(\"x\")".into() };
        assert_eq!(e.to_string(), "Websocket error: Close(\"x\")");
        assert_eq!(String::from(e), "Websocket error: Close(\"x\")");
    }

    #[cfg(all(feature = "line-06", feature = "line-07"))]
    #[test]
    fn a_closed_port_is_refused() {
        // Nothing listens on port 1: the connect fails with a kind the
        // caller can act on (a conductor that is not there), not text.
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        for line in [Line::V06, Line::V07] {
            let r = rt.block_on(AdminClient::connect(line, 1, "flowsta-test"));
            let e = r.err().expect("nothing listens on port 1");
            assert_eq!(e.op, "connect");
            assert!(matches!(e.kind, ZomeErrorKind::ConnectionRefused | ZomeErrorKind::ConnectionClosed), "{line:?}: {e:?}");
        }
    }
}
