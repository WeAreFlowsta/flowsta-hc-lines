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

/// One hApp bundle to install under `app_id` for `agent_key` (39 bytes).
pub struct InstallRequest<'a> {
    pub app_id: &'a str,
    pub bundle: &'a std::path::Path,
    pub agent_key: &'a [u8],
    /// A network seed of the app's own (a per-person network); None keeps
    /// the bundle's.
    pub network_seed: Option<&'a str>,
}

/// What a resilient install or enable needs to recover from a websocket the
/// conductor reset mid-call: where to reconnect, and the conductor process,
/// so a conductor that died is noticed at once instead of waited on.
pub struct Recovery<'a> {
    pub admin_port: u16,
    pub origin: &'a str,
    pub conductor: &'a mut crate::process::SidecarChild,
}

/// How long to wait for a cell to answer, and what to re-enable between
/// tries (a conductor can list an app as enabled while its cells are still
/// starting, and can disable them again on a restart).
pub struct ReadyWait<'a> {
    pub attempts: u32,
    pub gap: std::time::Duration,
    pub reenable: &'a [String],
    /// Prefix for the "not ready yet" log lines.
    pub label: &'a str,
}

/// A signing credential grant, as each line's client hands it back.
pub enum Grant {
    #[cfg(feature = "line-06")]
    V06(crate::v06::holochain_client::SigningCredentials),
    #[cfg(feature = "line-07")]
    V07(crate::v07::holochain_client::SigningCredentials),
}

/// Wait until a 0.6 cell answers. The probe authorizes a signing grant on
/// it (the one signal that the cells truly run; the listed status is not),
/// retried while the conductor says the cell is not running. The grant
/// is a chain write, so it is handed back for the caller to keep as the
/// session's grant, with the attempt it took.
#[cfg(feature = "line-06")]
pub async fn wait_cell_ready_06(
    ws: &crate::v06::holochain_client::AdminWebsocket,
    cell_id: &crate::v06::holochain_types::prelude::CellId,
    w: &ReadyWait<'_>,
) -> Result<(crate::v06::holochain_client::SigningCredentials, u32), AdminError> {
    use crate::v06::holochain_client::AuthorizeSigningCredentialsPayload;
    let mut attempt = 0;
    loop {
        attempt += 1;
        match ws.authorize_signing_credentials(AuthorizeSigningCredentialsPayload { cell_id: cell_id.clone(), functions: None }).await {
            Ok(creds) => return Ok((creds, attempt)),
            Err(e) => {
                let e = err_06("authorize_signing_credentials", e);
                if e.kind != ZomeErrorKind::CellNotRunning || attempt >= w.attempts {
                    return Err(e);
                }
                log::info!("{} cells not ready yet (attempt {}/{}), waiting {} s", w.label, attempt, w.attempts, w.gap.as_secs());
                tokio::time::sleep(w.gap).await;
                for id in w.reenable {
                    let _ = ws.enable_app(id.clone()).await;
                }
            }
        }
    }
}

/// Wait until a 0.7 cell answers: [`wait_cell_ready_06`] on the 0.7 line.
#[cfg(feature = "line-07")]
pub async fn wait_cell_ready_07(
    ws: &crate::v07::holochain_client::AdminWebsocket,
    cell_id: &crate::v07::holochain_types::prelude::CellId,
    w: &ReadyWait<'_>,
) -> Result<(crate::v07::holochain_client::SigningCredentials, u32), AdminError> {
    use crate::v07::holochain_client::AuthorizeSigningCredentialsPayload;
    let mut attempt = 0;
    loop {
        attempt += 1;
        match ws.authorize_signing_credentials(AuthorizeSigningCredentialsPayload { cell_id: cell_id.clone(), functions: None }).await {
            Ok(creds) => return Ok((creds, attempt)),
            Err(e) => {
                let e = err_07("authorize_signing_credentials", e);
                if e.kind != ZomeErrorKind::CellNotRunning || attempt >= w.attempts {
                    return Err(e);
                }
                log::info!("{} cells not ready yet (attempt {}/{}), waiting {} s", w.label, attempt, w.attempts, w.gap.as_secs());
                tokio::time::sleep(w.gap).await;
                for id in w.reenable {
                    let _ = ws.enable_app(id.clone()).await;
                }
            }
        }
    }
}

/// What a recovery tries again.
enum Retry<'r> {
    Install(&'r InstallRequest<'r>),
    Enable(&'r str),
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

    /// The 0.6 websocket, for calls this client does not wrap.
    #[cfg(feature = "line-06")]
    pub fn as_v06(&self) -> Option<&crate::v06::holochain_client::AdminWebsocket> {
        match self {
            AdminClient::V06(ws) => Some(ws),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    /// The 0.7 websocket, for calls this client does not wrap.
    #[cfg(feature = "line-07")]
    pub fn as_v07(&self) -> Option<&crate::v07::holochain_client::AdminWebsocket> {
        match self {
            AdminClient::V07(ws) => Some(ws),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    /// Wait until `probe` answers, on either line ([`wait_cell_ready_06`]).
    pub async fn wait_cell_ready(&self, probe: &CellRef, w: &ReadyWait<'_>) -> Result<(Grant, u32), AdminError> {
        match self {
            #[cfg(feature = "line-06")]
            AdminClient::V06(ws) => {
                use crate::v06::holochain_types::prelude::{AgentPubKey, CellId, DnaHash};
                let cell = CellId::new(DnaHash::from_raw_39(probe.dna_hash.clone()), AgentPubKey::from_raw_39(probe.agent_key.clone()));
                wait_cell_ready_06(ws, &cell, w).await.map(|(g, n)| (Grant::V06(g), n))
            }
            #[cfg(feature = "line-07")]
            AdminClient::V07(ws) => {
                use crate::v07::holochain_types::prelude::{AgentPubKey, CellId, DnaHash};
                let cell = CellId::new(DnaHash::from_raw_39(probe.dna_hash.clone()), AgentPubKey::from_raw_39(probe.agent_key.clone()));
                wait_cell_ready_07(ws, &cell, w).await.map(|(g, n)| (Grant::V07(g), n))
            }
        }
    }

    /// Install one bundle. Not enabled yet: see [`AdminClient::enable`].
    pub async fn install(&self, req: &InstallRequest<'_>) -> Result<(), AdminError> {
        match self {
            #[cfg(feature = "line-06")]
            AdminClient::V06(ws) => {
                use crate::v06::holochain_client::InstallAppPayload;
                use crate::v06::holochain_types::{app::AppBundleSource, prelude::AgentPubKey};
                ws.install_app(InstallAppPayload {
                    source: AppBundleSource::Path(req.bundle.to_path_buf()),
                    agent_key: Some(AgentPubKey::from_raw_39(req.agent_key.to_vec())),
                    installed_app_id: Some(req.app_id.to_string()),
                    network_seed: req.network_seed.map(str::to_string),
                    roles_settings: None,
                    ignore_genesis_failure: false,
                })
                .await
                .map(|_| ())
                .map_err(|e| err_06("install_app", e))
            }
            #[cfg(feature = "line-07")]
            AdminClient::V07(ws) => {
                use crate::v07::holochain_client::InstallAppPayload;
                use crate::v07::holochain_types::{app::AppBundleSource, prelude::AgentPubKey};
                ws.install_app(InstallAppPayload {
                    source: AppBundleSource::Path(req.bundle.to_path_buf()),
                    agent_key: Some(AgentPubKey::from_raw_39(req.agent_key.to_vec())),
                    installed_app_id: Some(req.app_id.to_string()),
                    network_seed: req.network_seed.map(str::to_string),
                    roles_settings: None,
                    ignore_genesis_failure: false,
                    restore_from_dht: false,
                })
                .await
                .map(|_| ())
                .map_err(|e| err_07("install_app", e))
            }
        }
    }

    /// Install, surviving a websocket the conductor reset mid-call. A first
    /// install of a sizeable hApp compiles its wasm long enough for the
    /// conductor to reset the admin request (Windows 10054, `ConnectionClosed`)
    /// while the conductor stays up and the compiled wasm is cached; so on a
    /// failure: reconnect, check whether the install went through, try again,
    /// every 3 s for up to 30 s, and stop at once if the conductor exited.
    pub async fn install_resilient(&mut self, req: &InstallRequest<'_>, rec: Recovery<'_>) -> Result<(), AdminError> {
        if self.install(req).await.is_ok() {
            return Ok(());
        }
        log::warn!("[install] {} initial install_app failed - reconnecting and polling for status", req.app_id);
        self.recover("install_app", req.app_id, rec, Retry::Install(req)).await
    }

    /// Enable, surviving a websocket reset mid-call (a first enable compiles
    /// wasm too): the same recovery as [`AdminClient::install_resilient`],
    /// done once the app reads as enabled.
    pub async fn enable_resilient(&mut self, app_id: &str, rec: Recovery<'_>) -> Result<(), AdminError> {
        if self.enable(app_id).await.is_ok() {
            return Ok(());
        }
        log::warn!("[enable] {} initial enable_app failed - reconnecting and polling for status", app_id);
        self.recover("enable_app", app_id, rec, Retry::Enable(app_id)).await
    }

    async fn recover(&mut self, op: &'static str, app_id: &str, rec: Recovery<'_>, what: Retry<'_>) -> Result<(), AdminError> {
        let need_enabled = matches!(what, Retry::Enable(_));
        let tag = if need_enabled { "enable" } else { "install" };
        let line = self.line();
        let started = std::time::Instant::now();
        // 30 s is plenty for a healthy conductor's slow wasm compile; a
        // conductor that died will not recover by waiting (its owner starts a
        // fresh one that warm-starts on what is on disk).
        let deadline = started + std::time::Duration::from_secs(30);
        let mut attempts: u32 = 0;
        while std::time::Instant::now() < deadline {
            attempts += 1;
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            if let Ok(Some(status)) = rec.conductor.try_wait() {
                return Err(AdminError {
                    op,
                    kind: ZomeErrorKind::ConnectionRefused,
                    detail: format!("{op}({app_id}) bailing: conductor process exited (status {status}) after {}ms", started.elapsed().as_millis()),
                });
            }
            match AdminClient::connect(line, rec.admin_port, rec.origin).await {
                Ok(c) => *self = c,
                Err(e) => {
                    log::warn!("[{tag}] {app_id} reconnect attempt {attempts} failed: {e}");
                    continue;
                }
            }
            // Did it go through server-side despite the lost response?
            match self.list_apps().await {
                Ok(apps) if apps.iter().any(|a| a.app_id == app_id && (!need_enabled || a.enabled)) => {
                    log::info!("[{tag}] {app_id} confirmed after {}ms ({attempts} attempts)", started.elapsed().as_millis());
                    return Ok(());
                }
                Ok(_) => match match &what {
                    Retry::Install(req) => self.install(req).await,
                    Retry::Enable(id) => self.enable(id).await,
                } {
                    Ok(()) => {
                        log::info!("[{tag}] {app_id} retry succeeded after {}ms ({attempts} attempts)", started.elapsed().as_millis());
                        return Ok(());
                    }
                    Err(e) => log::warn!("[{tag}] {app_id} retry attempt {attempts} failed: {e} - continuing to poll"),
                },
                Err(e) => log::warn!("[{tag}] {app_id} list_apps attempt {attempts} failed: {e} - continuing to poll"),
            }
        }
        Err(AdminError {
            op,
            kind: ZomeErrorKind::NoAnswer,
            detail: format!("{op}({app_id}) gave up after {}s ({attempts} attempts)", started.elapsed().as_secs()),
        })
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

    /// The cells of every enabled app, cloned cells included: the spaces this
    /// conductor gossips in and the agents it runs there.
    pub async fn running_cells(&self) -> Result<Vec<CellRef>, AdminError> {
        match self {
            #[cfg(feature = "line-06")]
            AdminClient::V06(ws) => {
                use crate::v06::holochain_client::{AppStatusFilter, CellInfo};
                let apps = ws.list_apps(Some(AppStatusFilter::Enabled)).await.map_err(|e| err_06("list_apps", e))?;
                let mut cells = Vec::new();
                for app in &apps {
                    for (role, infos) in app.cell_info.iter() {
                        for info in infos {
                            let id = match info {
                                CellInfo::Provisioned(c) => &c.cell_id,
                                CellInfo::Cloned(c) => &c.cell_id,
                                _ => continue,
                            };
                            cells.push(CellRef { role: role.to_string(), dna_hash: id.dna_hash().get_raw_39().to_vec(), agent_key: id.agent_pubkey().get_raw_39().to_vec() });
                        }
                    }
                }
                Ok(cells)
            }
            #[cfg(feature = "line-07")]
            AdminClient::V07(ws) => {
                use crate::v07::holochain_client::{AppStatusFilter, CellInfo};
                let apps = ws.list_apps(Some(AppStatusFilter::Enabled)).await.map_err(|e| err_07("list_apps", e))?;
                let mut cells = Vec::new();
                for app in &apps {
                    for (role, infos) in app.cell_info.iter() {
                        for info in infos {
                            let id = match info {
                                CellInfo::Provisioned(c) => &c.cell_id,
                                CellInfo::Cloned(c) => &c.cell_id,
                                _ => continue,
                            };
                            cells.push(CellRef { role: role.to_string(), dna_hash: id.dna_hash().get_raw_39().to_vec(), agent_key: id.agent_pubkey().get_raw_39().to_vec() });
                        }
                    }
                }
                Ok(cells)
            }
        }
    }

    /// The conductor's agent-info notes (its own and its peers'), as raw
    /// signed strings.
    pub async fn agent_info(&self) -> Result<Vec<String>, AdminError> {
        match self {
            #[cfg(feature = "line-06")]
            AdminClient::V06(ws) => ws.agent_info(None).await.map_err(|e| err_06("agent_info", e)),
            #[cfg(feature = "line-07")]
            AdminClient::V07(ws) => ws.agent_info(None).await.map_err(|e| err_07("agent_info", e)),
        }
    }

    /// Hand the conductor agent-info notes it did not have.
    pub async fn add_agent_info(&self, infos: Vec<String>) -> Result<(), AdminError> {
        match self {
            #[cfg(feature = "line-06")]
            AdminClient::V06(ws) => ws.add_agent_info(infos).await.map_err(|e| err_06("add_agent_info", e)),
            #[cfg(feature = "line-07")]
            AdminClient::V07(ws) => ws.add_agent_info(infos).await.map_err(|e| err_07("add_agent_info", e)),
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
