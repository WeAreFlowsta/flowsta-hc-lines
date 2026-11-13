//! A key that already has a chain on the network, on a new device (the 0.7
//! line): the conductor rebuilds the chain from peers
//! ([`AdminClient::install_restoring`]) and the app enables it once it is
//! whole.
//!
//! **A restore can come back short.** The conductor asks the peers it can
//! reach for the key's chain head and takes the head they agree on. What
//! the old device wrote last and no peer holds yet is not in that answer,
//! and the restore still completes. Enabled there, the new device writes
//! its next action at a seq the old device already used: the old device's
//! last records are lost to the network, and the chain forks if it ever
//! comes back. So an app that knows how far the chain went (its backup
//! records the highest seq it holds) passes that to [`finish`], which does
//! not enable a shorter chain.
//!
//! **A restoring device stands in for the key.** While an app restores, the
//! conductor announces this device as the key's agent, and peers follow one
//! address per agent: the old device's gossip rounds then time out and its
//! last records never leave it. Waiting with the short restore installed
//! therefore cannot succeed. [`set_aside`] removes it, which takes this
//! device off the network under the key; the old device, started again,
//! hands its records to the peers; then the app installs for restore once
//! more.
//!
//! The order an app follows:
//!
//! 1. [`AdminClient::install_restoring`], once per app of the key.
//! 2. [`finish`]: `Whole` means it is enabled. `Short` means it is not.
//! 3. On `Short`: [`set_aside`], tell the person (the old device's last
//!    records have not reached the network; open the app there, or go on
//!    without them), and on their word go back to 1, passing `accept_short`
//!    as true if they chose to go on.

use crate::admin::{AdminClient, AdminError, RestoreState};
use std::time::{Duration, Instant};

/// What a finished restore came back with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Restored {
    /// Enabled: the chain reaches at least as far as the backup, or the
    /// person chose to go on with a shorter one.
    Whole,
    /// Not enabled: the network's copy ends at `have`, the backup at `want`.
    Short { have: u32, want: u32 },
}

#[derive(Debug, thiserror::Error)]
pub enum RestoreError {
    /// The network holds a validated warrant against the key. Terminal.
    #[error("this key's chain cannot be restored: the network holds a warrant against it ({0})")]
    Unrecoverable(String),
    #[error("{0} is not installed")]
    NotInstalled(String),
    #[error(transparent)]
    Admin(#[from] AdminError),
}

/// Whether a restored chain ending at `have` is missing records a backup
/// holds up to `want`: `(have, want)` when it is. No `want` (the app does
/// not know how far the chain went): never short.
pub fn short_by(have: Option<u32>, want: Option<u32>) -> Option<(u32, u32)> {
    match (have, want) {
        (Some(have), Some(want)) if have < want => Some((have, want)),
        // A chain with nothing in it, against a backup with records.
        (None, Some(want)) if want > 0 => Some((0, want)),
        _ => None,
    }
}

/// Wait for `app_id`'s restore to finish, then enable it, unless its chain
/// is shorter than `backup_head` and `accept_short` is false.
///
/// There is no time limit: the conductor retries by itself, and a restore
/// with too few peers online waits for them. `waited` hears how long it
/// has been, every few seconds, for the app's own screen.
///
/// An app already enabled is `Whole` (a restore that finished on an earlier
/// start). An app that restored while the program was closed is compared
/// before it is enabled, as one that restores now.
pub async fn finish(
    admin: &AdminClient,
    app_id: &str,
    backup_head: Option<u32>,
    accept_short: bool,
    mut waited: impl FnMut(Duration),
) -> Result<Restored, RestoreError> {
    let started = Instant::now();
    loop {
        match admin.restore_state(app_id).await? {
            RestoreState::NotInstalled => return Err(RestoreError::NotInstalled(app_id.to_string())),
            RestoreState::Unrecoverable(reason) => return Err(RestoreError::Unrecoverable(reason)),
            RestoreState::Enabled => return Ok(Restored::Whole),
            RestoreState::Restoring => {
                waited(started.elapsed());
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
            RestoreState::Restored => {
                if backup_head.is_some() {
                    match head_of(admin, app_id).await {
                        Ok(have) => {
                            if let Some((have, want)) = short_by(have, backup_head) {
                                if !accept_short {
                                    log::warn!("[restore] {app_id} came back to seq {have} and the backup holds to seq {want}: not enabled");
                                    return Ok(Restored::Short { have, want });
                                }
                                log::warn!("[restore] {app_id} is enabled at seq {have} though the backup holds to seq {want}: the person chose to go on without the last {} record(s)", want - have);
                            }
                        }
                        // Nothing to compare with: enable it, as an app
                        // that passes no backup head.
                        Err(e) => log::warn!("[restore] {app_id} could not be compared with the backup ({e}); enabling it"),
                    }
                }
                admin.enable(app_id).await?;
                log::info!("[restore] {app_id}: chain restored from the network and enabled ({} s)", started.elapsed().as_secs());
                return Ok(Restored::Whole);
            }
        }
    }
}

/// The highest seq among the app's provisioned cells' chains (an app with
/// one cell per key, the usual shape, has one).
async fn head_of(admin: &AdminClient, app_id: &str) -> Result<Option<u32>, AdminError> {
    let apps = admin.list_apps().await?;
    let Some(app) = apps.iter().find(|a| a.app_id == app_id) else { return Ok(None) };
    let mut head = None;
    for cell in &app.cells {
        if let Some(h) = admin.chain_head(cell).await? {
            head = Some(head.map_or(h, |x: u32| x.max(h)));
        }
    }
    Ok(head)
}

/// Set a short restore aside: uninstall it, which also takes this device
/// off the network under the key, so the old device can hand its last
/// records to the peers (see the module's notes). `own_prefix`: the prefix
/// the app gives this line's apps ([`AdminClient::uninstall`]'s rule).
/// Nothing of the person's is lost: what was restored is the network's
/// copy, and the next [`AdminClient::install_restoring`] fetches it again.
pub async fn set_aside(admin: &AdminClient, app_id: &str, own_prefix: &str) -> Result<(), AdminError> {
    admin.uninstall(app_id, own_prefix).await?;
    log::info!("[restore] {app_id}: the short restore is set aside; this device is off the network under the key");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::short_by;

    #[test]
    fn a_restore_is_short_only_when_it_ends_before_the_backup() {
        // The network agreed on seq 37; the backup held to 39.
        assert_eq!(short_by(Some(37), Some(39)), Some((37, 39)));
        // As far as the backup, or further (the old device wrote after its backup).
        assert_eq!(short_by(Some(39), Some(39)), None);
        assert_eq!(short_by(Some(44), Some(39)), None);
        // The app does not know how far the chain went.
        assert_eq!(short_by(Some(3), None), None);
        assert_eq!(short_by(None, None), None);
        // An empty chain against a backup with records; against one with none.
        assert_eq!(short_by(None, Some(5)), Some((0, 5)));
        assert_eq!(short_by(None, Some(0)), None);
    }
}
