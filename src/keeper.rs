//! The registration keeper: keeps a conductor's agents listed on the
//! rendezvous and feeds the listing back in, whenever the conductor's own
//! registration has stalled.
//!
//! Why (measured 2026-10-19 on Holochain 0.6.1, kitsune2 0.4.1; 0.7.1's
//! kitsune2 0.5.2 re-queues a failed send the same way): the conductor
//! re-signs each agent's note every 15 min and sends it to the bootstrap
//! server. A refused send goes back on the queue unchanged and is retried
//! on a backoff that reaches 5 min; the server refuses notes older than
//! 3 min. So a device that is awake and cut off for more than 3 min across
//! a re-sign (Wi-Fi gone, server down) is never listed again, and a request
//! caught by a sleep never times out. The conductor's only cure is a
//! restart. This is the gentler one: once a minute the keeper reads the
//! conductor's own fresh notes over the admin port, PUTs the ones a server
//! lacks, and adds listed peers the conductor has not heard of, against
//! every rendezvous the app knows, not only the one the conductor was
//! configured with at launch. A supervisor runs one per line
//! ([`crate::supervisor::Supervisor::start_keeper`]).

use base64::Engine;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// One signed agent note as the admin port and the server both carry it:
/// the raw string is what gets PUT and what `add_agent_info` takes.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Note {
    pub space: String,
    pub agent: String,
    /// Microseconds since the epoch.
    pub created_at: i64,
    pub tombstone: bool,
    /// The address the note says the agent is reached at; None while it
    /// has none.
    pub url: Option<String>,
    pub raw: String,
}

/// `{"agentInfo": "<json>", "signature": ...}` with `createdAt` as a string
/// of microseconds (the server's form) or a number.
pub(crate) fn parse_note(raw: &str) -> Option<Note> {
    let outer: serde_json::Value = serde_json::from_str(raw).ok()?;
    let inner: serde_json::Value = serde_json::from_str(outer.get("agentInfo")?.as_str()?).ok()?;
    let created_at = match inner.get("createdAt")? {
        serde_json::Value::String(s) => s.parse().ok()?,
        serde_json::Value::Number(n) => n.as_i64()?,
        _ => return None,
    };
    Some(Note {
        space: inner.get("space")?.as_str()?.to_string(),
        agent: inner.get("agent")?.as_str()?.to_string(),
        created_at,
        tombstone: inner.get("isTombstone").and_then(|v| v.as_bool()).unwrap_or(false),
        url: inner.get("url").and_then(|v| v.as_str()).filter(|u| !u.is_empty()).map(str::to_string),
        raw: raw.to_string(),
    })
}

/// The 32-byte core of a 39-byte holo hash, encoded the way a note names
/// its agent and its space.
pub(crate) fn id_core(hash: &[u8]) -> String {
    let core = if hash.len() == 39 { &hash[3..35] } else { hash };
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(core)
}

/// A healthy conductor sends a note within a second of signing it; after
/// this long unlisted, it plainly has not.
const PUT_MIN_AGE_US: i64 = 45_000_000;
/// The server refuses anything older than 3 min.
const PUT_MAX_AGE_US: i64 = 170_000_000;
/// A note lives this long; what we registered longer ago can be forgotten.
const NOTE_LIFETIME_US: i64 = 1_200_000_000;
/// kitsune2-bootstrap-srv keeps at most this many notes per network and
/// evicts one when a new one arrives. In a network with more agents than
/// this (Flowsta's public identity network), a note missing from the
/// listing says nothing about the conductor: it may simply have been
/// evicted. Registering is still right - once per note, as the conductor
/// itself would - but it is no sign of a stall.
const SERVER_CAP: usize = 32;

/// A listing this long may be the cap, not the whole network.
pub(crate) fn listing_full(listed: usize) -> bool {
    listed >= SERVER_CAP
}

/// True the first time a note is seen, so each note is registered once no
/// matter how many rounds pass before the server lists it (the conductor
/// sends each note once too; this matches that rate, and in a crowded
/// network evicts nobody needlessly).
pub(crate) fn first_time(registered: &mut HashSet<(String, String, i64)>, note: &Note) -> bool {
    registered.insert((note.space.clone(), note.agent.clone(), note.created_at))
}

/// Our own notes the server should have and does not: fresh enough to be
/// accepted, old enough that the conductor has had its chance, and newer
/// than whatever the server lists for that agent.
pub(crate) fn notes_to_put<'a>(own: &'a [Note], listed: &[Note], now_us: i64) -> Vec<&'a Note> {
    own.iter()
        .filter(|n| !n.tombstone)
        .filter(|n| {
            let age = now_us - n.created_at;
            (PUT_MIN_AGE_US..=PUT_MAX_AGE_US).contains(&age)
        })
        .filter(|n| !listed.iter().any(|l| l.space == n.space && l.agent == n.agent && l.created_at >= n.created_at))
        .collect()
}

/// Listed notes of other agents the conductor lacks, or holds an older
/// copy of.
pub(crate) fn notes_to_add<'a>(listed: &'a [Note], own_agents: &HashSet<String>, known: &[Note]) -> Vec<&'a Note> {
    listed
        .iter()
        .filter(|l| !own_agents.contains(&l.agent))
        .filter(|l| !known.iter().any(|k| k.space == l.space && k.agent == l.agent && k.created_at >= l.created_at))
        .collect()
}

/// How long after the last note signed elsewhere another install still
/// counts as running: two of a note's 20-minute lives, since two installs
/// that sign close together show each other a newer note only briefly.
const ELSEWHERE_LAPSES_AFTER: Duration = Duration::from_secs(40 * 60);

/// Our own agents that a server lists at ANOTHER address, in a note signed
/// after ours: `(space, agent, when that note was signed)`. One conductor
/// signs each of its agents' notes, so a newer note for our agent naming
/// another address was signed by another conductor holding the same key:
/// a second install running as it. (Our own notes from an earlier run or an
/// earlier address are older than our current one, and never count.) Two
/// conductors under one key each keep their own chain, and neither's
/// records reach the other.
pub(crate) fn announced_elsewhere(own: &[Note], listed: &[Note]) -> Vec<(String, String, i64)> {
    let mut out = Vec::new();
    for mine in own.iter().filter(|n| !n.tombstone) {
        let Some(my_url) = mine.url.as_deref() else { continue };
        for other in listed.iter().filter(|l| l.space == mine.space && l.agent == mine.agent && !l.tombstone) {
            if other.created_at > mine.created_at && other.url.as_deref().is_some_and(|u| u != my_url) {
                out.push((other.space.clone(), other.agent.clone(), other.created_at));
            }
        }
    }
    out
}

/// The newest note per (space, agent) out of several servers' listings.
pub(crate) fn newest_per_agent<'a>(notes: impl IntoIterator<Item = &'a Note>) -> Vec<&'a Note> {
    let mut best: HashMap<(String, String), &Note> = HashMap::new();
    for n in notes {
        let key = (n.space.clone(), n.agent.clone());
        match best.get(&key) {
            Some(b) if b.created_at >= n.created_at => {}
            _ => {
                best.insert(key, n);
            }
        }
    }
    best.into_values().collect()
}

/// A bootstrap server as the keeper talks to it: Flowsta's with this
/// app's auth material, or an open community node without.
pub struct Server {
    pub url: String,
    auth: Option<Vec<u8>>,
    token: Option<String>,
}

impl Server {
    /// `auth_b64` is the conductor config's `base64_auth_material_bootstrap`
    /// (standard base64). Material that does not decode means a server we
    /// cannot sign in to: skipped, with the reason in the log.
    pub fn new(url: &str, auth_b64: Option<&str>) -> Option<Self> {
        let auth = match auth_b64 {
            Some(b64) => match base64::engine::general_purpose::STANDARD.decode(b64.trim()) {
                Ok(bytes) => Some(bytes),
                Err(e) => {
                    log::warn!("[rendezvous] the auth material for {} does not decode ({}) - not using it", url, e);
                    return None;
                }
            },
            None => None,
        };
        Some(Self { url: url.trim_end_matches('/').to_string(), auth, token: None })
    }

    async fn authenticate(&mut self, client: &reqwest::Client) -> Result<(), String> {
        let Some(material) = &self.auth else { return Ok(()) };
        let r = client
            .put(format!("{}/authenticate", self.url))
            .body(material.clone())
            .send()
            .await
            .map_err(|e| format!("authenticate: {e}"))?;
        let status = r.status();
        let body = r.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(format!("authenticate: HTTP {status}"));
        }
        let token = parse_token(&body).ok_or_else(|| "authenticate: no token in the answer".to_string())?;
        self.token = Some(token);
        Ok(())
    }

    fn bearer(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.token {
            Some(t) => req.bearer_auth(t),
            None => req,
        }
    }

    /// One request, signing in first when needed and once more on a 401
    /// (tokens expire).
    async fn send(&mut self, client: &reqwest::Client, build: impl Fn() -> reqwest::RequestBuilder) -> Result<reqwest::Response, String> {
        if self.auth.is_some() && self.token.is_none() {
            self.authenticate(client).await?;
        }
        let r = self.bearer(build()).send().await.map_err(|e| e.to_string())?;
        if r.status() == reqwest::StatusCode::UNAUTHORIZED && self.auth.is_some() {
            self.token = None;
            self.authenticate(client).await?;
            return self.bearer(build()).send().await.map_err(|e| e.to_string());
        }
        Ok(r)
    }

    /// Everyone the server lists for a space.
    pub(crate) async fn list(&mut self, client: &reqwest::Client, space: &str) -> Result<Vec<Note>, String> {
        let url = format!("{}/bootstrap/{}", self.url, space);
        let r = self.send(client, || client.get(&url)).await?;
        if !r.status().is_success() {
            return Err(format!("list: HTTP {}", r.status()));
        }
        let items: Vec<serde_json::Value> = r.json().await.map_err(|e| format!("list: {e}"))?;
        Ok(items
            .iter()
            .filter_map(|v| match v {
                serde_json::Value::String(s) => parse_note(s),
                other => parse_note(&other.to_string()),
            })
            .collect())
    }

    /// Register one of our notes, as the conductor would have.
    pub(crate) async fn put(&mut self, client: &reqwest::Client, note: &Note) -> Result<(), String> {
        let url = format!("{}/bootstrap/{}/{}", self.url, note.space, note.agent);
        let body = note.raw.clone();
        let r = self.send(client, || client.put(&url).body(body.clone())).await?;
        if r.status().is_success() {
            Ok(())
        } else {
            let status = r.status();
            Err(format!("put: HTTP {} {}", status, r.text().await.unwrap_or_default().trim()))
        }
    }
}

/// `{"authToken": "..."}`; a bare token is accepted too.
pub(crate) fn parse_token(body: &str) -> Option<String> {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        return v.get("authToken").and_then(|t| t.as_str()).map(String::from);
    }
    let t = body.trim();
    (!t.is_empty()).then(|| t.to_string())
}

/// What one round did.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Round {
    /// Our notes we registered ourselves in a network whose listing we could trust.
    pub put: usize,
    /// Our notes we registered in a network whose listing was full: needed or not, no one can tell.
    pub registered_blind: usize,
    /// Other devices' notes we handed the conductor.
    pub added: usize,
    /// Servers that answered.
    pub reached: usize,
    /// Our fresh notes the server already had: the conductor is doing its job.
    pub conductor_registered: usize,
    /// Our notes we registered on a rendezvous the conductor was not
    /// configured with (an open fallback): extra reach, never a stall.
    pub put_elsewhere: usize,
    /// Our agents another install is running as too, by now beyond doubt
    /// ([`Keeper::same_key_elsewhere`]); 0 for every install with a key of
    /// its own.
    pub same_key_elsewhere: usize,
}

/// Is this the rendezvous the conductor itself registers with? The one it
/// was configured with at launch; unknown (an older start path) = the first
/// in the list, as before.
pub(crate) fn is_conductors(url: &str, index: usize, conductor: Option<&str>) -> bool {
    match conductor {
        Some(c) => url.trim_end_matches('/') == c.trim_end_matches('/'),
        None => index == 0,
    }
}

pub struct Keeper {
    servers: Vec<Server>,
    client: reqwest::Client,
    /// Notes we have registered: (space, agent, created_at).
    registered: HashSet<(String, String, i64)>,
    /// When we first had to register for the conductor, until it registers again.
    stalled_since: Option<std::time::Instant>,
    every_server_dark: bool,
    /// Fallback servers we have said we register on, said once each.
    told_elsewhere: HashSet<String>,
    /// Notes for our own agents signed elsewhere: (space, agent) → the
    /// signing times seen, and when one was last listed. Two different
    /// times mean the other conductor signed twice: it is running, not a
    /// leftover. Not listed for [`ELSEWHERE_LAPSES_AFTER`], it has stopped
    /// or has a key of its own now.
    elsewhere: HashMap<(String, String), (HashSet<i64>, Instant)>,
    told_same_key: bool,
}

impl Keeper {
    pub fn new(servers: Vec<Server>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .unwrap_or_default();
        Self { servers, client, registered: HashSet::new(), stalled_since: None, every_server_dark: false, told_elsewhere: HashSet::new(), elsewhere: HashMap::new(), told_same_key: false }
    }

    /// How many servers this keeper asks.
    pub fn server_count(&self) -> usize {
        self.servers.len()
    }

    /// How many of this conductor's agents another install is running as
    /// too: a rendezvous has listed the agent at another address in two
    /// notes signed after ours, so the other conductor is alive and signing.
    /// Zero for an install with a key of its own. While it is not zero, the
    /// two installs cannot sync: an app should say so and offer the person
    /// a way to give one of them a key of its own.
    pub fn same_key_elsewhere(&self) -> usize {
        self.elsewhere.values().filter(|(times, seen)| times.len() >= 2 && seen.elapsed() < ELSEWHERE_LAPSES_AFTER).count()
    }

    /// How long the keeper has been registering for the conductor, whose own
    /// registration did not reach its server; None while the conductor
    /// registers by itself.
    pub fn stalled_for(&self) -> Option<std::time::Duration> {
        self.stalled_since.map(|since| since.elapsed())
    }

    /// Read the conductor's own notes and peers, compare with every server,
    /// register and feed in what is missing.
    pub async fn run_once(&mut self, admin: &crate::admin::AdminClient, conductor: Option<&str>) -> Result<Round, String> {
        let (spaces, own_agents, raw_notes) = conductor_view(admin).await?;
        if spaces.is_empty() {
            return Ok(Round::default());
        }
        let notes: Vec<Note> = raw_notes.iter().filter_map(|s| parse_note(s)).collect();
        let (own, known): (Vec<Note>, Vec<Note>) = notes.into_iter().partition(|n| own_agents.contains(&n.agent));
        let now_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as i64)
            .unwrap_or(0);

        self.registered.retain(|(_, _, created)| now_us - created < NOTE_LIFETIME_US);
        let mut round = Round::default();
        let mut listings: Vec<Note> = Vec::new();
        let mut reached: HashSet<String> = HashSet::new();
        let mut put_on: Vec<String> = Vec::new();
        let mut put_elsewhere_on: Vec<String> = Vec::new();
        for space in &spaces {
            let own_here: Vec<Note> = own.iter().filter(|n| n.space == *space).cloned().collect();
            for (index, server) in self.servers.iter_mut().enumerate() {
                let conductors = is_conductors(&server.url, index, conductor);
                let listed = match server.list(&self.client, space).await {
                    Ok(l) => l,
                    Err(e) => {
                        log::debug!("[rendezvous] {} did not answer: {}", server.url, e);
                        continue;
                    }
                };
                reached.insert(server.url.clone());
                round.conductor_registered += if !conductors { 0 } else { own_here
                    .iter()
                    .filter(|n| now_us - n.created_at <= PUT_MAX_AGE_US)
                    .filter(|n| listed.iter().any(|l| l.agent == n.agent && l.created_at >= n.created_at))
                    .count() };
                for (space, agent, signed_at) in announced_elsewhere(&own_here, &listed) {
                    let seen = self.elsewhere.entry((space, agent)).or_insert_with(|| (HashSet::new(), Instant::now()));
                    seen.0.insert(signed_at);
                    seen.1 = Instant::now();
                }
                let full = listing_full(listed.len());
                for note in notes_to_put(&own_here, &listed, now_us) {
                    if !first_time(&mut self.registered, note) {
                        continue;
                    }
                    match server.put(&self.client, note).await {
                        Ok(()) if !conductors => {
                            round.put_elsewhere += 1;
                            put_elsewhere_on.push(server.url.clone());
                        }
                        Ok(()) if full => round.registered_blind += 1,
                        Ok(()) => {
                            round.put += 1;
                            put_on.push(server.url.clone());
                        }
                        Err(e) => log::warn!("[rendezvous] could not register an agent on {}: {}", server.url, e),
                    }
                }
                listings.extend(listed);
            }
        }
        round.reached = reached.len();
        self.elsewhere.retain(|_, (_, seen)| seen.elapsed() < ELSEWHERE_LAPSES_AFTER);
        round.same_key_elsewhere = self.same_key_elsewhere();
        if round.same_key_elsewhere == 0 && self.told_same_key {
            self.told_same_key = false;
            log::info!("[rendezvous] no other install has announced this conductor's key for {} min", ELSEWHERE_LAPSES_AFTER.as_secs() / 60);
        }
        if round.same_key_elsewhere > 0 && !self.told_same_key {
            self.told_same_key = true;
            log::warn!(
                "[rendezvous] another install is running as this conductor's key ({} agent(s) listed at another address in notes signed after ours, twice): the two cannot sync until one has a key of its own",
                round.same_key_elsewhere
            );
        }

        let to_add: Vec<String> = newest_per_agent(notes_to_add(&listings, &own_agents, &known)).into_iter().map(|n| n.raw.clone()).collect();
        if !to_add.is_empty() {
            admin.add_agent_info(to_add.clone()).await.map_err(|e| format!("add agent info: {e}"))?;
            round.added = to_add.len();
        }

        self.report(&round, &put_on);
        for url in put_elsewhere_on {
            if self.told_elsewhere.insert(url.clone()) {
                log::info!(
                    "[rendezvous] this device is listed on {} too, so other devices find it if {} goes dark (the conductor registers only there)",
                    url,
                    conductor.unwrap_or("the main rendezvous")
                );
            }
        }
        Ok(round)
    }

    /// Say something only when the picture changes: the first time we had
    /// to step in, when the conductor registers again, when every server
    /// is dark and when one is back.
    fn report(&mut self, round: &Round, put_on: &[String]) {
        if round.reached == 0 {
            if !self.every_server_dark {
                log::warn!("[rendezvous] no rendezvous answered ({} tried) - the other devices cannot find this one until one does", self.servers.len());
                self.every_server_dark = true;
            }
            return;
        }
        if self.every_server_dark {
            log::info!("[rendezvous] a rendezvous answers again");
            self.every_server_dark = false;
        }
        if round.put > 0 {
            let mut on: Vec<&String> = put_on.iter().collect();
            on.sort();
            on.dedup();
            let on: Vec<&str> = on.iter().map(|s| s.as_str()).collect();
            match self.stalled_since {
                None => {
                    self.stalled_since = Some(std::time::Instant::now());
                    log::warn!(
                        "[rendezvous] registered {} agent note(s) on {} ourselves - the conductor's own registration did not reach the server",
                        round.put,
                        on.join(", ")
                    );
                }
                Some(since) => log::info!("[rendezvous] registered {} note(s) ourselves ({} min since the conductor last managed)", round.put, since.elapsed().as_secs() / 60),
            }
        } else if round.conductor_registered > 0 {
            if let Some(since) = self.stalled_since.take() {
                log::info!("[rendezvous] the conductor is registering again (we covered {} min)", since.elapsed().as_secs() / 60);
            }
        }
        if round.added > 0 {
            log::info!("[rendezvous] handed the conductor {} note(s) of other devices it had not heard of", round.added);
        }
        if round.registered_blind > 0 {
            log::debug!("[rendezvous] registered {} note(s) in a network whose listing is full (no sign of a stall)", round.registered_blind);
        }
    }
}

/// Servers from the app's list of `(bootstrap URL, auth material)`: the
/// conductor's own rendezvous first, then any open fallbacks.
pub fn servers_from(list: &[(String, Option<String>)]) -> Vec<Server> {
    list.iter().filter_map(|(url, auth)| Server::new(url, auth.as_deref())).collect()
}

/// What a conductor knows: the spaces its enabled cells are in, the agents
/// it runs, and its agent-info notes as raw strings.
async fn conductor_view(admin: &crate::admin::AdminClient) -> Result<(HashSet<String>, HashSet<String>, Vec<String>), String> {
    let cells = admin.running_cells().await.map_err(|e| format!("list apps: {e}"))?;
    let spaces: HashSet<String> = cells.iter().map(|c| id_core(&c.dna_hash)).collect();
    let own_agents: HashSet<String> = cells.iter().map(|c| id_core(&c.agent_key)).collect();
    let raw = if spaces.is_empty() { Vec::new() } else { admin.agent_info().await.map_err(|e| format!("agent info: {e}"))? };
    Ok((spaces, own_agents, raw))
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_the_rendezvous_the_conductor_was_given_counts_for_a_stall() {
        use super::is_conductors;
        let main = Some("https://bootstrap.flowsta.com");
        assert!(is_conductors("https://bootstrap.flowsta.com/", 0, main));
        assert!(!is_conductors("https://node1.flowsta.com", 1, main), "a fallback the conductor never registers with");
        let fell_back = Some("https://node1.flowsta.com/");
        assert!(is_conductors("https://node1.flowsta.com", 1, fell_back), "the conductor started on the fallback");
        assert!(!is_conductors("https://bootstrap.flowsta.com", 0, fell_back));
        assert!(is_conductors("https://bootstrap.flowsta.com", 0, None), "unknown: the first, as before");
        assert!(!is_conductors("https://node1.flowsta.com", 1, None));
    }

    use super::*;

    fn note(space: &str, agent: &str, created_at: i64, tombstone: bool) -> Note {
        let inner = serde_json::json!({ "agent": agent, "space": space, "createdAt": created_at.to_string(), "expiresAt": (created_at + 1_200_000_000).to_string(), "isTombstone": tombstone, "url": "http://relay/node", "storageArc": null });
        let raw = serde_json::json!({ "agentInfo": inner.to_string(), "signature": "c2ln" }).to_string();
        parse_note(&raw).expect("a note we made parses")
    }

    fn note_at(space: &str, agent: &str, created_at: i64, url: Option<&str>) -> Note {
        let mut n = note(space, agent, created_at, false);
        n.url = url.map(String::from);
        n
    }

    #[test]
    fn our_key_at_another_address_in_a_newer_note_is_another_install() {
        let mine = [note_at("s", "me", 1_000, Some("http://relay/here"))];
        // Signed after ours, at another address: another conductor holds the key.
        assert_eq!(announced_elsewhere(&mine, &[note_at("s", "me", 1_500, Some("http://relay/there"))]), vec![("s".to_string(), "me".to_string(), 1_500)]);
        // Our own note from an earlier run or an earlier address is older than ours.
        assert!(announced_elsewhere(&mine, &[note_at("s", "me", 900, Some("http://relay/before-the-restart"))]).is_empty());
        // The same address (the server has our own note, or a newer one of ours).
        assert!(announced_elsewhere(&mine, &[note_at("s", "me", 1_500, Some("http://relay/here"))]).is_empty());
        // Another agent, another space, a note with no address, a tombstone.
        assert!(announced_elsewhere(&mine, &[note_at("s", "other", 1_500, Some("http://relay/there")), note_at("t", "me", 1_500, Some("http://relay/there")), note_at("s", "me", 1_500, None)]).is_empty());
        let mut gone = note_at("s", "me", 1_500, Some("http://relay/there"));
        gone.tombstone = true;
        assert!(announced_elsewhere(&mine, &[gone]).is_empty());
        // While we have no address of our own, nothing can be compared.
        assert!(announced_elsewhere(&[note_at("s", "me", 1_000, None)], &[note_at("s", "me", 1_500, Some("http://relay/there"))]).is_empty());
    }

    #[test]
    fn another_install_is_called_only_once_it_has_signed_twice() {
        let mut k = Keeper::new(Vec::new());
        assert_eq!(k.same_key_elsewhere(), 0);
        // One note elsewhere: could be a leftover that was listed late.
        let key = ("s".to_string(), "me".to_string());
        k.elsewhere.insert(key.clone(), (HashSet::from([1_500]), Instant::now()));
        k.elsewhere.get_mut(&key).unwrap().0.insert(1_500);
        assert_eq!(k.same_key_elsewhere(), 0, "the same note seen in two rounds is one note");
        // It signed again: it is running.
        k.elsewhere.get_mut(&key).unwrap().0.insert(900_001_500);
        assert_eq!(k.same_key_elsewhere(), 1);
        // Not listed for two note lives: it stopped, or has a key of its own now.
        if let Some(long_ago) = Instant::now().checked_sub(ELSEWHERE_LAPSES_AFTER + Duration::from_secs(1)) {
            k.elsewhere.get_mut(&key).unwrap().1 = long_ago;
            assert_eq!(k.same_key_elsewhere(), 0);
        }
    }

    #[test]
    fn a_note_parses_from_the_servers_form_and_the_conductors() {
        let n = note("spaceA", "agentA", 1_700_000_000_000_000, false);
        assert_eq!((n.space.as_str(), n.agent.as_str(), n.created_at, n.tombstone), ("spaceA", "agentA", 1_700_000_000_000_000, false));
        let numeric = serde_json::json!({ "agentInfo": serde_json::json!({ "agent": "a", "space": "s", "createdAt": 5, "isTombstone": true }).to_string(), "signature": "x" }).to_string();
        let n = parse_note(&numeric).unwrap();
        assert!(n.tombstone);
        assert_eq!(n.created_at, 5);
        assert!(parse_note("not json").is_none());
        assert!(parse_note(r#"{"agentInfo":"{}","signature":"x"}"#).is_none(), "no agent, no note");
    }

    #[test]
    fn the_note_names_the_32_byte_core_of_a_holo_hash() {
        let mut hash = vec![0x84, 0x20, 0x24];
        hash.extend(std::iter::repeat_n(7u8, 32));
        hash.extend([1, 2, 3, 4]);
        assert_eq!(hash.len(), 39);
        assert_eq!(id_core(&hash), base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]));
        assert_eq!(id_core(&[1, 2, 3]), base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1, 2, 3]), "anything else as is");
    }

    #[test]
    fn we_register_only_what_is_fresh_unsent_and_missing_from_the_server() {
        let now = 2_000_000_000_000_000;
        let s = |age_s: i64| now - age_s * 1_000_000;
        let own = vec![
            note("sp", "too_new", s(10), false),
            note("sp", "due", s(60), false),
            note("sp", "due_but_listed_newer", s(60), false),
            note("sp", "due_and_listed_older", s(60), false),
            note("sp", "too_old", s(200), false),
            note("sp", "gone", s(60), true),
        ];
        let listed = vec![note("sp", "due_but_listed_newer", s(30), false), note("sp", "due_and_listed_older", s(900), false)];
        let agents: Vec<&str> = notes_to_put(&own, &listed, now).into_iter().map(|n| n.agent.as_str()).collect();
        assert_eq!(agents, vec!["due", "due_and_listed_older"]);
    }

    #[test]
    fn we_hand_the_conductor_only_other_devices_notes_it_lacks_or_holds_old() {
        let own: HashSet<String> = ["me"].into_iter().map(String::from).collect();
        let listed = vec![
            note("sp", "me", 100, false),
            note("sp", "peer_unknown", 100, false),
            note("sp", "peer_known_same", 100, false),
            note("sp", "peer_known_newer_here", 100, false),
            note("sp", "peer_known_older_here", 100, false),
        ];
        let known = vec![note("sp", "peer_known_same", 100, false), note("sp", "peer_known_newer_here", 150, false), note("sp", "peer_known_older_here", 50, false)];
        let agents: Vec<&str> = notes_to_add(&listed, &own, &known).into_iter().map(|n| n.agent.as_str()).collect();
        assert_eq!(agents, vec!["peer_unknown", "peer_known_older_here"]);
    }

    #[test]
    fn several_servers_listings_collapse_to_the_newest_note_per_agent() {
        let a1 = note("sp", "a", 100, false);
        let a2 = note("sp", "a", 300, false);
        let b = note("sp", "b", 100, false);
        let a_other_space = note("sp2", "a", 50, false);
        let mut got: Vec<(String, String, i64)> = newest_per_agent([&a1, &a2, &b, &a_other_space]).into_iter().map(|n| (n.space.clone(), n.agent.clone(), n.created_at)).collect();
        got.sort();
        assert_eq!(got, vec![("sp".into(), "a".into(), 300), ("sp".into(), "b".into(), 100), ("sp2".into(), "a".into(), 50)]);
    }

    #[test]
    fn a_note_is_registered_once_and_a_full_listing_is_no_stall() {
        let mut seen = HashSet::new();
        let n = note("sp", "a", 100, false);
        assert!(first_time(&mut seen, &n));
        assert!(!first_time(&mut seen, &n), "the same note again is not registered twice");
        assert!(first_time(&mut seen, &note("sp", "a", 200, false)), "a re-signed note is new");
        assert!(!listing_full(31));
        assert!(listing_full(32), "the server keeps 32 per network");
    }

    #[test]
    fn the_token_is_read_from_the_servers_json_or_taken_bare() {
        assert_eq!(parse_token(r#"{"authToken":"abc"}"#).as_deref(), Some("abc"));
        assert_eq!(parse_token("  raw-token \n").as_deref(), Some("raw-token"));
        assert_eq!(parse_token(""), None);
        assert_eq!(parse_token(r#"{"other":1}"#), None);
    }

    #[test]
    fn a_server_needs_decodable_material_or_none() {
        assert!(Server::new("https://x.example/", None).is_some());
        let s = Server::new("https://x.example/", Some("aGVsbG8=")).unwrap();
        assert_eq!(s.url, "https://x.example", "no trailing slash");
        assert_eq!(s.auth.as_deref(), Some(&b"hello"[..]));
        assert!(Server::new("https://x.example", Some("not base64!")).is_none());
    }
}

/// The keeper against real 0.6.1 conductors whose own bootstrap is a black
/// hole, with a local bootstrap server: it registers a stranded conductor's
/// agents, registers nothing more once they are listed, and hands a second
/// conductor the first one's notes.
///
/// `HC_LINES_CONDUCTOR_06=<holochain 0.6.1> HC_LINES_HAPP_06=<a .happ> KITSUNE2_BOOTSTRAP_SRV=<kitsune2-bootstrap-srv 0.4.1> cargo test --lib -- --ignored live_keeper --nocapture`
#[cfg(all(test, feature = "line-06"))]
mod live {
    use super::*;
    use crate::admin::{AdminClient, InstallRequest};
    use crate::Line;
    use std::io::Write;
    use std::path::{Path, PathBuf};

    const ORIGIN: &str = "hcl-keeper-live";

    struct Proc(std::process::Child);
    impl Drop for Proc {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    fn bin(var: &str) -> PathBuf {
        PathBuf::from(std::env::var(var).unwrap_or_else(|_| panic!("set {var}")))
    }

    async fn conductor(dir: &Path, admin_port: u16, black_hole: u16, relay_port: u16) -> (Proc, AdminClient) {
        std::fs::create_dir_all(dir.join("data")).unwrap();
        std::fs::create_dir_all(dir.join("ks")).unwrap();
        let config = dir.join("conductor-config.yaml");
        std::fs::write(
            &config,
            format!(
                "data_root_path: '{d}/data'\nkeystore:\n  type: lair_server_in_proc\n  lair_root: '{d}/ks'\nadmin_interfaces:\n- driver:\n    type: websocket\n    port: {admin_port}\n    allowed_origins: '*'\nnetwork:\n  bootstrap_url: http://127.0.0.1:{black_hole}\n  signal_url: ws://127.0.0.1:{black_hole}\n  relay_url: http://127.0.0.1:{relay_port}/\n  advanced:\n    irohTransport:\n      relayAllowPlainText: true\ndb_sync_strategy: Resilient\n",
                d = dir.display(),
            ),
        )
        .unwrap();
        let mut child = std::process::Command::new(bin("HC_LINES_CONDUCTOR_06"))
            .arg("--piped")
            .arg("-c")
            .arg(&config)
            .stdin(std::process::Stdio::piped())
            .stdout(std::fs::File::create(dir.join("holochain.log")).unwrap())
            .stderr(std::fs::File::create(dir.join("holochain-stderr.log")).unwrap())
            .spawn()
            .expect("start the conductor");
        child.stdin.take().unwrap().write_all(b"live-test\n").unwrap();
        let proc_ = Proc(child);
        for _ in 0..120 {
            if let Ok(admin) = AdminClient::connect(Line::V06, admin_port, ORIGIN).await {
                return (proc_, admin);
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        panic!("{}: the admin interface never came up", dir.display());
    }

    /// `count` agents, each with the hApp under `seed`; their ids as notes name them.
    async fn install(admin: &AdminClient, count: usize, seed: &str) -> Vec<String> {
        let happ = bin("HC_LINES_HAPP_06");
        let ws = admin.as_v06().expect("a 0.6 admin client");
        let mut agents = Vec::new();
        for i in 0..count {
            let agent = ws.generate_agent_pub_key().await.unwrap();
            let app_id = format!("keeper_live_{i}");
            admin.install(&InstallRequest { app_id: &app_id, bundle: &happ, agent_key: agent.get_raw_39(), network_seed: Some(seed) }).await.unwrap();
            admin.enable(&app_id).await.unwrap();
            agents.push(id_core(agent.get_raw_39()));
        }
        agents
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn live_keeper_registers_a_stranded_conductor_and_feeds_peers_in() {
        let tmp = tempfile::tempdir().unwrap();
        let srv_port = free_port();
        let black_hole = free_port();
        let _srv = Proc(
            std::process::Command::new(bin("KITSUNE2_BOOTSTRAP_SRV"))
                .arg("--listen")
                .arg(format!("127.0.0.1:{srv_port}"))
                .stdout(std::fs::File::create(tmp.path().join("srv.log")).unwrap())
                .stderr(std::fs::File::create(tmp.path().join("srv-stderr.log")).unwrap())
                .spawn()
                .expect("start the bootstrap server"),
        );
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let url = format!("http://127.0.0.1:{srv_port}");
        let seed = format!("keeper-live-{}", std::process::id());

        let (_a, admin_a) = conductor(&tmp.path().join("a"), free_port(), black_hole, srv_port).await;
        let a_agents = install(&admin_a, 2, &seed).await;
        eprintln!("A up with {} agents, its own bootstrap a black hole", a_agents.len());
        // Old enough that a conductor that could reach its server would have sent them.
        tokio::time::sleep(std::time::Duration::from_secs(50)).await;

        let mut keeper = Keeper::new(vec![Server::new(&url, None).unwrap()]);
        let round = keeper.run_once(&admin_a, None).await.expect("a round for A");
        eprintln!("A round: {round:?}");
        assert_eq!((round.put, round.reached), (2, 1), "both of A's agents registered by the keeper");
        let space = id_core(&admin_a.running_cells().await.unwrap()[0].dna_hash);
        let listed = Server::new(&url, None).unwrap().list(&reqwest::Client::new(), &space).await.unwrap();
        let listed_agents: HashSet<String> = listed.iter().map(|n| n.agent.clone()).collect();
        assert_eq!(listed_agents, a_agents.iter().cloned().collect::<HashSet<_>>(), "the server lists exactly A's agents");
        assert!(keeper.stalled_for().is_some(), "the keeper knows it is covering for the conductor");
        let again = keeper.run_once(&admin_a, None).await.unwrap();
        assert_eq!(again.put, 0, "nothing more once listed");

        let (_b, admin_b) = conductor(&tmp.path().join("b"), free_port(), black_hole, srv_port).await;
        install(&admin_b, 1, &seed).await;
        let mut keeper_b = Keeper::new(vec![Server::new(&url, None).unwrap()]);
        let round_b = keeper_b.run_once(&admin_b, None).await.expect("a round for B");
        eprintln!("B round: {round_b:?}");
        assert_eq!(round_b.added, 2, "B is handed A's two notes");
        let b_knows: HashSet<String> = admin_b.agent_info().await.unwrap().iter().filter_map(|s| parse_note(s)).map(|n| n.agent).collect();
        for agent in &a_agents {
            assert!(b_knows.contains(agent), "B's conductor knows A's agent {agent}");
        }
    }
}
