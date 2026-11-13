//! Where a conductor meets its peers: one server does peer discovery
//! (bootstrap), signaling on the 0.6 line, and the Iroh relay.

use std::time::Duration;

/// How long a start waits for the rendezvous to answer before starting
/// without its auth: long enough for a slow link, short enough not to hold
/// up an offline start.
pub const PROBE_TIMEOUT: Duration = Duration::from_millis(2500);

/// One rendezvous server, as a conductor config names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rendezvous {
    /// `https://...` (the conductor refuses a plaintext relay).
    pub bootstrap_url: String,
    /// The 0.6 line's signal server, `wss://...`. None: the bootstrap's own
    /// host. The 0.7 config has no such field.
    pub signal_url: Option<String>,
    /// Standard padded base64, for servers that gate on it. Sent to both the
    /// bootstrap and the relay.
    pub auth_material: Option<String>,
    /// The relay, when another host than the bootstrap's serves it
    /// (`https://relay.example.com./`). None: the bootstrap's own host.
    pub relay_url: Option<String>,
}

impl Rendezvous {
    pub fn new(bootstrap_url: impl Into<String>) -> Self {
        Self { bootstrap_url: bootstrap_url.into(), signal_url: None, auth_material: None, relay_url: None }
    }

    /// The relay URL: as given, else the bootstrap's host ([`relay_url_for`]).
    pub fn relay_url(&self) -> String {
        match self.relay_url.as_deref().filter(|r| !r.is_empty()) {
            Some(r) => r.to_string(),
            None => relay_url_for(&self.bootstrap_url),
        }
    }

    /// The 0.6 signal URL: as given, else `wss://` on the bootstrap's host.
    pub fn signal_url(&self) -> String {
        match &self.signal_url {
            Some(s) => s.clone(),
            None => {
                let host = self.bootstrap_url.trim_end_matches('/');
                let host = host.trim_start_matches("https://").trim_start_matches("http://");
                format!("wss://{host}")
            }
        }
    }
}

/// Whether a bootstrap server answers now: `GET <bootstrap_url>/health`
/// returns a success status within `timeout`. kitsune2's bootstrap server
/// serves it without auth.
pub async fn answers(bootstrap_url: &str, timeout: Duration) -> bool {
    let health = format!("{}/health", bootstrap_url.trim_end_matches('/'));
    let Ok(client) = reqwest::Client::builder().timeout(timeout).build() else {
        return false;
    };
    matches!(client.get(&health).send().await, Ok(r) if r.status().is_success())
}

/// A rendezvous as a conductor start uses it ([`Rendezvous::for_start`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForStart {
    pub rendezvous: Rendezvous,
    /// The start goes without the auth because its server did not answer.
    /// The app restarts the line with the auth once [`answers`] is true.
    pub without_auth: bool,
}

impl Rendezvous {
    /// The entry as a start should use it. Holochain 0.6.1 and 0.7.1
    /// authenticate with the relay while they start, and a conductor that
    /// cannot (no network) refuses to start at all. So a start with auth
    /// material probes first: answering, the entry is used as it is; not
    /// answering, it is used without its auth, the conductor runs, and
    /// everything local works until the network is back. An entry with no
    /// auth material is used as it is, without a probe.
    pub async fn for_start(&self, timeout: Duration) -> ForStart {
        let has_auth = self.auth_material.as_deref().is_some_and(|m| !m.is_empty());
        if !has_auth || answers(&self.bootstrap_url, timeout).await {
            return ForStart { rendezvous: self.clone(), without_auth: false };
        }
        ForStart { rendezvous: Rendezvous { auth_material: None, ..self.clone() }, without_auth: true }
    }
}

/// The canonical relay URL for a bootstrap server. kitsune2 and Iroh want
/// the FQDN form, a trailing dot on the hostname and a trailing slash:
/// `https://bootstrap.example.com./`. With a port the dot goes before the
/// colon; an IP literal never gets one.
pub fn relay_url_for(bootstrap_url: &str) -> String {
    let trimmed = bootstrap_url.trim_end_matches('/');
    let (scheme, rest) = match trimmed.split_once("://") {
        Some((s, r)) => (s, r),
        None => return format!("{}./", trimmed.trim_end_matches('.')),
    };
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => (h, Some(p)),
        _ => (rest, None),
    };
    let is_ip_literal =
        host.trim_end_matches('.').chars().all(|c| c.is_ascii_digit() || c == '.') || host.contains('[');
    let canon_host = if is_ip_literal { host.trim_end_matches('.').to_string() } else { format!("{}.", host.trim_end_matches('.')) };
    match port {
        Some(p) => format!("{scheme}://{canon_host}:{p}/"),
        None => format!("{scheme}://{canon_host}/"),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_relay_of_its_own_is_used_as_given_and_none_means_the_bootstraps_host() {
        use super::*;
        assert_eq!(Rendezvous::new("https://b.example.com").relay_url(), "https://b.example.com./");
        let other = Rendezvous { relay_url: Some("https://relay.example.net./".into()), ..Rendezvous::new("https://b.example.com") };
        assert_eq!(other.relay_url(), "https://relay.example.net./");
        let empty = Rendezvous { relay_url: Some(String::new()), ..Rendezvous::new("https://b.example.com") };
        assert_eq!(empty.relay_url(), "https://b.example.com./");
    }

    use super::*;

    #[test]
    fn the_relay_is_the_bootstraps_host_in_canonical_form() {
        assert_eq!(relay_url_for("https://bootstrap.example.com"), "https://bootstrap.example.com./");
        assert_eq!(relay_url_for("https://bootstrap.example.com/"), "https://bootstrap.example.com./");
        assert_eq!(relay_url_for("https://bootstrap.example.com."), "https://bootstrap.example.com./");
        assert_eq!(relay_url_for("https://node.example.com:8443"), "https://node.example.com.:8443/");
        assert_eq!(relay_url_for("https://10.0.0.5:443"), "https://10.0.0.5:443/");
        assert_eq!(relay_url_for("https://[::1]:443"), "https://[::1]:443/");
        assert_eq!(relay_url_for("http://node1.example.com:18080"), "http://node1.example.com.:18080/");
        assert_eq!(relay_url_for("http://192.168.1.3:18080"), "http://192.168.1.3:18080/");
    }

    /// A local server that answers every request with 200 and an empty body.
    async fn health_server() -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let _ = socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
            }
        });
        format!("http://{addr}")
    }

    /// A URL nothing listens on.
    fn silent_url() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        format!("http://127.0.0.1:{port}")
    }

    #[tokio::test]
    async fn a_start_drops_the_auth_only_when_its_server_does_not_answer() {
        let live = health_server().await;
        let dead = silent_url();
        assert!(answers(&live, PROBE_TIMEOUT).await);
        assert!(!answers(&dead, PROBE_TIMEOUT).await);

        let with_auth = |url: &str| Rendezvous { auth_material: Some("eyJmb28iOiJiYXIifQ==".into()), ..Rendezvous::new(url) };
        let answering = with_auth(&live).for_start(PROBE_TIMEOUT).await;
        assert_eq!(answering.rendezvous, with_auth(&live));
        assert!(!answering.without_auth);

        let offline = with_auth(&dead).for_start(PROBE_TIMEOUT).await;
        assert_eq!(offline.rendezvous.auth_material, None, "offline: no auth, so the conductor starts");
        assert_eq!(offline.rendezvous.bootstrap_url, dead);
        assert!(offline.without_auth, "the app knows to restart the line with the auth later");

        let no_auth = Rendezvous::new(&dead).for_start(PROBE_TIMEOUT).await;
        assert_eq!(no_auth.rendezvous, Rendezvous::new(&dead), "nothing to drop: used as it is");
        assert!(!no_auth.without_auth);
    }

    #[test]
    fn the_signal_url_defaults_to_the_bootstraps_host() {
        assert_eq!(Rendezvous::new("https://b.example.com/").signal_url(), "wss://b.example.com");
        let mut r = Rendezvous::new("https://b.example.com");
        r.signal_url = Some("wss://s.example.com".into());
        assert_eq!(r.signal_url(), "wss://s.example.com");
    }
}
