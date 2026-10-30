//! Where a conductor meets its peers: one server does peer discovery
//! (bootstrap), signaling on the 0.6 line, and the Iroh relay.

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
}

impl Rendezvous {
    pub fn new(bootstrap_url: impl Into<String>) -> Self {
        Self { bootstrap_url: bootstrap_url.into(), signal_url: None, auth_material: None }
    }

    /// The relay URL, served by the bootstrap's host ([`relay_url_for`]).
    pub fn relay_url(&self) -> String {
        relay_url_for(&self.bootstrap_url)
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

    #[test]
    fn the_signal_url_defaults_to_the_bootstraps_host() {
        assert_eq!(Rendezvous::new("https://b.example.com/").signal_url(), "wss://b.example.com");
        let mut r = Rendezvous::new("https://b.example.com");
        r.signal_url = Some("wss://s.example.com".into());
        assert_eq!(r.signal_url(), "wss://s.example.com");
    }
}
